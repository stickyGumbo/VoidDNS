package com.voiddns.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.voiddns.app.blocklist.BlocklistManager
import com.voiddns.app.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

class VoidVpnService : VpnService() {

    companion object {
        const val TAG = "VoidVpnService"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "voiddns_channel"
        var isRunning = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private lateinit var blocklistManager: BlocklistManager
    private val tcpConnections = ConcurrentHashMap<String, TcpForwarder>()

    override fun onCreate() {
        super.onCreate()
        blocklistManager = BlocklistManager.getInstance(this)
        blocklistManager.initialize()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.2")
            .setSession("VoidDNS")
            .setMtu(1500)
            .establish()

        isRunning = true
        Log.d(TAG, "VPN started")

        serviceJob = CoroutineScope(Dispatchers.IO).launch {
            runTunnel()
        }
    }

    private suspend fun runTunnel() {
        val input = FileInputStream(vpnInterface!!.fileDescriptor)
        val output = FileOutputStream(vpnInterface!!.fileDescriptor)
        val packet = ByteArray(32767)

        while (isRunning) {
            try {
                val length = input.read(packet)
                if (length <= 0 || length < 20) continue

                val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
                if (ipHeaderLen < 20 || length < ipHeaderLen + 8) {
                    continue
                }

                val protocol = packet[9].toInt() and 0xFF
                when (protocol) {
                    17 -> handleUdpPacket(packet, length, ipHeaderLen, output)
                    else -> continue
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Tunnel error: ${e.message}")
            }
        }
    }

    private fun handleUdpPacket(packet: ByteArray, length: Int, ipHeaderLen: Int, output: FileOutputStream) {
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = ((packet[ipHeaderLen].toInt() and 0xFF) shl 8) or
            (packet[ipHeaderLen + 1].toInt() and 0xFF)
        val dstPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
            (packet[ipHeaderLen + 3].toInt() and 0xFF)
        val payload = packet.copyOfRange(ipHeaderLen + 8, length)

        if (dstPort == 53) {
            val dnsResponse = handleDnsPacket(payload, srcIp, dstIp, srcPort, dstPort)
            if (dnsResponse != null) {
                output.write(dnsResponse)
            }
        }
        // For non-DNS UDP we do not touch the packet — let Android handle it via real interface.
    }

    private fun handleDnsPacket(
        payload: ByteArray,
        clientIp: ByteArray,
        serverIp: ByteArray,
        clientPort: Int,
        serverPort: Int
    ): ByteArray? {
        val domain = extractDomain(payload) ?: return null
        Log.d(TAG, "DNS query for $domain")

        return if (blocklistManager.isBlocked(domain)) {
            Log.d(TAG, "Blocked DNS: $domain")
            blocklistManager.incrementBlockedCount()
            buildNxDomain(payload, clientIp, clientPort)
        } else {
            forwardDns(payload, clientIp, clientPort, serverIp, serverPort)
        }
    }

    private fun forwardUdpPacket(
        payload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        output: FileOutputStream
    ) {
        try {
            val socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 5000
            val remoteAddress = InetAddress.getByAddress(dstIp)
            socket.send(DatagramPacket(payload, payload.size, remoteAddress, dstPort))

            val responseBuffer = ByteArray(4096)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            socket.close()

            val responsePayload = responseBuffer.copyOf(responsePacket.length)
            output.write(
                buildIpv4UdpPacket(
                    payload = responsePayload,
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort
                )
            )
        } catch (e: Exception) {
            Log.e(TAG, "UDP forward failed: ${e.message}")
        }
    }

    private fun forwardDns(
        query: ByteArray,
        clientIp: ByteArray,
        clientPort: Int,
        serverIp: ByteArray,
        serverPort: Int
    ): ByteArray? {
        return try {
            val socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 5000
            val prefs = getSharedPreferences("voiddns_prefs", MODE_PRIVATE)
            val upstreamAddr = prefs.getString("upstream_dns", "1.1.1.1") ?: "1.1.1.1"
            val upstream = InetAddress.getByName(upstreamAddr)
            socket.send(DatagramPacket(query, query.size, upstream, 53))

            val responseBuffer = ByteArray(4096)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            socket.close()

            buildIpv4UdpPacket(
                payload = responseBuffer.copyOf(responsePacket.length),
                srcIp = upstream.address,
                dstIp = clientIp,
                srcPort = 53,
                dstPort = clientPort
            )
        } catch (e: Exception) {
            Log.e(TAG, "DNS forward failed: ${e.message}")
            null
        }
    }

    private fun buildNxDomain(query: ByteArray, clientIp: ByteArray, clientPort: Int): ByteArray {
        val response = query.copyOf()
        response[2] = (response[2].toInt() or 0x80).toByte()
        response[3] = 0x03.toByte()
        return buildIpv4UdpPacket(
            payload = response,
            srcIp = byteArrayOf(1, 1, 1, 1),
            dstIp = clientIp,
            srcPort = 53,
            dstPort = clientPort
        )
    }

    private fun handleTcpPacket(packet: ByteArray, length: Int, ipHeaderLen: Int, output: FileOutputStream) {
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = ((packet[ipHeaderLen].toInt() and 0xFF) shl 8) or (packet[ipHeaderLen + 1].toInt() and 0xFF)
        val dstPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or (packet[ipHeaderLen + 3].toInt() and 0xFF)

        val dataOffset = ((packet[ipHeaderLen + 12].toInt() and 0xF0) ushr 2)
        val payloadOffset = ipHeaderLen + dataOffset
        if (payloadOffset >= length) {
            return
        }

        val payload = packet.copyOfRange(payloadOffset, length)
        val key = tcpConnectionKey(srcIp, srcPort, dstIp, dstPort)
        val connection = tcpConnections.getOrPut(key) {
            TcpForwarder(this, output, srcIp, srcPort, dstIp, dstPort).also { it.start() }
        }

        if (payload.isNotEmpty()) {
            connection.writePayload(payload)
        }
    }

    private fun extractDomain(dns: ByteArray): String? {
        return try {
            val sb = StringBuilder()
            var i = 12
            while (i < dns.size) {
                val len = dns[i].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                sb.append(String(dns, i + 1, len))
                i += len + 1
            }
            if (sb.isEmpty()) null else sb.toString().lowercase()
        } catch (e: Exception) {
            null
        }
    }

    private fun buildIpv4UdpPacket(
        payload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val buffer = ByteBuffer.allocate(totalLen)

        buffer.put(0x45.toByte())
        buffer.put(0x00.toByte())
        buffer.putShort(totalLen.toShort())
        buffer.putShort(0)
        buffer.putShort(0x4000.toShort())
        buffer.put(0x40.toByte())
        buffer.put(0x11.toByte())
        buffer.putShort(0)
        buffer.put(srcIp)
        buffer.put(dstIp)

        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putShort((8 + payload.size).toShort())
        buffer.putShort(0)
        buffer.put(payload)
        return buffer.array()
    }

    private fun buildIpv4TcpPacket(
        payload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val totalLen = 20 + 20 + payload.size
        val buffer = ByteBuffer.allocate(totalLen)

        buffer.put(0x45.toByte())
        buffer.put(0x00.toByte())
        buffer.putShort(totalLen.toShort())
        buffer.putShort(0)
        buffer.putShort(0x4000.toShort())
        buffer.put(0x06.toByte())
        buffer.put(0x06.toByte())
        buffer.putShort(0)
        buffer.put(srcIp)
        buffer.put(dstIp)

        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putInt(0)
        buffer.putInt(0)
        buffer.put(0x50.toByte())
        buffer.put(0x10.toByte())
        buffer.putShort(0)
        buffer.put(payload)
        return buffer.array()
    }

    private fun tcpConnectionKey(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int): String {
        val left = "${InetAddress.getByAddress(srcIp).hostAddress}:$srcPort"
        val right = "${InetAddress.getByAddress(dstIp).hostAddress}:$dstPort"
        return listOf(left, right).sorted().joinToString("::")
    }

    private fun ipToString(address: ByteArray): String = InetAddress.getByAddress(address).hostAddress

    private fun buildNotification(): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, VoidVpnService::class.java).apply { action = "STOP" },
            PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("VoidDNS Active")
            .setContentText("Blocking ads system-wide")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_delete, "Stop", stopIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "VoidDNS Protection",
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    private fun stopVpn() {
        isRunning = false
        serviceJob?.cancel()
        tcpConnections.values.forEach { it.close() }
        tcpConnections.clear()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        com.voiddns.app.stats.StatsManager.getInstance(this).persistSession()
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private inner class TcpForwarder(
        private val service: VoidVpnService,
        private val output: FileOutputStream,
        private val clientIp: ByteArray,
        private val clientPort: Int,
        private val serverIp: ByteArray,
        private val serverPort: Int
    ) {
        private val socket = Socket()

        fun start() {
            CoroutineScope(Dispatchers.IO).launch {
                runRemoteToTun()
            }
        }

        fun writePayload(payload: ByteArray) {
            if (payload.isEmpty()) return
            try {
                if (!socket.isConnected) {
                    protect(socket)
                    socket.connect(InetSocketAddress(InetAddress.getByAddress(serverIp), serverPort), 5000)
                    socket.soTimeout = 1000
                    socket.keepAlive = true
                }
                socket.getOutputStream().write(payload)
                socket.getOutputStream().flush()
            } catch (e: Exception) {
                Log.e(TAG, "TCP write failed: ${e.message}")
                close()
            }
        }

        private suspend fun runRemoteToTun() {
            try {
                protect(socket)
                socket.connect(InetSocketAddress(InetAddress.getByAddress(serverIp), serverPort), 5000)
                socket.soTimeout = 1000
                socket.keepAlive = true

                val buffer = ByteArray(4096)
                while (isRunning && !socket.isClosed) {
                    val read = socket.getInputStream().read(buffer)
                    if (read <= 0) break
                    val packet = buildIpv4TcpPacket(
                        payload = buffer.copyOf(read),
                        srcIp = serverIp,
                        dstIp = clientIp,
                        srcPort = serverPort,
                        dstPort = clientPort
                    )
                    output.write(packet)
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "TCP relay stopped: ${e.message}")
            } finally {
                close()
            }
        }

        fun close() {
            try {
                socket.close()
            } catch (_: Exception) {
            }
            tcpConnections.entries.removeIf { it.value === this }
        }
    }
}
