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
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

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
            .addRoute("10.0.0.0", 24)
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
                if (length < 28) continue

                val response = handleDnsPacket(packet, length)
                if (response != null) {
                    output.write(response)
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Tunnel error: ${e.message}")
            }
        }
    }

    private fun handleDnsPacket(packet: ByteArray, length: Int): ByteArray? {
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // UDP only

        val srcPort = ((packet[ipHeaderLen].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLen + 1].toInt() and 0xFF)
        val dstPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLen + 3].toInt() and 0xFF)
        if (dstPort != 53) return null // DNS only

        val srcIp = packet.copyOfRange(12, 16)
        val dnsPayload = packet.copyOfRange(ipHeaderLen + 8, length)
        val domain = extractDomain(dnsPayload) ?: return null

        Log.d(TAG, "DNS: $domain")

        return if (blocklistManager.isBlocked(domain)) {
            Log.d(TAG, "BLOCKED: $domain")
            blocklistManager.incrementBlockedCount()
            buildNxDomain(dnsPayload, srcIp, srcPort)
        } else {
            forwardDns(dnsPayload, srcIp, srcPort)
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
        } catch (e: Exception) { null }
    }

    private fun forwardDns(query: ByteArray, clientIp: ByteArray, clientPort: Int): ByteArray? {
        return try {
            val socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 5000

            val upstream = InetAddress.getByName("1.1.1.1")
            socket.send(DatagramPacket(query, query.size, upstream, 53))

            val buf = ByteArray(4096)
            val resp = DatagramPacket(buf, buf.size)
            socket.receive(resp)
            socket.close()

            buildIpUdpPacket(
                payload = buf.copyOf(resp.length),
                srcIp = byteArrayOf(10, 0, 0, 2),
                dstIp = clientIp,
                srcPort = 53,
                dstPort = clientPort
            )
        } catch (e: Exception) {
            Log.e(TAG, "Forward error: ${e.message}")
            null
        }
    }

    private fun buildNxDomain(query: ByteArray, clientIp: ByteArray, clientPort: Int): ByteArray {
        val response = query.copyOf()
        response[2] = (response[2].toInt() or 0x80).toByte()
        response[3] = 0x03.toByte()
        return buildIpUdpPacket(
            payload = response,
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = clientIp,
            srcPort = 53,
            dstPort = clientPort
        )
    }

    private fun buildIpUdpPacket(
        payload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val buf = ByteBuffer.allocate(totalLen)

        // IP header
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort(0)
        buf.putShort(0x4000.toShort())
        buf.put(0x40.toByte())
        buf.put(0x11.toByte())
        buf.putShort(0) // checksum - 0 is fine for VPN tun
        buf.put(srcIp)
        buf.put(dstIp)

        // UDP header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort((8 + payload.size).toShort())
        buf.putShort(0)

        buf.put(payload)
        return buf.array()
    }

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
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
