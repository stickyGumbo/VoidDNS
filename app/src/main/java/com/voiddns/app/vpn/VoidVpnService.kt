package com.voiddns.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.voiddns.app.dns.DnsEngine
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
    private lateinit var dnsEngine: DnsEngine

    override fun onCreate() {
        super.onCreate()
        dnsEngine = DnsEngine(BlocklistManager.getInstance(this), this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "STOP" -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.2")
            .addRoute("0.0.0.0", 0)
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
        val buffer = ByteBuffer.allocate(32767)

        while (isRunning) {
            try {
                buffer.clear()
                val length = input.read(buffer.array())
                if (length <= 0) continue

                buffer.limit(length)
                val response = dnsEngine.processPacket(buffer.array(), length)
                if (response != null) {
                    output.write(response)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Tunnel error: ${e.message}")
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        serviceJob?.cancel()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.d(TAG, "VPN stopped")
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

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
