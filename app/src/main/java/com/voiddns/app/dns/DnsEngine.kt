package com.voiddns.app.dns

import android.util.Log
import com.voiddns.app.blocklist.BlocklistManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

class DnsEngine(private val blocklistManager: BlocklistManager) {

    companion object {
        const val TAG = "DnsEngine"
        const val UPSTREAM_DNS = "1.1.1.1"
        const val DNS_PORT = 53
    }

    fun processPacket(packet: ByteArray, length: Int): ByteArray? {
        return try {
            val buffer = ByteBuffer.wrap(packet, 0, length)

            // Skip IP header (20 bytes) + UDP header (8 bytes)
            val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
            val dnsOffset = ipHeaderLength + 8
            val dnsLength = length - dnsOffset

            if (dnsLength <= 0) return null

            val dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
            val domain = extractDomain(dnsPayload) ?: return null

            Log.d(TAG, "DNS query: $domain")

            if (blocklistManager.isBlocked(domain)) {
                Log.d(TAG, "BLOCKED: $domain")
                blocklistManager.incrementBlockedCount()
                buildBlockedResponse(dnsPayload)
            } else {
                forwardToUpstream(dnsPayload)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet: ${e.message}")
            null
        }
    }

    private fun extractDomain(dns: ByteArray): String? {
        return try {
            val sb = StringBuilder()
            var i = 12 // skip DNS header
            while (i < dns.size) {
                val len = dns[i].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                val label = String(dns, i + 1, len)
                sb.append(label)
                i += len + 1
            }
            if (sb.isEmpty()) null else sb.toString().lowercase()
        } catch (e: Exception) {
            null
        }
    }

    private fun buildBlockedResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        // Set QR bit (response) + RCODE 3 (NXDOMAIN)
        response[2] = (response[2].toInt() or 0x80).toByte()
        response[3] = (response[3].toInt() or 0x03).toByte()
        return wrapInIpUdp(response)
    }

    private fun forwardToUpstream(dnsQuery: ByteArray): ByteArray? {
        return try {
            val socket = DatagramSocket()
            socket.soTimeout = 3000
            protect(socket)

            val upstream = InetAddress.getByName(UPSTREAM_DNS)
            val sendPacket = DatagramPacket(dnsQuery, dnsQuery.size, upstream, DNS_PORT)
            socket.send(sendPacket)

            val responseBuffer = ByteArray(4096)
            val receivePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(receivePacket)
            socket.close()

            wrapInIpUdp(responseBuffer.copyOf(receivePacket.length))
        } catch (e: Exception) {
            Log.e(TAG, "Upstream DNS error: ${e.message}")
            null
        }
    }

    private fun protect(socket: DatagramSocket) {
        // Will be called from VpnService context
    }

    private fun wrapInIpUdp(dns: ByteArray): ByteArray {
        val totalLength = 20 + 8 + dns.size
        val packet = ByteBuffer.allocate(totalLength)

        // IP Header
        packet.put(0x45.toByte())           // Version + IHL
        packet.put(0x00.toByte())           // DSCP
        packet.putShort(totalLength.toShort())
        packet.putInt(0)                    // ID + Flags
        packet.put(0x40.toByte())           // TTL
        packet.put(0x11.toByte())           // Protocol UDP
        packet.putShort(0)                  // Checksum placeholder
        packet.put(InetAddress.getByName("1.1.1.1").address)   // src
        packet.put(InetAddress.getByName("10.0.0.2").address)  // dst

        // UDP Header
        packet.putShort(DNS_PORT.toShort()) // src port
        packet.putShort(DNS_PORT.toShort()) // dst port
        packet.putShort((8 + dns.size).toShort())
        packet.putShort(0)                  // checksum

        packet.put(dns)
        return packet.array()
    }
}
