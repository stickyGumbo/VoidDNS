package com.voiddns.app.dns

import android.net.VpnService
import android.util.Log
import com.voiddns.app.blocklist.BlocklistManager
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

class DnsEngine(
    private val blocklistManager: BlocklistManager,
    private val vpnService: VpnService
) {

    companion object {
        const val TAG = "DnsEngine"
        const val UPSTREAM_DNS = "1.1.1.1"
        const val DNS_PORT = 53
    }

    fun processPacket(packet: ByteArray, length: Int): ByteArray? {
        return try {
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
                buildBlockedResponse(dnsPayload, packet, ipHeaderLength)
            } else {
                forwardToUpstream(dnsPayload, packet, ipHeaderLength)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet: ${e.message}")
            null
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

    private fun buildBlockedResponse(
        query: ByteArray,
        originalPacket: ByteArray,
        ipHeaderLength: Int
    ): ByteArray {
        val response = query.copyOf()
        response[2] = (response[2].toInt() or 0x80).toByte()
        response[3] = (response[3].toInt() or 0x03).toByte()
        return wrapInIpUdp(
            response,
            srcIp = originalPacket.copyOfRange(16, 20),
            dstIp = originalPacket.copyOfRange(12, 16),
            srcPort = DNS_PORT,
            dstPort = getSourcePort(originalPacket, ipHeaderLength)
        )
    }

    private fun forwardToUpstream(
        dnsQuery: ByteArray,
        originalPacket: ByteArray,
        ipHeaderLength: Int
    ): ByteArray? {
        return try {
            val socket = DatagramSocket()
            // THIS is the key fix - protect socket from VPN tunnel
            vpnService.protect(socket)
            socket.soTimeout = 3000

            val upstream = InetAddress.getByName(UPSTREAM_DNS)
            socket.send(DatagramPacket(dnsQuery, dnsQuery.size, upstream, DNS_PORT))

            val buf = ByteArray(4096)
            val response = DatagramPacket(buf, buf.size)
            socket.receive(response)
            socket.close()

            wrapInIpUdp(
                buf.copyOf(response.length),
                srcIp = InetAddress.getByName(UPSTREAM_DNS).address,
                dstIp = originalPacket.copyOfRange(12, 16),
                srcPort = DNS_PORT,
                dstPort = getSourcePort(originalPacket, ipHeaderLength)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Upstream error: ${e.message}")
            null
        }
    }

    private fun getSourcePort(packet: ByteArray, ipHeaderLength: Int): Int {
        return ((packet[ipHeaderLength].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLength + 1].toInt() and 0xFF)
    }

    private fun wrapInIpUdp(
        dns: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val totalLength = 20 + 8 + dns.size
        val packet = ByteBuffer.allocate(totalLength)

        packet.put(0x45.toByte())
        packet.put(0x00.toByte())
        packet.putShort(totalLength.toShort())
        packet.putInt(0)
        packet.put(0x40.toByte())
        packet.put(0x11.toByte())
        packet.putShort(0)
        packet.put(srcIp)
        packet.put(dstIp)

        packet.putShort(srcPort.toShort())
        packet.putShort(dstPort.toShort())
        packet.putShort((8 + dns.size).toShort())
        packet.putShort(0)
        packet.put(dns)

        return packet.array()
    }
}
