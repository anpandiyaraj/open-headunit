package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import com.andrerinas.openheadunit.utils.useSocket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Direct UDP DNS client for querying reverse PTR records against the local gateway router.
 * Essential on Android when Private DNS or public DNS (8.8.8.8) is active, since only the
 * local router knows DHCP client hostnames on the LAN.
 */
object DnsLookup {

    private const val DNS_PORT = 53
    private const val TYPE_PTR = 12
    private const val TYPE_CNAME = 5

    fun queryPtr(dnsServerIp: String, targetIp: String, timeoutMs: Int = 450): String? {
        val query = buildPtrQuery(targetIp) ?: return null
        return try {
            DatagramSocket().useSocket { socket ->
                socket.soTimeout = timeoutMs
                val serverAddr = InetAddress.getByName(dnsServerIp)
                socket.send(DatagramPacket(query, query.size, serverAddr, DNS_PORT))
                val buffer = ByteArray(512)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                parsePtrResponse(buffer, response.length) ?: ""
            }
        } catch (_: Exception) {
            null
        }
    }

    internal fun buildPtrQuery(ip: String): ByteArray? {
        val octets = ip.split(".")
        if (octets.size != 4 || octets.any { it.toIntOrNull() !in 0..255 }) return null

        val reverseName = "${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa"
        val qname = reverseName.split(".").flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.ISO_8859_1).toList()
        }.toByteArray() + byteArrayOf(0x00)

        val header = byteArrayOf(
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        val questionFooter = byteArrayOf(0x00, 0x0C, 0x00, 0x01)
        return header + qname + questionFooter
    }

    private fun parsePtrResponse(data: ByteArray, length: Int): String? {
        if (length < 12) return null
        val qdCount = u16(data, 4)
        val anCount = u16(data, 6)
        val nsCount = u16(data, 8)
        val arCount = u16(data, 10)

        var idx = 12
        repeat(qdCount) {
            idx = skipName(data, idx)
            idx += 4
        }

        repeat(anCount + nsCount + arCount) {
            if (idx >= length) return null
            idx = skipName(data, idx)
            if (idx + 10 > length) return null
            val type = u16(data, idx)
            val rdLength = u16(data, idx + 8)
            idx += 10
            if (type == TYPE_PTR || type == TYPE_CNAME) {
                return readName(data, idx)
                    ?.trimEnd('.')
                    ?.removeSuffix(".local")
                    ?.removeSuffix(".lan")
                    ?.removeSuffix(".home")
            }
            idx += rdLength
        }
        return null
    }

    private fun u16(data: ByteArray, i: Int): Int =
        ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)

    private fun skipName(data: ByteArray, start: Int): Int {
        var i = start
        while (i < data.size) {
            val b = data[i].toInt() and 0xFF
            if (b == 0) return i + 1
            if ((b and 0xC0) == 0xC0) return i + 2
            i += b + 1
        }
        return i
    }

    private fun readName(data: ByteArray, start: Int): String? {
        val parts = mutableListOf<String>()
        var i = start
        var hops = 0
        while (i < data.size && hops < 64) {
            hops++
            val b = data[i].toInt() and 0xFF
            if (b == 0) break
            if ((b and 0xC0) == 0xC0) {
                val next = data.getOrNull(i + 1)?.toInt()?.and(0xFF) ?: return null
                i = ((b and 0x3F) shl 8) or next
                continue
            }
            if (i + 1 + b > data.size) return null
            parts.add(String(data, i + 1, b, Charsets.ISO_8859_1))
            i += b + 1
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(".")
    }
}
