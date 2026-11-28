package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.SocketTimeoutException

data class MdnsHostInfo(
    val hostname: String? = null,
    val friendlyName: String? = null,
    val modelHint: String? = null,
    val services: Set<String> = emptySet()
)

/**
 * Low-level multicast DNS (mDNS / Bonjour / Avahi) scanner with reverse `.in-addr.arpa`
 * mDNS PTR queries and TXT key-value extraction (`model=`, `fn=`, `md=`, `ty=`).
 */
object LowLevelMdnsScanner {

    private val MDNS_GROUP: InetAddress =
        Inet4Address.getByAddress(byteArrayOf(224.toByte(), 0, 0, 251.toByte()))
    private const val MDNS_PORT = 5353

    private val COMMON_SERVICES = listOf(
        "_services._dns-sd._udp.local",
        "_companion-link._tcp.local",
        "_device-info._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_androidtvremote2._tcp.local",
        "_spotify-connect._tcp.local",
        "_workstation._tcp.local",
        "_smb._tcp.local",
        "_afpovertcp._tcp.local",
        "_ssh._tcp.local",
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_http._tcp.local",
        "_hap._tcp.local",
        "_homekit._tcp.local",
        "_matter._tcp.local"
    )

    suspend fun scanLanMdns(
        reverseLookupIps: List<String> = emptyList(),
        listenDurationMs: Long = 1200L
    ): Map<String, MdnsHostInfo> = withContext(Dispatchers.IO) {
        val results = mutableMapOf<String, MdnsHostInfo>()
        var socket: MulticastSocket? = null
        try {
            socket = MulticastSocket(MDNS_PORT).apply {
                reuseAddress = true
                timeToLive = 255
                soTimeout = 250
                try {
                    joinGroup(MDNS_GROUP)
                } catch (_: Exception) {
                }
            }

            for (service in COMMON_SERVICES) {
                val packetBytes = buildPtrQuery(service)
                try {
                    socket.send(DatagramPacket(packetBytes, packetBytes.size, MDNS_GROUP, MDNS_PORT))
                } catch (_: Exception) {
                }
            }

            for (ip in reverseLookupIps) {
                val parts = ip.split(".")
                if (parts.size == 4) {
                    val arpa = "${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa"
                    val packetBytes = buildPtrQuery(arpa)
                    try {
                        socket.send(DatagramPacket(packetBytes, packetBytes.size, MDNS_GROUP, MDNS_PORT))
                    } catch (_: Exception) {
                    }
                }
            }

            val buffer = ByteArray(8192)
            val deadline = System.currentTimeMillis() + listenDurationMs
            while (System.currentTimeMillis() < deadline) {
                coroutineContext.ensureActive()
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val senderIp = (packet.address as? Inet4Address)?.hostAddress
                    val copy = packet.data.copyOfRange(0, packet.length)
                    val parsed = parseMdnsPacket(copy)
                    mergeParsedPacket(results, senderIp, parsed)
                } catch (_: SocketTimeoutException) {
                } catch (_: Exception) {
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            results.putAll(scanEphemeralFallback(reverseLookupIps, listenDurationMs / 2))
        } finally {
            try {
                socket?.leaveGroup(MDNS_GROUP)
            } catch (_: Exception) {
            }
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
        results
    }

    private suspend fun scanEphemeralFallback(
        reverseLookupIps: List<String>,
        listenDurationMs: Long
    ): Map<String, MdnsHostInfo> {
        val results = mutableMapOf<String, MdnsHostInfo>()
        var socket: MulticastSocket? = null
        try {
            socket = MulticastSocket().apply {
                timeToLive = 255
                soTimeout = 250
                try {
                    joinGroup(MDNS_GROUP)
                } catch (_: Exception) {
                }
            }
            for (service in COMMON_SERVICES) {
                val bytes = buildPtrQuery(service)
                try {
                    socket.send(DatagramPacket(bytes, bytes.size, MDNS_GROUP, MDNS_PORT))
                } catch (_: Exception) {
                }
            }
            for (ip in reverseLookupIps) {
                val parts = ip.split(".")
                if (parts.size == 4) {
                    val bytes = buildPtrQuery("${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa")
                    try {
                        socket.send(DatagramPacket(bytes, bytes.size, MDNS_GROUP, MDNS_PORT))
                    } catch (_: Exception) {
                    }
                }
            }
            val buffer = ByteArray(8192)
            val deadline = System.currentTimeMillis() + listenDurationMs
            while (System.currentTimeMillis() < deadline) {
                coroutineContext.ensureActive()
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val senderIp = (packet.address as? Inet4Address)?.hostAddress
                    val parsed = parseMdnsPacket(packet.data.copyOfRange(0, packet.length))
                    mergeParsedPacket(results, senderIp, parsed)
                } catch (_: SocketTimeoutException) {
                } catch (_: Exception) {
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
        } finally {
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
        return results
    }

    internal fun buildPtrQuery(domainName: String): ByteArray {
        val labels = domainName.trimEnd('.').split('.').filter { it.isNotEmpty() }
        val qname = labels.flatMap { label ->
            val bytes = label.toByteArray(Charsets.UTF_8)
            listOf(bytes.size.toByte()) + bytes.toList()
        }.toByteArray() + byteArrayOf(0x00)

        val header = byteArrayOf(
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        )
        val footer = byteArrayOf(0x00, 0x0C, 0x80.toByte(), 0x01)
        return header + qname + footer
    }

    internal data class ParsedMdnsRecord(
        val recordName: List<String>,
        val type: Int,
        val targetLabels: List<String> = emptyList(),
        val ipv4: String? = null,
        val txtPairs: Map<String, String> = emptyMap()
    )

    internal fun parseMdnsPacket(data: ByteArray): List<ParsedMdnsRecord> {
        if (data.size < 12) return emptyList()
        val qdCount = u16(data, 4)
        val anCount = u16(data, 6)
        val nsCount = u16(data, 8)
        val arCount = u16(data, 10)

        var offset = 12
        repeat(qdCount) {
            val (nextOffset, _) = readLabels(data, offset) ?: return emptyList()
            offset = nextOffset + 4
            if (offset > data.size) return emptyList()
        }

        val records = mutableListOf<ParsedMdnsRecord>()
        val totalRr = (anCount + nsCount + arCount).coerceAtMost(64)
        repeat(totalRr) {
            if (offset >= data.size) return records
            val (afterName, nameLabels) = readLabels(data, offset) ?: return records
            if (afterName + 10 > data.size) return records

            val type = u16(data, afterName)
            val rdLength = u16(data, afterName + 8)
            val rdataStart = afterName + 10
            val rdataEnd = rdataStart + rdLength
            if (rdataEnd > data.size) return records

            when (type) {
                1 -> {
                    if (rdLength == 4) {
                        val ip = Inet4Address.getByAddress(data.copyOfRange(rdataStart, rdataEnd)).hostAddress
                        records.add(ParsedMdnsRecord(nameLabels, type, ipv4 = ip))
                    }
                }
                12 -> {
                    val target = readLabels(data, rdataStart)?.second.orEmpty()
                    records.add(ParsedMdnsRecord(nameLabels, type, targetLabels = target))
                }
                33 -> {
                    if (rdLength > 6) {
                        val target = readLabels(data, rdataStart + 6)?.second.orEmpty()
                        records.add(ParsedMdnsRecord(nameLabels, type, targetLabels = target))
                    }
                }
                16 -> {
                    val kv = parseTxtRdata(data, rdataStart, rdataEnd)
                    records.add(ParsedMdnsRecord(nameLabels, type, txtPairs = kv))
                }
            }
            offset = rdataEnd
        }
        return records
    }

    private fun mergeParsedPacket(
        results: MutableMap<String, MdnsHostInfo>,
        senderIp: String?,
        records: List<ParsedMdnsRecord>
    ) {
        if (records.isEmpty()) return

        val resolvedIp = records.firstOrNull { it.ipv4 != null && !it.ipv4.startsWith("127.") }?.ipv4
            ?: senderIp
            ?: return

        var hostname: String? = null
        var friendlyName: String? = null
        var modelHint: String? = null
        val services = mutableSetOf<String>()

        for (rec in records) {
            val joinedOwner = rec.recordName.joinToString(".")
            extractServiceFromLabels(rec.recordName)?.let { services.add(it) }
            extractServiceFromLabels(rec.targetLabels)?.let { services.add(it) }

            when (rec.type) {
                1 -> {
                    val hostLabel = rec.recordName.firstOrNull { !it.startsWith("_") && it != "local" }
                    if (!hostLabel.isNullOrBlank()) {
                        hostname = hostname ?: DeviceNameResolver.sanitizeMdnsName(hostLabel)
                    }
                }
                12 -> {
                    if (joinedOwner.endsWith("in-addr.arpa", ignoreCase = true)) {
                        val ptrHost = rec.targetLabels.firstOrNull { it != "local" }
                        if (!ptrHost.isNullOrBlank()) {
                            hostname = DeviceNameResolver.sanitizeMdnsName(ptrHost)
                        }
                    } else {
                        val instance = rec.targetLabels.firstOrNull { !it.startsWith("_") && it != "local" }
                        if (!instance.isNullOrBlank()) {
                            friendlyName = friendlyName ?: DeviceNameResolver.sanitizeMdnsName(instance)
                        }
                    }
                }
                33 -> {
                    val instance = rec.recordName.firstOrNull { !it.startsWith("_") && it != "local" }
                    if (!instance.isNullOrBlank()) {
                        friendlyName = friendlyName ?: DeviceNameResolver.sanitizeMdnsName(instance)
                    }
                    val targetHost = rec.targetLabels.firstOrNull { !it.startsWith("_") && it != "local" }
                    if (!targetHost.isNullOrBlank()) {
                        hostname = hostname ?: DeviceNameResolver.sanitizeMdnsName(targetHost)
                    }
                }
                16 -> {
                    rec.txtPairs["fn"]?.takeIf { it.isNotBlank() }?.let { friendlyName = it }
                    val model = rec.txtPairs["model"] ?: rec.txtPairs["md"] ?: rec.txtPairs["ty"]
                    if (!model.isNullOrBlank()) {
                        modelHint = modelHint ?: model
                    }
                }
            }
        }

        val current = results[resolvedIp]
        results[resolvedIp] = MdnsHostInfo(
            hostname = chooseBetterName(current?.hostname, hostname),
            friendlyName = chooseBetterName(current?.friendlyName, friendlyName),
            modelHint = modelHint ?: current?.modelHint,
            services = (current?.services.orEmpty()) + services
        )
    }

    private fun chooseBetterName(existing: String?, candidate: String?): String? {
        if (candidate.isNullOrBlank()) return existing
        if (existing.isNullOrBlank()) return candidate
        val candidateLooksHex = candidate.matches(Regex("^[0-9A-Fa-f:-]{8,}$"))
        if (candidateLooksHex) return existing
        return if (candidate.length > existing.length) candidate else existing
    }

    private fun extractServiceFromLabels(labels: List<String>): String? {
        val idx = labels.indexOfFirst { it.startsWith("_") && it != "_services" }
        if (idx != -1 && idx + 1 < labels.size && labels[idx + 1].startsWith("_")) {
            return "${labels[idx]}.${labels[idx + 1]}"
        }
        return null
    }

    private fun parseTxtRdata(data: ByteArray, start: Int, end: Int): Map<String, String> {
        val map = mutableMapOf<String, String>()
        var i = start
        while (i < end) {
            val len = data[i].toInt() and 0xFF
            i += 1
            if (len == 0 || i + len > end) break
            val entry = String(data, i, len, Charsets.UTF_8)
            val eq = entry.indexOf('=')
            if (eq > 0) {
                map[entry.substring(0, eq).lowercase()] = entry.substring(eq + 1).trim()
            }
            i += len
        }
        return map
    }

    private fun readLabels(data: ByteArray, start: Int, depth: Int = 0): Pair<Int, List<String>>? {
        if (depth > 20 || start >= data.size) return null
        val labels = mutableListOf<String>()
        var i = start
        var endAfterFirstJump = -1

        while (i < data.size) {
            val b = data[i].toInt() and 0xFF
            if (b == 0) {
                if (endAfterFirstJump == -1) endAfterFirstJump = i + 1
                break
            }
            if ((b and 0xC0) == 0xC0) {
                if (i + 1 >= data.size) return null
                val ptr = ((b and 0x3F) shl 8) or (data[i + 1].toInt() and 0xFF)
                if (endAfterFirstJump == -1) endAfterFirstJump = i + 2
                val jumped = readLabels(data, ptr, depth + 1)?.second ?: return null
                labels.addAll(jumped)
                break
            }
            val len = b
            if (i + 1 + len > data.size) return null
            labels.add(String(data, i + 1, len, Charsets.UTF_8))
            i += 1 + len
        }

        val nextIdx = if (endAfterFirstJump != -1) endAfterFirstJump else i
        return nextIdx to labels
    }

    private fun u16(data: ByteArray, idx: Int): Int =
        ((data[idx].toInt() and 0xFF) shl 8) or (data[idx + 1].toInt() and 0xFF)
}
