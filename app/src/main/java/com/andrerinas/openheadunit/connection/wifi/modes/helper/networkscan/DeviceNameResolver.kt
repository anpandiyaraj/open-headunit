package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import com.andrerinas.openheadunit.utils.useSocket

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger

data class SsdpResult(
    val ip: String,
    val friendlyName: String? = null,
    val manufacturer: String? = null,
    val modelName: String? = null,
    val deviceType: String? = null,
    val serverHint: String? = null,
    val locationUrl: String? = null
)

object DeviceNameResolver {

    private val MDNS_SERVICE_TYPES = listOf(
        "_http._tcp.",
        "_https._tcp.",
        "_workstation._tcp.",
        "_smb._tcp.",
        "_afpovertcp._tcp.",
        "_airplay._tcp.",
        "_raop._tcp.",
        "_googlecast._tcp.",
        "_androidtvremote2._tcp.",
        "_spotify-connect._tcp.",
        "_printer._tcp.",
        "_ipp._tcp.",
        "_ssh._tcp.",
        "_homekit._tcp.",
        "_matter._tcp.",
        "_companion-link._tcp."
    )

    suspend fun resolveReverseDns(ip: String): String? = withContext(Dispatchers.IO) {
        try {
            val addr = InetAddress.getByName(ip)
            val host = addr.canonicalHostName
            if (!host.isNullOrBlank() && host != ip && isPlausibleHostname(host)) {
                host.removeSuffix(".local").removeSuffix(".lan").removeSuffix(".home")
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    internal fun isPlausibleHostname(name: String): Boolean {
        if (name.isBlank() || name.length > 253) return false
        return name.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' || it == ' ' }
    }

    suspend fun queryNetBiosName(ip: String, timeoutMs: Int = 280): String? = withContext(Dispatchers.IO) {
        try {
            DatagramSocket().useSocket { socket ->
                socket.soTimeout = timeoutMs
                val query = byteArrayOf(
                    0x13, 0x37,
                    0x00, 0x00,
                    0x00, 0x01,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x20,
                    0x43, 0x4B,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x00,
                    0x00, 0x21,
                    0x00, 0x01
                )
                val address = InetAddress.getByName(ip)
                socket.send(DatagramPacket(query, query.size, address, 137))

                val buffer = ByteArray(1024)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                parseNetBiosResponse(buffer, response.length)
            }
        } catch (_: Exception) {
            null
        }
    }

    internal fun parseNetBiosResponse(data: ByteArray, length: Int): String? {
        if (length < 57) return null
        val answerCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
        if (answerCount == 0) return null

        val qdCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val answerStart = if (qdCount > 0) 50 else 12
        if (answerStart >= length) return null

        val nameFieldLen = if ((data[answerStart].toInt() and 0xC0) == 0xC0) 2 else 34
        val numNamesOffset = answerStart + nameFieldLen + 10
        if (numNamesOffset >= length) return null

        val numNames = data[numNamesOffset].toInt() and 0xFF
        var offset = numNamesOffset + 1

        for (i in 0 until numNames) {
            if (offset + 18 > length) break
            val name = String(data, offset, 15, Charsets.ISO_8859_1).trimEnd()
            val suffix = data[offset + 15].toInt() and 0xFF
            val flags = ((data[offset + 16].toInt() and 0xFF) shl 8) or (data[offset + 17].toInt() and 0xFF)
            val isGroup = (flags and 0x8000) != 0
            if (!isGroup && (suffix == 0x00 || suffix == 0x20) && name.isNotBlank()) {
                return name
            }
            offset += 18
        }
        return null
    }

    suspend fun discoverSsdpDevices(durationMs: Long = 1400L): Map<String, SsdpResult> =
        withContext(Dispatchers.IO) {
            val lock = Any()
            val results = LinkedHashMap<String, SsdpResult>()
            try {
                DatagramSocket().useSocket { socket ->
                    socket.soTimeout = 350
                    socket.broadcast = true
                    val searchMsg = (
                        "M-SEARCH * HTTP/1.1\r\n" +
                            "HOST: 239.255.255.250:1900\r\n" +
                            "MAN: \"ssdp:discover\"\r\n" +
                            "MX: 1\r\n" +
                            "ST: ssdp:all\r\n\r\n"
                        ).toByteArray(Charsets.UTF_8)

                    val group = InetAddress.getByName("239.255.255.250")
                    socket.send(DatagramPacket(searchMsg, searchMsg.size, group, 1900))

                    val deadline = System.currentTimeMillis() + durationMs
                    val buf = ByteArray(2048)

                    while (System.currentTimeMillis() < deadline) {
                        coroutineContext.ensureActive()
                        try {
                            val packet = DatagramPacket(buf, buf.size)
                            socket.receive(packet)
                            val ip = packet.address.hostAddress ?: continue
                            val payload = String(packet.data, 0, packet.length, Charsets.UTF_8)
                            val server = extractHeader(payload, "SERVER")
                            val location = extractHeader(payload, "LOCATION")
                            val st = extractHeader(payload, "ST")
                            synchronized(lock) {
                                val existing = results[ip]
                                results[ip] = SsdpResult(
                                    ip = ip,
                                    deviceType = st ?: existing?.deviceType,
                                    serverHint = server ?: existing?.serverHint,
                                    locationUrl = location ?: existing?.locationUrl
                                )
                            }
                        } catch (_: Exception) {
                        }
                    }
                }

                val itemsToFetch = synchronized(lock) { results.values.filter { it.locationUrl != null } }
                coroutineScope {
                    itemsToFetch.map { item ->
                        async {
                            val desc = fetchUpnpDescription(item.locationUrl!!) ?: return@async
                            synchronized(lock) {
                                val cur = results[item.ip]
                                if (cur != null) {
                                    results[item.ip] = cur.copy(
                                        friendlyName = desc.friendlyName ?: cur.friendlyName,
                                        manufacturer = desc.manufacturer ?: cur.manufacturer,
                                        modelName = desc.modelName ?: cur.modelName,
                                        deviceType = desc.deviceType ?: cur.deviceType
                                    )
                                }
                            }
                        }
                    }.awaitAll()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
            }
            synchronized(lock) { LinkedHashMap(results) }
        }

    private fun extractHeader(payload: String, headerName: String): String? {
        return payload.lineSequence()
            .firstOrNull { it.startsWith("$headerName:", ignoreCase = true) }
            ?.substringAfter(':')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
    }

    private fun fetchUpnpDescription(locationUrl: String): SsdpResult? {
        return try {
            val conn = (URL(locationUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 800
                readTimeout = 800
                requestMethod = "GET"
            }
            val xml = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()
            SsdpResult(
                ip = "",
                friendlyName = extractXmlTag(xml, "friendlyName"),
                manufacturer = extractXmlTag(xml, "manufacturer"),
                modelName = extractXmlTag(xml, "modelName"),
                deviceType = extractXmlTag(xml, "deviceType")
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun extractXmlTag(xml: String, tag: String): String? {
        val match = Regex("<$tag>([^<]*)</$tag>", RegexOption.IGNORE_CASE).find(xml)
        return match?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
    }

    suspend fun discoverMdnsNames(
        context: Context,
        durationMs: Long = 1500L
    ): Map<String, Pair<String, List<String>>> = withContext(Dispatchers.IO) {
        val lock = Any()
        val discovered = LinkedHashMap<String, Pair<String, MutableList<String>>>()
        val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
            ?: return@withContext emptyMap()

        val pendingResolves = AtomicInteger(0)
        val listeners = mutableListOf<NsdManager.DiscoveryListener>()
        try {
            MDNS_SERVICE_TYPES.forEach { serviceType ->
                val listener = object : NsdManager.DiscoveryListener {
                    override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {}
                    override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {}
                    override fun onDiscoveryStarted(serviceType: String?) {}
                    override fun onDiscoveryStopped(serviceType: String?) {}
                    override fun onServiceLost(serviceInfo: NsdServiceInfo?) {}
                    override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                        pendingResolves.incrementAndGet()
                        @Suppress("DEPRECATION")
                        nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(info: NsdServiceInfo?, errorCode: Int) {
                                pendingResolves.decrementAndGet()
                            }

                            override fun onServiceResolved(resolved: NsdServiceInfo) {
                                try {
                                    val ip = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                                        val addrs = resolved.hostAddresses
                                        addrs.firstOrNull { it is Inet4Address }?.hostAddress
                                            ?: addrs.firstOrNull()?.hostAddress
                                    } else {
                                        @Suppress("DEPRECATION")
                                        resolved.host?.hostAddress
                                    } ?: return
                                    if (ip.startsWith("fe80")) return

                                    val cleanName = sanitizeMdnsName(resolved.serviceName ?: "")
                                    val type = resolved.serviceType ?: ""
                                    synchronized(lock) {
                                        val current = discovered[ip]
                                        if (current == null) {
                                            discovered[ip] = cleanName to mutableListOf(type)
                                        } else {
                                            if (type !in current.second) current.second.add(type)
                                            val bestName = if (current.first.isNotBlank() && current.first.length >= cleanName.length) {
                                                current.first
                                            } else {
                                                cleanName
                                            }
                                            discovered[ip] = bestName to current.second
                                        }
                                    }
                                } finally {
                                    pendingResolves.decrementAndGet()
                                }
                            }
                        })
                    }
                }
                try {
                    nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
                    listeners.add(listener)
                } catch (_: Exception) {
                }
            }
            delay(durationMs)
        } finally {
            listeners.forEach { listener ->
                try {
                    nsdManager.stopServiceDiscovery(listener)
                } catch (_: Exception) {
                }
            }
        }

        val waitUntil = System.currentTimeMillis() + 500L
        while (pendingResolves.get() > 0 && System.currentTimeMillis() < waitUntil) {
            delay(50)
        }
        synchronized(lock) {
            discovered.mapValues { (_, v) -> v.first to v.second.toList() }
        }
    }

    internal fun sanitizeMdnsName(name: String): String {
        val stripped = name.replace(Regex("-[0-9a-fA-F]{8,}$"), "")
        return stripped.replace('-', ' ').trim()
    }
}
