package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.coroutineContext
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

private data class HostProbeResult(
    val ip: String,
    val latencyMs: Int?,
    val ttl: Int?,
    val openPorts: List<Int>
)

/**
 * Discovers active hosts on the current WiFi / local Ethernet subnet and classifies mobile devices
 * using ICMP ping RTT/TTL, ARP/`ip neigh`, IEEE OUI vendor lookup, mDNS (NsdManager + low-level
 * multicast DNS + reverse `.in-addr.arpa`), SSDP, NetBIOS, and gateway reverse DNS PTR queries.
 *
 * Deliberately never probes TCP ports 5289 (Wireless Helper wake) or 5277 (Android Auto Headunit
 * Server) during discovery: probing 5289 wakes phones prematurely, and probing 5277 wedges Android
 * Auto's single-accept Headunit Server socket.
 */
class CommonWifiDeviceScanner(private val context: Context) {

    init {
        OuiLookup.initialize(context)
    }

    companion object {
        private val QUICK_TCP_FALLBACK_PORTS = intArrayOf(445, 139, 22, 80, 443, 8080, 5000, 3389, 62078, 8008, 5555)
        private val ROUTER_SENSITIVE_PORTS = setOf(53, 80, 443, 8080, 8443, 23)
        private val HEURISTIC_PORTS = listOf(53, 80, 443, 8080, 8443, 22, 23, 445, 139, 3389, 5555, 62078, 8008, 8009, 7000, 7100, 9100, 515, 631)
        private const val PING_TIMEOUT_MS = 900L
        private const val PORT_TIMEOUT_MS = 240
        private const val ROUTER_PORT_TIMEOUT_MS = 380
        private const val MAX_CONCURRENCY = 50

        private val PING_RTT_REGEX = Regex("""time[=<]([\d.]+)\s*ms""")
        private val PING_TTL_REGEX = Regex("""ttl=(\d+)""", RegexOption.IGNORE_CASE)
    }

    private fun collectAllLocalIdentity(wifiInfoIp: Int, wifiMac: String?): Pair<Set<String>, Set<String>> {
        val ips = LinkedHashSet<String>()
        val macs = LinkedHashSet<String>()
        ips.add("127.0.0.1")
        if (wifiInfoIp != 0) {
            ips.add(intLittleEndianToIp(wifiInfoIp))
        }
        OuiLookup.normalizeMac(wifiMac)?.let { macs.add(it) }

        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            for (iface in interfaces) {
                try {
                    iface.hardwareAddress?.let { bytes ->
                        val formatted = bytes.joinToString(":") { "%02X".format(it) }
                        OuiLookup.normalizeMac(formatted)?.let { macs.add(it) }
                    }
                } catch (_: Exception) {
                }
                val addrs = try { iface.inetAddresses?.toList().orEmpty() } catch (_: Exception) { emptyList() }
                for (addr in addrs) {
                    if (addr is Inet4Address) {
                        addr.hostAddress?.let { ips.add(it) }
                    }
                }
            }
        } catch (_: Exception) {
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                @Suppress("DEPRECATION")
                cm?.allNetworks?.forEach { net ->
                    cm.getLinkProperties(net)?.linkAddresses?.forEach { la ->
                        val a = la.address
                        if (a is Inet4Address) {
                            a.hostAddress?.let { ips.add(it) }
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return ips to macs
    }

    fun getActiveNetworkInfo(): NetworkInfo? {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        val wifiInfo = wifiManager?.connectionInfo
        @Suppress("DEPRECATION")
        val dhcpInfo = wifiManager?.dhcpInfo

        val rawSsid = wifiInfo?.ssid?.removeSurrounding("\"")
            ?.takeUnless { it == "<unknown ssid>" || it.isBlank() }
        val bssid = OuiLookup.normalizeMac(wifiInfo?.bssid)
        @Suppress("DEPRECATION")
        val (allLocalIps, allLocalMacs) = collectAllLocalIdentity(wifiInfo?.ipAddress ?: 0, wifiInfo?.macAddress)

        val dhcpGateways = buildSet {
            if (dhcpInfo != null) {
                if (dhcpInfo.gateway != 0) add(intLittleEndianToIp(dhcpInfo.gateway))
                if (dhcpInfo.serverAddress != 0) add(intLittleEndianToIp(dhcpInfo.serverAddress))
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (cm != null) {
                // Prefer TRANSPORT_WIFI across all networks (on offline car Wi-Fi routers activeNetwork may be cellular or null).
                val candidateNetworks = buildList {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        cm.activeNetwork?.let { add(it) }
                    }
                    @Suppress("DEPRECATION")
                    addAll(cm.allNetworks.orEmpty())
                }.distinct()

                val chosenNet = candidateNetworks.firstOrNull { net ->
                    cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                } ?: candidateNetworks.firstOrNull { net ->
                    cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true
                }

                val linkProps = chosenNet?.let { cm.getLinkProperties(it) }
                if (linkProps != null) {
                    val ipv4Link = linkProps.linkAddresses.firstOrNull {
                        it.address is Inet4Address && !it.address.isLoopbackAddress
                    }
                    val localIp = ipv4Link?.address?.hostAddress
                    if (localIp != null) {
                        val routeGateways = linkProps.routes
                            .mapNotNull { route ->
                                val gw = route.gateway
                                if (gw is Inet4Address && !gw.isLoopbackAddress && gw.hostAddress != "0.0.0.0") {
                                    gw.hostAddress
                                } else {
                                    null
                                }
                            }
                        val allGateways = buildSet {
                            addAll(routeGateways)
                            addAll(dhcpGateways)
                            if (isEmpty()) {
                                guessDotOneGateway(localIp)?.let { add(it) }
                            }
                        } - localIp
                        val primaryGw = routeGateways.firstOrNull()
                            ?: dhcpGateways.firstOrNull()
                            ?: guessDotOneGateway(localIp)
                        return NetworkInfo(
                            localIp = localIp,
                            prefixLength = ipv4Link.prefixLength,
                            gatewayIp = primaryGw,
                            interfaceName = linkProps.interfaceName ?: "wlan0",
                            ssid = rawSsid,
                            bssid = bssid,
                            gatewayIps = allGateways - allLocalIps,
                            localIps = allLocalIps + localIp,
                            localMacs = allLocalMacs
                        )
                    }
                }
            }
        }

        return findFallbackNetworkInterface(rawSsid, bssid, dhcpGateways, allLocalIps, allLocalMacs)
    }

    private fun intLittleEndianToIp(ip: Int): String =
        "${ip and 0xFF}.${(ip shr 8) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 24) and 0xFF}"

    private fun guessDotOneGateway(localIp: String): String? {
        val parts = localIp.split(".")
        return if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}.1" else null
    }

    private fun findFallbackNetworkInterface(
        ssid: String?,
        bssid: String?,
        dhcpGateways: Set<String>,
        allLocalIps: Set<String>,
        allLocalMacs: Set<String>
    ): NetworkInfo? {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            for (iface in interfaces) {
                if (!iface.isUp || iface.isLoopback || iface.isVirtual) continue
                val lowerName = iface.name.lowercase()
                if (lowerName.startsWith("rmnet") || lowerName.startsWith("ccmni") || lowerName.startsWith("p2p")) continue
                for (addr in iface.interfaceAddresses) {
                    val inet = addr.address
                    if (inet is Inet4Address && !inet.isLoopbackAddress && inet.isSiteLocalAddress) {
                        val ip = inet.hostAddress ?: continue
                        val localSet = allLocalIps + ip
                        val primaryGw = dhcpGateways.firstOrNull() ?: guessDotOneGateway(ip)
                        val gateways = (dhcpGateways + setOfNotNull(primaryGw)) - localSet
                        return NetworkInfo(
                            localIp = ip,
                            prefixLength = addr.networkPrefixLength.toInt().coerceIn(8, 30),
                            gatewayIp = primaryGw?.takeIf { it !in localSet },
                            interfaceName = iface.name,
                            ssid = ssid,
                            bssid = bssid,
                            gatewayIps = gateways,
                            localIps = localSet,
                            localMacs = allLocalMacs
                        )
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    fun scanNetwork(): Flow<ScanUpdate> = flow {
        val netInfo = getActiveNetworkInfo()
        if (netInfo == null) {
            emit(
                ScanUpdate(
                    networkInfo = null,
                    progress = 0f,
                    phaseMessage = "Disconnected",
                    devices = emptyList(),
                    isScanning = false,
                    errorMessage = "Not connected to a Wi-Fi or local Ethernet network."
                )
            )
            return@flow
        }

        val selfIps = netInfo.localIps + netInfo.localIp
        val selfMacs = buildSet {
            addAll(netInfo.localMacs)
            getLocalInterfaceMac(netInfo.interfaceName)?.let { add(it) }
        }
        val knownGatewayIps = buildSet {
            addAll(netInfo.gatewayIps)
            netInfo.gatewayIp?.let { add(it) }
        } - selfIps

        fun isSelfDevice(ip: String, mac: String?): Boolean {
            if (ip in selfIps) return true
            if (mac != null && selfMacs.any { it.equals(mac, ignoreCase = true) }) return true
            return false
        }

        fun isKnownGateway(ip: String, mac: String?): Boolean {
            if (ip in knownGatewayIps) return true
            if (netInfo.bssid != null && mac != null && mac.equals(netInfo.bssid, ignoreCase = true)) return true
            return false
        }

        emit(
            ScanUpdate(
                networkInfo = netInfo,
                progress = 0.1f,
                phaseMessage = "Scanning Wi-Fi network...",
                devices = emptyList(),
                isScanning = true
            )
        )

        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val multicastLock = wifiManager?.createMulticastLock("OpenHeadUnitCommonWifiScan")?.apply {
            setReferenceCounted(false)
            try {
                acquire()
            } catch (_: Exception) {
            }
        }

        try {
            val hostsToScan = SubnetUtils.getHostAddresses(netInfo.localIp, netInfo.prefixLength)
                .filter { it !in selfIps && it !in knownGatewayIps }

            emit(
                ScanUpdate(
                    networkInfo = netInfo,
                    progress = 0.25f,
                    phaseMessage = "Sweeping ${hostsToScan.size} subnet addresses...",
                    devices = emptyList(),
                    isScanning = true
                )
            )

            val (ssdpMap, nsdMdnsMap, hostProbes) = coroutineScope {
                val ssdpDeferred = async { DeviceNameResolver.discoverSsdpDevices(1400L) }
                val mdnsDeferred = async { DeviceNameResolver.discoverMdnsNames(context, 1500L) }

                val semaphore = Semaphore(MAX_CONCURRENCY)
                val probeJobs = hostsToScan.map { ip ->
                    async(Dispatchers.IO) {
                        semaphore.withPermit {
                            coroutineContext.ensureActive()
                            pingOrTcpReachable(ip)
                        }
                    }
                }

                val reachable = probeJobs.awaitAll().filterNotNull().associateBy { it.ip }
                Triple(ssdpDeferred.await(), mdnsDeferred.await(), reachable)
            }

            val rawMdnsMap = LowLevelMdnsScanner.scanLanMdns(
                reverseLookupIps = hostProbes.keys.toList(),
                listenDurationMs = 1000L
            )

            val arpFirst = ArpTableReader.readArpTable()
            delay(200L)
            val arpTable = arpFirst + ArpTableReader.readArpTable()

            val mdnsIps = nsdMdnsMap.keys + rawMdnsMap.keys
            val candidateIps = (
                hostProbes.keys +
                    arpTable.keys +
                    ssdpMap.keys +
                    mdnsIps
                )
                .filter { ip ->
                    ip in hostsToScan &&
                        !isSelfDevice(ip, arpTable[ip]) &&
                        !isKnownGateway(ip, arpTable[ip])
                }
                .distinct()
                .sortedWith(SubnetUtils::compareIps)

            fun combinedMdnsName(ip: String): String? {
                val low = rawMdnsMap[ip]
                return listOfNotNull(
                    low?.friendlyName?.takeIf { it.isNotBlank() },
                    low?.hostname?.takeIf { it.isNotBlank() },
                    nsdMdnsMap[ip]?.first?.takeIf { it.isNotBlank() }
                ).firstOrNull()
            }

            fun combinedMdnsServices(ip: String): List<String> {
                return (rawMdnsMap[ip]?.services.orEmpty() + nsdMdnsMap[ip]?.second.orEmpty()).distinct()
            }

            val previewDevices = candidateIps.mapNotNull { ip ->
                val probe = hostProbes[ip]
                val mac = arpTable[ip]
                if (isSelfDevice(ip, mac) || isKnownGateway(ip, mac)) return@mapNotNull null
                val isRand = OuiLookup.isRandomizedMac(mac)
                val vendor = OuiLookup.lookupVendor(mac)
                val rawVendor = OuiLookup.lookupRawVendor(mac) ?: vendor
                val mdnsName = combinedMdnsName(ip)
                val prelimType = DeviceClassifier.classify(
                    isGateway = false,
                    isLocalDevice = false,
                    macAddress = mac,
                    deviceName = mdnsName ?: ssdpMap[ip]?.friendlyName,
                    vendor = rawVendor,
                    mdnsServices = combinedMdnsServices(ip),
                    ssdpDeviceType = ssdpMap[ip]?.deviceType,
                    ssdpModel = rawMdnsMap[ip]?.modelHint,
                    isRandomizedMac = isRand,
                    ttl = probe?.ttl,
                    portsProbed = false
                )
                NetworkDevice(
                    ipAddress = ip,
                    deviceName = mdnsName
                        ?: ssdpMap[ip]?.friendlyName?.takeIf { it.isNotBlank() }
                        ?: vendor?.let { "$it (${ip.substringAfterLast('.')})" }
                        ?: if (prelimType == DeviceType.MOBILE_TABLET) "Mobile Device (${ip.substringAfterLast('.')})" else ip,
                    macAddress = mac,
                    isRandomizedMac = isRand,
                    vendor = vendor,
                    deviceType = prelimType,
                    ttl = probe?.ttl,
                    latencyMs = probe?.latencyMs,
                    isGateway = prelimType == DeviceType.ROUTER
                )
            }

            emit(
                ScanUpdate(
                    networkInfo = netInfo,
                    progress = 0.65f,
                    phaseMessage = "Identifying mobile devices...",
                    devices = CommonWifiDevicePolicy.mobileCandidates(previewDevices, localIps = selfIps, gatewayIps = knownGatewayIps),
                    isScanning = true
                )
            )

            val gatewayAnswersDns = netInfo.gatewayIp?.let { gw ->
                DnsLookup.queryPtr(gw, gw, timeoutMs = 500) != null
            } ?: false

            val finalDevices = coroutineScope {
                val detailSemaphore = Semaphore(20)
                candidateIps.map { ip ->
                    async(Dispatchers.IO) {
                        detailSemaphore.withPermit {
                            coroutineContext.ensureActive()
                            val mac = arpTable[ip]
                            if (isSelfDevice(ip, mac) || isKnownGateway(ip, mac)) return@withPermit null
                            val probe = hostProbes[ip]
                            val openPorts = probePorts(ip, HEURISTIC_PORTS)
                            val isRandomized = OuiLookup.isRandomizedMac(mac)
                            val ssdp = ssdpMap[ip]
                            val mdnsName = combinedMdnsName(ip)
                            val mdnsServices = combinedMdnsServices(ip)
                            val mdnsModel = rawMdnsMap[ip]?.modelHint

                            val vendor = OuiLookup.lookupVendor(mac)
                                ?: ssdp?.manufacturer?.let { OuiLookup.simplifyVendorName(it) }
                            val rawVendorForClassify = OuiLookup.lookupRawVendor(mac) ?: vendor

                            val netBiosName = DeviceNameResolver.queryNetBiosName(ip, timeoutMs = 260)

                            val gatewayDnsName = if (gatewayAnswersDns && netInfo.gatewayIp != null) {
                                DnsLookup.queryPtr(netInfo.gatewayIp, ip, timeoutMs = 400)
                                    ?.takeIf { it.isNotBlank() && it != ip && DeviceNameResolver.isPlausibleHostname(it) }
                            } else {
                                null
                            }

                            val reverseDnsName = if (gatewayDnsName == null && mdnsName == null && ssdp?.friendlyName == null && netBiosName == null) {
                                DeviceNameResolver.resolveReverseDns(ip)
                            } else {
                                null
                            }

                            val resolvedHostname = listOfNotNull(
                                mdnsName,
                                ssdp?.friendlyName?.takeIf { it.isNotBlank() },
                                netBiosName?.takeIf { it.isNotBlank() },
                                gatewayDnsName?.takeIf { it.isNotBlank() },
                                reverseDnsName?.takeIf { it.isNotBlank() }
                            ).firstOrNull()

                            val modelAndServerHints = listOfNotNull(
                                mdnsModel,
                                ssdp?.modelName,
                                ssdp?.serverHint
                            ).joinToString(" ").takeIf { it.isNotBlank() }

                            val deviceType = DeviceClassifier.classify(
                                isGateway = false,
                                isLocalDevice = false,
                                macAddress = mac,
                                deviceName = resolvedHostname,
                                vendor = rawVendorForClassify,
                                openPorts = openPorts,
                                mdnsServices = mdnsServices,
                                ssdpDeviceType = ssdp?.deviceType,
                                ssdpModel = modelAndServerHints,
                                hasNetBios = netBiosName != null,
                                isRandomizedMac = isRandomized,
                                ttl = probe?.ttl,
                                portsProbed = true
                            )

                            val displayName = resolvedHostname ?: when {
                                vendor != null -> "$vendor (${ip.substringAfterLast('.')})"
                                deviceType == DeviceType.MOBILE_TABLET -> "Mobile Device (${ip.substringAfterLast('.')})"
                                else -> ip
                            }

                            val method = buildList {
                                if (probe?.ttl != null) add("ICMP")
                                if (openPorts.isNotEmpty()) add("TCP")
                                if (mac != null) add("ARP")
                                if (mdnsName != null || mdnsServices.isNotEmpty()) add("mDNS")
                                if (ssdp != null) add("SSDP")
                                if (netBiosName != null) add("NetBIOS")
                                if (gatewayDnsName != null) add("DHCP-DNS")
                            }.ifEmpty { listOf("ARP") }.joinToString(" · ")

                            val isClassifiedRouter = deviceType == DeviceType.ROUTER

                            NetworkDevice(
                                ipAddress = ip,
                                deviceName = displayName,
                                macAddress = mac,
                                isRandomizedMac = isRandomized,
                                vendor = vendor,
                                deviceType = deviceType,
                                openPorts = openPorts,
                                discoveryMethod = method,
                                ttl = probe?.ttl,
                                latencyMs = probe?.latencyMs,
                                isGateway = isClassifiedRouter,
                                isLocalDevice = false
                            )
                        }
                    }
                }.awaitAll().filterNotNull()
            }

            val mobileDevicesOnly = CommonWifiDevicePolicy.mobileCandidates(
                finalDevices,
                localIps = selfIps,
                gatewayIps = knownGatewayIps
            )

            emit(
                ScanUpdate(
                    networkInfo = netInfo,
                    progress = 1f,
                    phaseMessage = "Scan complete",
                    devices = mobileDevicesOnly,
                    isScanning = false
                )
            )
        } finally {
            try {
                if (multicastLock?.isHeld == true) {
                    multicastLock.release()
                }
            } catch (_: Exception) {
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * minSdk-16-compatible ICMP ping (`Process.waitFor(timeout, unit)` is API 26, so we bound the
     * wait via `withTimeoutOrNull` and call `process.destroy()` in `finally`), falling back to
     * quick safe TCP ports when ICMP is dropped.
     */
    private suspend fun pingOrTcpReachable(ip: String): HostProbeResult? {
        coroutineContext.ensureActive()
        val startMs = System.currentTimeMillis()
        var process: Process? = null
        try {
            val pingResult = withTimeoutOrNull(PING_TIMEOUT_MS + 350L) {
                withContext(Dispatchers.IO) {
                    val p = Runtime.getRuntime().exec(arrayOf("/system/bin/ping", "-c", "1", "-W", "1", ip))
                    process = p
                    val output = p.inputStream.bufferedReader().readText()
                    val exit = p.waitFor()
                    if (exit == 0) output else null
                }
            }
            if (pingResult != null) {
                val rtt = PING_RTT_REGEX.find(pingResult)?.groupValues?.getOrNull(1)?.toFloatOrNull()?.toInt()
                if (rtt != null) {
                    val ttl = PING_TTL_REGEX.find(pingResult)?.groupValues?.getOrNull(1)?.toIntOrNull()
                    return HostProbeResult(ip = ip, latencyMs = rtt, ttl = ttl, openPorts = emptyList())
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
        } finally {
            try {
                process?.destroy()
            } catch (_: Exception) {
            }
        }

        return withContext(Dispatchers.IO) {
            val hit = CompletableDeferred<Int>()
            val jobs = QUICK_TCP_FALLBACK_PORTS.map { port ->
                async {
                    if (isPortOpen(ip, port, 180)) {
                        hit.complete(port)
                    }
                }
            }
            val firstPort = withTimeoutOrNull(500L) { hit.await() }
            jobs.forEach { it.cancel() }
            if (firstPort != null) {
                val elapsed = (System.currentTimeMillis() - startMs).toInt()
                HostProbeResult(ip = ip, latencyMs = elapsed, ttl = null, openPorts = listOf(firstPort))
            } else {
                null
            }
        }
    }

    private suspend fun probePorts(ip: String, ports: List<Int>): List<Int> = coroutineScope {
        ports.map { port ->
            async(Dispatchers.IO) {
                val timeout = if (port in ROUTER_SENSITIVE_PORTS) ROUTER_PORT_TIMEOUT_MS else PORT_TIMEOUT_MS
                if (isPortOpen(ip, port, timeout)) port else null
            }
        }.awaitAll().filterNotNull().sorted()
    }

    private fun isPortOpen(ip: String, port: Int, timeoutMs: Int): Boolean {
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(ip, port), timeoutMs)
            true
        } catch (_: Exception) {
            false
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun getLocalInterfaceMac(interfaceName: String): String? {
        return try {
            val iface = NetworkInterface.getByName(interfaceName) ?: return null
            val bytes = iface.hardwareAddress ?: return null
            val mac = bytes.joinToString(":") { "%02X".format(it) }
            OuiLookup.normalizeMac(mac)
        } catch (_: Exception) {
            null
        }
    }
}
