package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

/**
 * Pure filtering and ordering rules for the Common WiFi (NSD) mobile device selector.
 *
 * Strictly returns only [DeviceType.MOBILE_TABLET] peers (smartphones / tablets) on the shared
 * network — excluding this head unit itself, routers/gateways, PCs, TVs, printers, and IoT devices.
 */
object CommonWifiDevicePolicy {

    private val APPLE_HINTS = listOf("iphone", "ipad", "ipod", "ios")

    fun mobileCandidates(
        devices: Collection<NetworkDevice>,
        lastUsedIp: String? = null,
        localIps: Set<String> = emptySet(),
        gatewayIps: Set<String> = emptySet()
    ): List<NetworkDevice> =
        sortForSelection(
            devices.filter {
                !it.isLocalDevice &&
                    !it.isGateway &&
                    it.ipAddress !in localIps &&
                    it.ipAddress !in gatewayIps &&
                    it.deviceType == DeviceType.MOBILE_TABLET
            },
            lastUsedIp
        )

    fun isLikelyAppleDevice(device: NetworkDevice): Boolean {
        if (device.vendor.equals("Apple", ignoreCase = true)) return true
        if (62078 in device.openPorts) return true
        val lowerName = device.deviceName.lowercase()
        return APPLE_HINTS.any { it in lowerName }
    }

    fun sortForSelection(devices: Collection<NetworkDevice>, lastUsedIp: String? = null): List<NetworkDevice> {
        val preferredIp = lastUsedIp?.trim()?.takeIf { it.isNotEmpty() }
        return devices.sortedWith(
            compareByDescending<NetworkDevice> { preferredIp != null && it.ipAddress == preferredIp }
                .thenBy { isLikelyAppleDevice(it) }
                .thenComparator { a, b -> SubnetUtils.compareIps(a.ipAddress, b.ipAddress) }
        )
    }

    fun subtitleFor(device: NetworkDevice): String {
        val parts = mutableListOf<String>()
        parts.add(device.ipAddress)
        device.vendor?.takeIf {
            it.isNotBlank() && !device.deviceName.contains(it, ignoreCase = true)
        }?.let { parts.add(it) }
        device.latencyMs?.let { parts.add("${it}ms") }
        return parts.joinToString(" · ")
    }
}
