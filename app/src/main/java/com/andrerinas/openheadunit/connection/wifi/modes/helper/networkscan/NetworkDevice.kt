package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

enum class DeviceType(val label: String) {
    ROUTER("Router"),
    MOBILE_TABLET("Mobile / Tablet"),
    PC_LAPTOP("PC / Laptop"),
    TV_MEDIA("TV / Media"),
    PRINTER("Printer"),
    IOT("IoT / Smart Home"),
    UNKNOWN("Unknown")
}

data class NetworkDevice(
    val ipAddress: String,
    val deviceName: String,
    val macAddress: String? = null,
    val isRandomizedMac: Boolean = false,
    val vendor: String? = null,
    val deviceType: DeviceType = DeviceType.UNKNOWN,
    val openPorts: List<Int> = emptyList(),
    val discoveryMethod: String = "",
    val ttl: Int? = null,
    val latencyMs: Int? = null,
    val isGateway: Boolean = false,
    val isLocalDevice: Boolean = false
)

data class NetworkInfo(
    val localIp: String,
    val prefixLength: Int,
    val gatewayIp: String?,
    val interfaceName: String,
    val ssid: String? = null,
    val bssid: String? = null,
    val gatewayIps: Set<String> = emptySet(),
    val localIps: Set<String> = emptySet(),
    val localMacs: Set<String> = emptySet()
)

data class ScanUpdate(
    val networkInfo: NetworkInfo?,
    val progress: Float,
    val phaseMessage: String,
    val devices: List<NetworkDevice>,
    val isScanning: Boolean,
    val errorMessage: String? = null
)
