package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

object DeviceClassifier {

    private val PRINTER_PORTS = setOf(9100, 515, 631)
    private val ROUTER_PORTS = setOf(53)
    private val WEB_OR_ADMIN_PORTS = setOf(80, 443, 8080, 8443, 23)
    private val PC_PORTS = setOf(445, 139, 3389, 22, 5900)
    private val SERVER_OR_INFRA_PORTS =
        PRINTER_PORTS + ROUTER_PORTS + WEB_OR_ADMIN_PORTS + PC_PORTS

    private val ROUTER_KEYWORDS = listOf(
        "router", "gateway", "openwrt", "mikrotik", "routerboard", "ubiquiti", "unifi",
        "fritz", "avm", "compal", "arcadyan", "sagemcom", "technicolor", "sercomm",
        "fiberhome", "calix", "tp-link", "tplink", "netgear", "linksys", "d-link",
        "dlink", "cisco", "eero", "orbi", "arris", "zyxel", "tenda", "mercusys",
        "archer", "deco", "echolife", "hg8", "ont", "onu", "cpe", "hgu", "speedport",
        "livebox", "freebox", "bbox", "jiofiber", "dasan", "humax", "kaon", "mitrastar",
        "wlan-ap", "access point", "repeater", "extender", "mifi"
    )
    private val PRINTER_KEYWORDS = listOf(
        "printer", "epson", "canon", "brother", "laserjet", "deskjet", "officejet", "ipp", "xerox", "lexmark"
    )
    private val TV_KEYWORDS = listOf(
        "chromecast", "appletv", "apple tv", "airplay", "roku", "bravia", "azurewave",
        "tizen", "webos", "firetv", "fire tv", "smarttv", "smart tv", "androidtv",
        "television", "samsung tv", "lg tv", "sony tv", "shield"
    )
    private val EXPLICIT_MOBILE_NAME_KEYWORDS = listOf(
        "iphone", "ipad", "ipod", "android", "mobile", "smartphone", "phone", "tablet",
        "galaxy", "pixel", "redmi", "poco", "oneplus", "nord", "sm-", "gt-", "cph",
        "reno", "iqoo", "realme", "rmx", "narzo", "moto", "razr", "fairphone",
        "nothing phone", "infinix", "tecno", "itel", "meizu", "xperia", "zenfone",
        "mi pad", "mi-pad", "galaxy tab", "galaxy-tab", "lenovo tab", "lenovo-tab",
        "fire hd", "fire-hd"
    )
    private val MOBILE_VENDOR_KEYWORDS = listOf(
        "xiaomi communications", "xiaomi", "huawei", "honor", "samsung", "oppo",
        "vivo", "realme", "motorola", "oneplus", "fairphone", "nothing", "nokia",
        "hmd", "infinix", "tecno", "transsion", "itel", "meizu", "htc", "zte",
        "blackberry", "wingtech", "huaqin", "longcheer", "tinno", "lg mobile",
        "lg electronics (mobile", "sony mobile", "apple", "google"
    )
    private val PC_KEYWORDS = listOf(
        "macbook", "imac", "mac mini", "mac-mini", "macpro", "desktop", "laptop", "notebook",
        "thinkpad", "chromebook", "workstation", "windows", "ubuntu", "debian", "fedora",
        "dell", "lenovo", "lcfc", "micro-star", "msi", "acer", "asrock", "gigabyte", "giga-byte",
        "hewlett", "microsoft", "surface", "intel", "vmware", "virtualbox"
    )
    private val IOT_KEYWORDS = listOf(
        "xiaomi smart home", "xiaomi electronics", "esp_", "esp-", "espressif", "tuya",
        "shelly", "hue", "nest", "wyze", "ring", "echo", "alexa", "homepod", "sonos",
        "google home", "camera", "smartplug", "thermostat", "raspberry", "tasmota"
    )

    fun classify(
        isGateway: Boolean,
        isLocalDevice: Boolean = false,
        macAddress: String? = null,
        deviceName: String? = null,
        vendor: String? = null,
        openPorts: List<Int> = emptyList(),
        mdnsServices: List<String> = emptyList(),
        ssdpDeviceType: String? = null,
        ssdpModel: String? = null,
        hasNetBios: Boolean = false,
        isRandomizedMac: Boolean = false,
        ttl: Int? = null,
        portsProbed: Boolean = true
    ): DeviceType {
        if (isGateway) return DeviceType.ROUTER
        if (isLocalDevice) return DeviceType.MOBILE_TABLET
        if (macAddress?.startsWith("52:54:00") == true || macAddress?.startsWith("08:00:27") == true) {
            return DeviceType.PC_LAPTOP
        }

        val ports = openPorts.toSet()

        // Routers / gateways expose DNS (port 53) or UPnP InternetGatewayDevice; phones never do.
        if (ports.any { it in ROUTER_PORTS }) {
            return DeviceType.ROUTER
        }

        if (!ssdpDeviceType.isNullOrBlank()) {
            val st = ssdpDeviceType.lowercase()
            when {
                "internetgatewaydevice" in st || "wandevice" in st || "wanconnectiondevice" in st || "wfawlanconfig" in st ->
                    return DeviceType.ROUTER
                "printer" in st -> return DeviceType.PRINTER
                "mediarenderer" in st -> return DeviceType.TV_MEDIA
            }
        }

        // Reliable mDNS service types
        for (rawService in mdnsServices) {
            val s = rawService.lowercase()
            when {
                // _aawireless._tcp is advertised by an Android Auto head unit receiver (self), never a phone client.
                "_aawireless" in s -> return DeviceType.IOT
                "_companion-link" in s -> return DeviceType.MOBILE_TABLET
                "_printer" in s || "_ipp" in s || "_pdl" in s -> return DeviceType.PRINTER
                "_airplay" in s || "_androidtvremote2" in s -> return DeviceType.TV_MEDIA
                "_homekit" in s || "_matter" in s || "_raop" in s || "_spotify-connect" in s -> return DeviceType.IOT
                "_smb" in s || "_afpovertcp" in s || "_ssh" in s || "_workstation" in s -> return DeviceType.PC_LAPTOP
            }
        }

        // Strong TCP port heuristics
        when {
            ports.any { it in PRINTER_PORTS } -> return DeviceType.PRINTER
            7000 in ports || 7100 in ports -> return DeviceType.TV_MEDIA
            8008 in ports && 8009 in ports -> return DeviceType.TV_MEDIA
            8008 in ports && 8009 !in ports && ports.none { it in WEB_OR_ADMIN_PORTS } -> return DeviceType.MOBILE_TABLET
            (5555 in ports || 62078 in ports) && ports.none { it in WEB_OR_ADMIN_PORTS } -> return DeviceType.MOBILE_TABLET
            ports.any { it in PC_PORTS } -> return DeviceType.PC_LAPTOP
        }

        val nameAndModel = listOfNotNull(deviceName, ssdpModel).joinToString(" ").lowercase()
        val hasServerPorts = ports.any { it in SERVER_OR_INFRA_PORTS }

        // Check hostname / SSDP model keywords first (router keywords win before brand names like Huawei/Xiaomi/Nokia/ZTE).
        if (nameAndModel.isNotBlank()) {
            matchNameKeywords(nameAndModel, hasServerPorts)?.let { return it }
        }

        // Any device serving HTTP/HTTPS/Telnet admin ports (80, 443, 8080, 8443, 23) without mobile proof is a router/server/IoT, never a phone.
        if (ports.any { it in WEB_OR_ADMIN_PORTS }) {
            val vendorLower = vendor?.lowercase().orEmpty()
            if (ROUTER_KEYWORDS.any { it in vendorLower || it in nameAndModel }) {
                return DeviceType.ROUTER
            }
            return DeviceType.ROUTER
        }

        // Vendor matching (only reached when ports are probed and NO server/admin ports are open!)
        if (portsProbed && !hasServerPorts) {
            val vendorLower = vendor?.lowercase().orEmpty()
            if (vendorLower.isNotBlank()) {
                matchVendorKeywords(vendorLower)?.let { return it }
            }
        }

        // NetBIOS or Windows TTL (128) -> PC / Laptop
        if (hasNetBios || (ttl != null && ttl in 115..130)) {
            return DeviceType.PC_LAPTOP
        }

        if (!portsProbed) {
            return DeviceType.UNKNOWN
        }

        // Passive smartphone/tablet heuristics (only after port & SSDP/NetBIOS probing confirms zero server/infra services):
        if (isRandomizedMac && !hasNetBios && ssdpDeviceType == null && (ttl == null || ttl <= 64) && !hasServerPorts) {
            return DeviceType.MOBILE_TABLET
        }

        val hasNonMobileMdns = mdnsServices.any { s ->
            val lower = s.lowercase()
            "_googlecast" !in lower && "_companion-link" !in lower
        }
        if (ttl != null && ttl in 48..64 &&
            !hasNetBios &&
            ssdpDeviceType == null &&
            ssdpModel == null &&
            !hasNonMobileMdns &&
            !hasServerPorts &&
            vendor == null
        ) {
            return DeviceType.MOBILE_TABLET
        }

        return DeviceType.UNKNOWN
    }

    private fun matchNameKeywords(text: String, hasServerPorts: Boolean): DeviceType? {
        return when {
            ROUTER_KEYWORDS.any { it in text } -> DeviceType.ROUTER
            PRINTER_KEYWORDS.any { it in text } -> DeviceType.PRINTER
            TV_KEYWORDS.any { it in text } -> DeviceType.TV_MEDIA
            text.contains("xiaomi electronics") || text.contains("xiaomi smart home") -> DeviceType.IOT
            IOT_KEYWORDS.any { it in text } -> DeviceType.IOT
            !hasServerPorts && (
                text.contains("ipad") || text.contains("tablet") || text.contains("galaxy tab") ||
                    text.contains("galaxy-tab") || text.contains("lenovo tab") || text.contains("lenovo-tab") ||
                    text.contains("mi pad") || text.contains("mi-pad") || text.contains("fire hd") ||
                    text.contains("fire-hd")
                ) -> DeviceType.MOBILE_TABLET
            PC_KEYWORDS.any { it in text } -> DeviceType.PC_LAPTOP
            !hasServerPorts && EXPLICIT_MOBILE_NAME_KEYWORDS.any { it in text } -> DeviceType.MOBILE_TABLET
            else -> null
        }
    }

    private fun matchVendorKeywords(vendorLower: String): DeviceType? {
        return when {
            ROUTER_KEYWORDS.any { it in vendorLower } -> DeviceType.ROUTER
            PRINTER_KEYWORDS.any { it in vendorLower } -> DeviceType.PRINTER
            TV_KEYWORDS.any { it in vendorLower } -> DeviceType.TV_MEDIA
            vendorLower.contains("xiaomi electronics") || vendorLower.contains("xiaomi smart home") -> DeviceType.IOT
            IOT_KEYWORDS.any { it in vendorLower } -> DeviceType.IOT
            PC_KEYWORDS.any { it in vendorLower } -> DeviceType.PC_LAPTOP
            MOBILE_VENDOR_KEYWORDS.any { it in vendorLower } -> DeviceType.MOBILE_TABLET
            else -> null
        }
    }
}
