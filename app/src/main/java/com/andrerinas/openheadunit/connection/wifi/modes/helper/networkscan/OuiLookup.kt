package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import android.content.Context

object OuiLookup {

    private const val ASSET_FILE = "oui_vendors.txt"

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var assetOuiMap: Map<String, String>? = null

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    private fun loadAssetOuiMap(): Map<String, String> {
        assetOuiMap?.let { return it }
        val ctx = appContext ?: return emptyMap()
        synchronized(this) {
            assetOuiMap?.let { return it }
            val loaded = try {
                ctx.assets.open(ASSET_FILE).bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.mapNotNull { line ->
                        val sep = line.indexOf('|')
                        if (sep > 0) {
                            line.substring(0, sep).uppercase() to line.substring(sep + 1).trim()
                        } else {
                            null
                        }
                    }.toMap()
                }
            } catch (_: Exception) {
                emptyMap()
            }
            assetOuiMap = loaded
            return loaded
        }
    }

    private val FALLBACK_OUI_VENDORS = mapOf(
        "00:03:93" to "Apple", "00:1C:B3" to "Apple", "00:25:00" to "Apple",
        "28:CF:E9" to "Apple", "3C:15:C2" to "Apple", "40:A6:D9" to "Apple",
        "60:F8:1D" to "Apple", "70:56:81" to "Apple", "88:66:5A" to "Apple",
        "A4:83:E7" to "Apple", "AC:BC:32" to "Apple", "B8:E8:56" to "Apple",
        "D0:03:4B" to "Apple", "F0:18:98" to "Apple", "F4:5C:89" to "Apple",
        "00:12:47" to "Samsung", "00:16:32" to "Samsung", "00:21:19" to "Samsung",
        "18:3A:2D" to "Samsung", "28:39:5E" to "Samsung", "34:23:BA" to "Samsung",
        "50:01:BB" to "Samsung", "64:B3:10" to "Samsung", "78:47:1D" to "Samsung",
        "84:25:DB" to "Samsung", "9C:65:B0" to "Samsung", "BC:14:85" to "Samsung",
        "CC:07:AB" to "Samsung", "E4:7C:F9" to "Samsung", "F4:7B:5E" to "Samsung",
        "00:1A:11" to "Google", "3C:5A:B4" to "Google", "54:60:09" to "Google",
        "94:EB:2C" to "Google", "A4:77:33" to "Google", "F4:F5:D8" to "Google",
        "04:CF:8C" to "Xiaomi", "14:F6:5A" to "Xiaomi", "28:6C:07" to "Xiaomi",
        "34:CE:00" to "Xiaomi", "50:64:2B" to "Xiaomi", "64:09:80" to "Xiaomi",
        "74:23:44" to "Xiaomi", "7C:1D:D9" to "Xiaomi", "98:FA:E3" to "Xiaomi",
        "94:65:2D" to "OnePlus", "AC:37:43" to "OnePlus", "C0:EE:FB" to "OnePlus",
        "14:9B:F3" to "Oppo", "2C:59:8A" to "Oppo", "84:10:0D" to "Oppo",
        "44:66:FC" to "Realme", "98:E7:43" to "Realme", "DC:EF:CA" to "Realme",
        "0C:8E:29" to "Vivo", "24:79:F3" to "Vivo", "9C:F4:8E" to "Vivo",
        "00:0A:28" to "Motorola", "1C:56:FE" to "Motorola", "60:BE:B5" to "Motorola",
        "00:1E:10" to "Huawei", "00:46:4B" to "Huawei", "48:46:FB" to "Huawei",
        "00:27:19" to "TP-Link", "14:CC:20" to "TP-Link", "50:C7:BF" to "TP-Link",
        "00:09:5B" to "Netgear", "20:4E:7F" to "Netgear", "44:94:FC" to "Netgear",
        "00:1E:8C" to "Asus", "04:92:26" to "Asus", "2C:56:DC" to "Asus",
        "04:18:D6" to "Ubiquiti", "24:A4:3C" to "Ubiquiti", "74:83:C2" to "Ubiquiti",
        "00:00:0C" to "Cisco", "00:14:BF" to "Linksys", "00:17:9A" to "D-Link",
        "00:14:22" to "Dell", "34:17:EB" to "Dell", "00:1B:78" to "HP",
        "00:21:CC" to "Lenovo", "28:D2:44" to "Lenovo", "00:1B:21" to "Intel",
        "00:50:F2" to "Microsoft", "00:0D:F0" to "Sony", "00:E0:91" to "LG",
        "B8:3E:59" to "Roku", "B8:27:EB" to "Raspberry Pi", "DC:A6:32" to "Raspberry Pi",
        "24:0A:C4" to "Espressif", "30:AE:A4" to "Espressif", "44:65:0D" to "Amazon"
    )

    fun normalizeMac(mac: String?): String? {
        if (mac.isNullOrBlank()) return null
        val cleaned = mac.trim().uppercase().replace(":", "").replace("-", "")
        if (cleaned.length != 12 || !cleaned.all { it in '0'..'9' || it in 'A'..'F' }) {
            return null
        }
        val formatted = cleaned.chunked(2).joinToString(":")
        if (formatted == "00:00:00:00:00:00" || formatted == "FF:FF:FF:FF:FF:FF" || formatted == "02:00:00:00:00:00") {
            return null
        }
        return formatted
    }

    fun isRandomizedMac(mac: String?): Boolean {
        val normalized = normalizeMac(mac) ?: return false
        val firstOctet = normalized.substring(0, 2).toIntOrNull(16) ?: return false
        return (firstOctet and 0x02) != 0
    }

    fun lookupRawVendor(mac: String?): String? {
        val normalized = normalizeMac(mac) ?: return null
        if (isRandomizedMac(normalized)) return null
        val prefix = normalized.substring(0, 8)
        return loadAssetOuiMap()[prefix] ?: FALLBACK_OUI_VENDORS[prefix]
    }

    fun lookupVendor(mac: String?): String? {
        val rawVendor = lookupRawVendor(mac) ?: return null
        return simplifyVendorName(rawVendor)
    }

    internal fun simplifyVendorName(raw: String): String {
        val lower = raw.lowercase()
        return when {
            "apple" in lower -> "Apple"
            "samsung" in lower -> "Samsung"
            "google" in lower -> "Google"
            "xiaomi electronics" in lower -> "Xiaomi Smart Home"
            "xiaomi" in lower || "redmi" in lower || "poco" in lower -> "Xiaomi"
            "oppo" in lower -> "Oppo"
            "realme" in lower -> "Realme"
            "vivo" in lower -> "Vivo"
            "oneplus" in lower -> "OnePlus"
            "huawei" in lower -> "Huawei"
            "honor" in lower -> "Honor"
            "motorola" in lower -> "Motorola"
            "fairphone" in lower -> "Fairphone"
            "nothing" in lower -> "Nothing"
            "wingtech" in lower -> "Wingtech (Mobile ODM)"
            "huaqin" in lower -> "Huaqin (Mobile ODM)"
            "longcheer" in lower -> "Longcheer (Mobile ODM)"
            "transsion" in lower || "infinix" in lower || "tecno" in lower || "itel" in lower -> "Transsion (Infinix/Tecno)"
            "lg electronics (mobile" in lower -> "LG Mobile"
            "hmd global" in lower || "nokia" in lower -> "Nokia"
            "meizu" in lower -> "Meizu"
            "lcfc" in lower -> "Lenovo (LCFC)"
            "micro-star" in lower -> "MSI"
            "avm " in lower || lower == "avm" || "audiovisuelles" in lower -> "AVM (FRITZ!Box)"
            "compal" in lower -> "Compal"
            "tp-link" in lower || "tplink" in lower -> "TP-Link"
            "netgear" in lower -> "Netgear"
            "ubiquiti" in lower -> "Ubiquiti"
            "mikrotik" in lower || "routerboard" in lower -> "MikroTik"
            "cisco" in lower -> "Cisco"
            "linksys" in lower -> "Linksys"
            "d-link" in lower || "dlink" in lower -> "D-Link"
            "asustek" in lower || "asus" in lower -> "Asus"
            "dell" in lower -> "Dell"
            "hewlett" in lower || lower == "hp" || lower.startsWith("hp ") -> "HP"
            "lenovo" in lower -> "Lenovo"
            "intel" in lower -> "Intel"
            "microsoft" in lower -> "Microsoft"
            "vmware" in lower -> "VMware"
            "azurewave" in lower -> "AzureWave"
            "raspberry" in lower -> "Raspberry Pi"
            "espressif" in lower -> "Espressif"
            "amazon" in lower -> "Amazon"
            "sonos" in lower -> "Sonos"
            "roku" in lower -> "Roku"
            "sony" in lower -> "Sony"
            "lg " in lower || lower.startsWith("lg") -> "LG"
            else -> raw
        }
    }
}
