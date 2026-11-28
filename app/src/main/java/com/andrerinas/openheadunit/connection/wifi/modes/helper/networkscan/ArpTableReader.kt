package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import java.io.File

object ArpTableReader {

    /**
     * Reads ARP/neighbor entries from BOTH /proc/net/arp and `ip neigh show`,
     * merging valid MAC mappings so partial `/proc/net/arp` results on Android 10+
     * don't shadow `ip neigh show`.
     */
    fun readArpTable(): Map<String, String> {
        val merged = LinkedHashMap<String, String>()
        merged.putAll(readProcNetArp())
        merged.putAll(readIpNeigh())
        return merged
    }

    private fun readProcNetArp(): Map<String, String> {
        return try {
            val file = File("/proc/net/arp")
            if (!file.exists() || !file.canRead()) return emptyMap()
            file.bufferedReader().useLines { lines ->
                parseArpLines(lines)
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    private fun readIpNeigh(): Map<String, String> {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("ip", "neigh", "show"))
            val output = process.inputStream.bufferedReader().useLines { lines ->
                parseIpNeighLines(lines)
            }
            process.waitFor()
            output
        } catch (_: Exception) {
            emptyMap()
        } finally {
            process?.destroy()
        }
    }

    internal fun parseArpLines(lines: Sequence<String>): Map<String, String> {
        val result = mutableMapOf<String, String>()
        lines.drop(1).forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 4) {
                val ip = parts[0]
                val flags = parts[2]
                if (flags != "0x0") {
                    val mac = OuiLookup.normalizeMac(parts[3])
                    if (mac != null) {
                        result[ip] = mac
                    }
                }
            }
        }
        return result
    }

    internal fun parseIpNeighLines(lines: Sequence<String>): Map<String, String> {
        val result = mutableMapOf<String, String>()
        lines.forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 4) {
                val ip = parts[0]
                val isFailed = parts.any { it == "FAILED" || it == "INCOMPLETE" }
                val lladdrIdx = parts.indexOf("lladdr")
                if (!isFailed && lladdrIdx != -1 && lladdrIdx + 1 < parts.size) {
                    val mac = OuiLookup.normalizeMac(parts[lladdrIdx + 1])
                    if (mac != null) {
                        result[ip] = mac
                    }
                }
            }
        }
        return result
    }
}
