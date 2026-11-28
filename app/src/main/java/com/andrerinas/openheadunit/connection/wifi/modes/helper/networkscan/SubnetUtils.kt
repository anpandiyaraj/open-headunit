package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import java.net.Inet4Address
import java.net.InetAddress

object SubnetUtils {

    fun ipToInt(ip: String): Int? {
        return try {
            val addr = InetAddress.getByName(ip) as? Inet4Address ?: return null
            val bytes = addr.address
            ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)
        } catch (_: Exception) {
            null
        }
    }

    fun intToIp(ipInt: Int): String {
        return "${(ipInt ushr 24) and 0xFF}.${(ipInt ushr 16) and 0xFF}." +
            "${(ipInt ushr 8) and 0xFF}.${ipInt and 0xFF}"
    }

    /**
     * Generates host IPv4 addresses to scan for the given local IP and prefix length.
     * Caps scan range to a /24 (254 hosts) around the local IP so large subnets complete quickly.
     */
    fun getHostAddresses(localIp: String, prefixLength: Int): List<String> {
        val ipInt = ipToInt(localIp) ?: return emptyList()
        val effectivePrefix = prefixLength.coerceIn(24, 30)
        val mask = (-1 shl (32 - effectivePrefix))
        val network = ipInt and mask
        val broadcast = network or mask.inv()

        val hosts = mutableListOf<String>()
        for (addr in (network + 1) until broadcast) {
            hosts.add(intToIp(addr))
        }
        return hosts
    }

    fun compareIps(a: String, b: String): Int {
        val aInt = ipToInt(a) ?: return a.compareTo(b)
        val bInt = ipToInt(b) ?: return a.compareTo(b)
        return (aInt xor Int.MIN_VALUE).compareTo(bInt xor Int.MIN_VALUE)
    }
}
