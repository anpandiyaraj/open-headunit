package com.andrerinas.openheadunit.connection.wifi.modes.helper.networkscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CommonWifiDeviceScannerTest {

    @Test
    fun `classifies Android phones via vendor, hostname, randomized MAC, or passive TTL`() {
        assertEquals(
            DeviceType.MOBILE_TABLET,
            DeviceClassifier.classify(
                isGateway = false,
                deviceName = "Pixel-8-Pro",
                vendor = "Google",
                ttl = 64
            )
        )

        assertEquals(
            DeviceType.MOBILE_TABLET,
            DeviceClassifier.classify(
                isGateway = false,
                macAddress = "AE:12:34:56:78:9A",
                isRandomizedMac = true,
                ttl = 64
            )
        )

        assertEquals(
            DeviceType.MOBILE_TABLET,
            DeviceClassifier.classify(
                isGateway = false,
                macAddress = null,
                vendor = null,
                ttl = 64
            )
        )

        assertEquals(
            DeviceType.ROUTER,
            DeviceClassifier.classify(
                isGateway = true,
                deviceName = "TP-Link Router",
                vendor = "TP-Link"
            )
        )

        // Routers from brands that also make phones (Huawei/Xiaomi/Nokia/ZTE/Google) exposing port 53/80/443 must NEVER be classified as mobile!
        assertEquals(
            DeviceType.ROUTER,
            DeviceClassifier.classify(
                isGateway = false,
                deviceName = null,
                vendor = "Huawei",
                openPorts = listOf(53, 80, 443),
                ttl = 64
            )
        )

        assertEquals(
            DeviceType.ROUTER,
            DeviceClassifier.classify(
                isGateway = false,
                deviceName = "Xiaomi-AX3000-Router",
                vendor = "Xiaomi",
                openPorts = emptyList(),
                ttl = 64
            )
        )

        // Before ports are probed (preview phase), a generic Linux TTL=64 host must not prematurely become MOBILE_TABLET.
        assertEquals(
            DeviceType.UNKNOWN,
            DeviceClassifier.classify(
                isGateway = false,
                vendor = null,
                ttl = 64,
                portsProbed = false
            )
        )

        assertEquals(
            DeviceType.PC_LAPTOP,
            DeviceClassifier.classify(
                isGateway = false,
                deviceName = "WORKSTATION",
                hasNetBios = true,
                ttl = 128
            )
        )
    }

    @Test
    fun `mobileCandidates excludes local device and non-mobile peers and prioritizes last used and Android phones`() {
        val localHeadunit = NetworkDevice(
            ipAddress = "192.168.1.10",
            deviceName = "HeadUnit",
            deviceType = DeviceType.MOBILE_TABLET,
            isLocalDevice = true
        )
        val router = NetworkDevice(
            ipAddress = "192.168.1.1",
            deviceName = "Router",
            deviceType = DeviceType.ROUTER,
            isGateway = true
        )
        val iphone = NetworkDevice(
            ipAddress = "192.168.1.20",
            deviceName = "iPhone",
            vendor = "Apple",
            deviceType = DeviceType.MOBILE_TABLET
        )
        val galaxy = NetworkDevice(
            ipAddress = "192.168.1.35",
            deviceName = "Galaxy S24",
            vendor = "Samsung",
            deviceType = DeviceType.MOBILE_TABLET
        )
        val pixelLastUsed = NetworkDevice(
            ipAddress = "192.168.1.50",
            deviceName = "Pixel 9",
            vendor = "Google",
            deviceType = DeviceType.MOBILE_TABLET
        )

        val secondarySelfAlias = NetworkDevice(
            ipAddress = "192.168.1.11",
            deviceName = "HeadUnit Secondary IP",
            deviceType = DeviceType.MOBILE_TABLET,
            isLocalDevice = false
        )
        val secondaryGateway = NetworkDevice(
            ipAddress = "192.168.1.254",
            deviceName = "Mesh Gateway",
            deviceType = DeviceType.MOBILE_TABLET,
            isGateway = false
        )

        val all = listOf(localHeadunit, secondarySelfAlias, router, secondaryGateway, iphone, galaxy, pixelLastUsed)
        val mobile = CommonWifiDevicePolicy.mobileCandidates(
            all,
            lastUsedIp = "192.168.1.50",
            localIps = setOf("192.168.1.10", "192.168.1.11"),
            gatewayIps = setOf("192.168.1.1", "192.168.1.254")
        )

        assertEquals(listOf("192.168.1.50", "192.168.1.35", "192.168.1.20"), mobile.map { it.ipAddress })
        assertFalse(mobile.any { it.isLocalDevice })
        assertFalse(mobile.any { it.isGateway })
        assertFalse(mobile.any { it.ipAddress == "192.168.1.11" })
        assertFalse(mobile.any { it.ipAddress == "192.168.1.254" })
    }

    @Test
    fun `parses arp and ip neigh lines and normalizes MACs`() {
        val arp = ArpTableReader.parseArpLines(
            sequenceOf(
                "IP address       HW type     Flags       HW address            Mask     Device",
                "192.168.1.42     0x1         0x2         94:eb:2c:11:22:33     *        wlan0",
                "192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0"
            )
        )
        assertEquals("94:EB:2C:11:22:33", arp["192.168.1.42"])
        assertFalse(arp.containsKey("192.168.1.99"))

        val neigh = ArpTableReader.parseIpNeighLines(
            sequenceOf(
                "192.168.1.55 dev wlan0 lladdr 18:3a:2d:aa:bb:cc REACHABLE",
                "192.168.1.56 dev wlan0 INCOMPLETE"
            )
        )
        assertEquals("18:3A:2D:AA:BB:CC", neigh["192.168.1.55"])
        assertFalse(neigh.containsKey("192.168.1.56"))
        assertTrue(OuiLookup.isRandomizedMac("AE:11:22:33:44:55"))
        assertFalse(OuiLookup.isRandomizedMac("94:EB:2C:11:22:33"))
    }

    @Test
    fun `subnet host generation caps at slash 24 and compares IPs numerically`() {
        val hosts = SubnetUtils.getHostAddresses("192.168.1.15", 24)
        assertEquals(254, hosts.size)
        assertEquals("192.168.1.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
        assertTrue(SubnetUtils.compareIps("192.168.1.9", "192.168.1.10") < 0)
    }
}
