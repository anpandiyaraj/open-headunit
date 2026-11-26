package com.andrerinas.openheadunit.connection.bluetooth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BtHidKeypadPolicyTest {

    @Test
    fun `dummy keypad report descriptor and idle report have valid structure`() {
        val desc = BtHidKeypadPolicy.DUMMY_KEYPAD_DESCRIPTOR
        assertEquals(45, desc.size)
        // Usage Page (Generic Desktop = 0x05, 0x01) & Usage (Keyboard = 0x09, 0x06)
        assertEquals(0x05.toByte(), desc[0])
        assertEquals(0x01.toByte(), desc[1])
        assertEquals(0x09.toByte(), desc[2])
        assertEquals(0x06.toByte(), desc[3])
        // End Collection = 0xC0
        assertEquals(0xC0.toByte(), desc.last())
        // Idle report is 8 zero bytes (no modifiers, no keys pressed)
        assertEquals(8, BtHidKeypadPolicy.IDLE_KEYPAD_REPORT.size)
        assertTrue(BtHidKeypadPolicy.IDLE_KEYPAD_REPORT.all { it == 0.toByte() })
    }

    @Test
    fun `shouldWatcherRun stops when AA connected or preferred BT connected and starts only when both disconnected`() {
        // Both disconnected -> watcher runs
        assertTrue(BtHidKeypadPolicy.shouldWatcherRun(aaConnected = false, anyPreferredBtConnected = false))

        // Preferred BT connected -> watcher stops
        assertFalse(BtHidKeypadPolicy.shouldWatcherRun(aaConnected = false, anyPreferredBtConnected = true))

        // AA connected -> watcher stops
        assertFalse(BtHidKeypadPolicy.shouldWatcherRun(aaConnected = true, anyPreferredBtConnected = false))

        // Both connected -> watcher stops
        assertFalse(BtHidKeypadPolicy.shouldWatcherRun(aaConnected = true, anyPreferredBtConnected = true))
    }

    @Test
    fun `shouldAttemptHidConnect skips when AA session is up or device already connected`() {
        assertFalse(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = true,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = false,
                aclAlreadyConnected = false,
                lastAttemptElapsedMs = 0L,
                nowElapsedMs = 50_000L,
            )
        )
        assertFalse(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = false,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = true,
                aclAlreadyConnected = false,
                lastAttemptElapsedMs = 0L,
                nowElapsedMs = 50_000L,
            )
        )
        assertFalse(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = false,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = false,
                aclAlreadyConnected = true,
                lastAttemptElapsedMs = 0L,
                nowElapsedMs = 50_000L,
            )
        )
    }

    @Test
    fun `shouldAttemptHidConnect respects cooldown and allows connect when phone is offline`() {
        assertTrue(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = false,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = false,
                aclAlreadyConnected = false,
                lastAttemptElapsedMs = 0L,
                nowElapsedMs = 10_000L,
            )
        )
        assertFalse(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = false,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = false,
                aclAlreadyConnected = false,
                lastAttemptElapsedMs = 10_000L,
                nowElapsedMs = 25_000L,
            )
        )
        assertTrue(
            BtHidKeypadPolicy.shouldAttemptHidConnect(
                aaSessionUp = false,
                hidAppRegistered = true,
                hidStateConnectedOrConnecting = false,
                aclAlreadyConnected = false,
                lastAttemptElapsedMs = 10_000L,
                nowElapsedMs = 31_000L,
            )
        )
    }

    @Test
    fun `selectTargetAddresses prefers explicit MACs and falls back to bonded phone candidates`() {
        val explicit = BtHidKeypadPolicy.selectTargetAddresses(
            configuredAutoStartMacs = setOf("aa:bb:cc:dd:ee:01"),
            configuredNativeMacs = emptyList(),
            provenNativeMacs = listOf("aa:bb:cc:dd:ee:02"),
            candidatePhoneMacs = listOf("aa:bb:cc:dd:ee:03"),
        )
        assertEquals(setOf("AA:BB:CC:DD:EE:01"), explicit)

        val fallback = BtHidKeypadPolicy.selectTargetAddresses(
            configuredAutoStartMacs = emptySet(),
            configuredNativeMacs = emptyList(),
            provenNativeMacs = listOf("aa:bb:cc:dd:ee:02"),
            candidatePhoneMacs = listOf("aa:bb:cc:dd:ee:03"),
        )
        assertEquals(setOf("AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"), fallback)
    }

    @Test
    fun `shouldLiftAaCancelOnBtArrival lifts immediately when phone was absent at cancel`() {
        assertTrue(
            BtHidKeypadPolicy.shouldLiftAaCancelOnBtArrival(
                cancelledByUser = true,
                aaSessionUp = false,
                phoneWasDisconnectedSinceCancel = true,
                elapsedSinceCancelMs = 2_000L,
                graceMs = 15_000L,
            )
        )
        assertFalse(
            BtHidKeypadPolicy.shouldLiftAaCancelOnBtArrival(
                cancelledByUser = true,
                aaSessionUp = true,
                phoneWasDisconnectedSinceCancel = true,
                elapsedSinceCancelMs = 30_000L,
                graceMs = 15_000L,
            )
        )
    }
}
