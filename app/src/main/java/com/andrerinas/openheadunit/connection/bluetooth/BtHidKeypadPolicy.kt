package com.andrerinas.openheadunit.connection.bluetooth

/**
 * Pure decision policy for the persistent Bluetooth HID dummy keypad connection & background watcher.
 *
 * Lifecycle rules:
 * 1. The head unit registers a single `BluetoothHidDevice` application (a dummy 8-byte boot keyboard
 *    report descriptor) and keeps that HID profile connected without ever switching or tearing down
 *    Bluetooth profiles afterward.
 * 2. **Watcher Pause / Stop Rule**: The background watcher loop stops/idles immediately as soon as
 *    Android Auto is connected (`aaConnected`) OR any preferred/target Bluetooth phone is connected
 *    (`anyPreferredBtConnected`). Zero periodic ticks run while in that satisfied state.
 * 3. **Watcher Auto-Start / Resume Rule**: Once BOTH Android Auto is disconnected (`!aaConnected`)
 *    AND all preferred/target Bluetooth phones are disconnected (`!anyPreferredBtConnected`), the
 *    background watcher automatically starts scanning/connecting again.
 */
object BtHidKeypadPolicy {

    /**
     * Standard USB HID 8-byte Keyboard/Keypad Report Descriptor (61 bytes):
     * - Byte 0: Modifier keys (Left Ctrl..Right GUI)
     * - Byte 1: Reserved (constant)
     * - Bytes 2..7: Up to 6 simultaneous keycodes (Usage Page 0x07)
     *
     * Sending an all-zero 8-byte report (`00 00 00 00 00 00 00 00`) is a silent no-op key-release
     * frame that finalizes the HID link without typing anything on the phone.
     */
    val DUMMY_KEYPAD_DESCRIPTOR: ByteArray = byteArrayOf(
        0x05.toByte(), 0x01.toByte(), // Usage Page (Generic Desktop)
        0x09.toByte(), 0x06.toByte(), // Usage (Keyboard)
        0xA1.toByte(), 0x01.toByte(), // Collection (Application)
        0x05.toByte(), 0x07.toByte(), //   Usage Page (Key Codes / Keypad)
        0x19.toByte(), 0xE0.toByte(), //   Usage Minimum (224 - Left Control)
        0x29.toByte(), 0xE7.toByte(), //   Usage Maximum (231 - Right GUI)
        0x15.toByte(), 0x00.toByte(), //   Logical Minimum (0)
        0x25.toByte(), 0x01.toByte(), //   Logical Maximum (1)
        0x75.toByte(), 0x01.toByte(), //   Report Size (1)
        0x95.toByte(), 0x08.toByte(), //   Report Count (8)
        0x81.toByte(), 0x02.toByte(), //   Input (Data, Variable, Absolute) - Modifier byte
        0x95.toByte(), 0x01.toByte(), //   Report Count (1)
        0x75.toByte(), 0x08.toByte(), //   Report Size (8)
        0x81.toByte(), 0x01.toByte(), //   Input (Constant) - Reserved byte
        0x95.toByte(), 0x06.toByte(), //   Report Count (6)
        0x75.toByte(), 0x08.toByte(), //   Report Size (8)
        0x15.toByte(), 0x00.toByte(), //   Logical Minimum (0)
        0x25.toByte(), 0x65.toByte(), //   Logical Maximum (101)
        0x05.toByte(), 0x07.toByte(), //   Usage Page (Key Codes / Keypad)
        0x19.toByte(), 0x00.toByte(), //   Usage Minimum (0)
        0x29.toByte(), 0x65.toByte(), //   Usage Maximum (101)
        0x81.toByte(), 0x00.toByte(), //   Input (Data, Array) - Key array (6 bytes)
        0xC0.toByte()                 // End Collection
    )

    val IDLE_KEYPAD_REPORT: ByteArray = ByteArray(8)

    /** Poll interval for the dedicated background watcher thread while scanning for disconnected phones. */
    const val WATCH_INTERVAL_MS = 10_000L

    /** Minimum cooldown between `BluetoothHidDevice.connect(device)` calls to the same MAC. */
    const val PER_DEVICE_CONNECT_COOLDOWN_MS = 20_000L

    /** Backoff before retrying `registerApp` when the Bluetooth stack rejects or drops registration. */
    const val REGISTER_RETRY_MS = 8_000L

    /**
     * Whether the Bluetooth watcher loop should keep running periodic scan ticks.
     *
     * Returns `false` (watcher stops/pauses) whenever Android Auto is connected OR any preferred
     * Bluetooth target phone is already connected.
     * Returns `true` (watcher runs) ONLY when BOTH Android Auto is disconnected AND all preferred
     * Bluetooth target phones are disconnected.
     */
    fun shouldWatcherRun(
        aaConnected: Boolean,
        anyPreferredBtConnected: Boolean,
    ): Boolean = !aaConnected && !anyPreferredBtConnected

    /**
     * Decides whether the background watcher should call `BluetoothHidDevice.connect(device)` on
     * this pass.
     */
    fun shouldAttemptHidConnect(
        aaSessionUp: Boolean,
        hidAppRegistered: Boolean,
        hidStateConnectedOrConnecting: Boolean,
        aclAlreadyConnected: Boolean,
        lastAttemptElapsedMs: Long,
        nowElapsedMs: Long,
    ): Boolean {
        if (aaSessionUp) return false
        if (!hidAppRegistered) return false
        if (hidStateConnectedOrConnecting) return false
        if (aclAlreadyConnected) return false
        if (lastAttemptElapsedMs > 0L && nowElapsedMs - lastAttemptElapsedMs < PER_DEVICE_CONNECT_COOLDOWN_MS) {
            return false
        }
        return true
    }

    /**
     * Filters bonded addresses down to the preferred/target phones the watcher monitors.
     *
     * Priority:
     * 1. Explicit user-selected Bluetooth auto-start or Native AA phone lists, if non-empty.
     * 2. Otherwise all bonded candidate phones (`candidatePhoneMacs`), so out-of-the-box pairings
     *    work without manual MAC entry.
     */
    fun selectTargetAddresses(
        configuredAutoStartMacs: Set<String>,
        configuredNativeMacs: Collection<String>,
        provenNativeMacs: Collection<String>,
        candidatePhoneMacs: Collection<String>,
    ): Set<String> {
        val explicit = LinkedHashSet<String>()
        configuredAutoStartMacs.mapTo(explicit) { it.trim().uppercase() }
        configuredNativeMacs.mapTo(explicit) { it.trim().uppercase() }
        explicit.remove("")
        if (explicit.isNotEmpty()) return explicit

        val fallback = LinkedHashSet<String>()
        provenNativeMacs.mapTo(fallback) { it.trim().uppercase() }
        candidatePhoneMacs.mapTo(fallback) { it.trim().uppercase() }
        fallback.remove("")
        return fallback
    }

    /**
     * Whether a user cancel of Android Auto reconnection should be lifted because a target phone
     * became connected on Bluetooth.
     */
    fun shouldLiftAaCancelOnBtArrival(
        cancelledByUser: Boolean,
        aaSessionUp: Boolean,
        phoneWasDisconnectedSinceCancel: Boolean,
        elapsedSinceCancelMs: Long,
        graceMs: Long,
    ): Boolean {
        if (!cancelledByUser || aaSessionUp) return false
        return phoneWasDisconnectedSinceCancel || elapsedSinceCancelMs > graceMs
    }
}
