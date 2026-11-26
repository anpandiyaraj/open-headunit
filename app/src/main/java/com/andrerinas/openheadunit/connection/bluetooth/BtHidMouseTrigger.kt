package com.andrerinas.openheadunit.connection.bluetooth

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothHidDeviceAppQosSettings
import android.bluetooth.BluetoothHidDeviceAppSdpSettings
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.andrerinas.openheadunit.utils.AppLog
import com.andrerinas.openheadunit.utils.BluetoothHelper
import com.andrerinas.openheadunit.utils.Settings
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor

/**
 * Persistent Bluetooth HID Dummy Keypad connection & event-driven background watcher (API 28+).
 *
 * Lifecycle:
 * - Runs on a dedicated background `HandlerThread` (`BtHidKeypadWatcher`) even when the app is in
 *   the background and completely independent of the "Connect over WiFi" button.
 * - Registers once as a Bluetooth HID Dummy Keypad (`SUBCLASS1_KEYBOARD`) and keeps that HID
 *   profile connected — never switching or tearing down profiles once linked.
 * - **Stops watching automatically** when Android Auto is connected OR any preferred/selected
 *   Bluetooth phone is connected (cancels all periodic polling ticks).
 * - **Starts watching automatically** as soon as BOTH Android Auto is disconnected AND all
 *   preferred/selected Bluetooth phones are disconnected.
 */
class BtHidMouseTrigger(
    private val context: Context,
    private val settings: Settings,
    private val isAaSessionUp: () -> Boolean,
    private val onTargetPhoneConnected: (address: String, name: String?, reason: String) -> Unit,
) {

    @Volatile private var started = false
    @Volatile private var watcherActivelyScanning = false
    private var workerThread: HandlerThread? = null
    private var workerHandler: Handler? = null
    private var workerExecutor: Executor? = null

    @Volatile private var hidProxy: BluetoothHidDevice? = null
    @Volatile private var hidAppRegistered = false
    @Volatile private var registerInFlight = false
    @Volatile private var lastRegisterAttemptMs = 0L

    private val lastConnectAttemptMs = ConcurrentHashMap<String, Long>()
    private val connectedHidAddresses = ConcurrentHashMap.newKeySet<String>()
    private val notifiedConnectedAddresses = ConcurrentHashMap.newKeySet<String>()

    /** Tracks whether we observed zero target phones connected since the last cancel/disconnect. */
    @Volatile var sawTargetAbsent = true
        private set

    private val bluetoothReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.action) {
                BluetoothAdapter.ACTION_STATE_CHANGED -> {
                    val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                    if (state == BluetoothAdapter.STATE_ON) {
                        AppLog.i("BtHidKeypad: Bluetooth adapter turned ON; evaluating watcher state")
                        postImmediateEvaluate("adapter_on")
                    } else if (state == BluetoothAdapter.STATE_OFF || state == BluetoothAdapter.STATE_TURNING_OFF) {
                        hidAppRegistered = false
                        registerInFlight = false
                        connectedHidAddresses.clear()
                        notifiedConnectedAddresses.clear()
                        pauseWatcherLoop("Bluetooth adapter turned off")
                    }
                }
                BluetoothDevice.ACTION_BOND_STATE_CHANGED -> {
                    val bondState = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)
                    if (bondState == BluetoothDevice.BOND_BONDED) {
                        postImmediateEvaluate("bond_completed")
                    }
                }
                BluetoothDevice.ACTION_ACL_CONNECTED -> {
                    val dev = extractDevice(intent) ?: return
                    val mac = dev.address.uppercase()
                    if (isPreferredTargetAddress(mac)) {
                        val devName = try { dev.name } catch (_: Exception) { null }
                        if (!isAaSessionUp() && notifiedConnectedAddresses.add(mac)) {
                            onTargetPhoneConnected(dev.address, devName, "Preferred Bluetooth ACL connected")
                        }
                        postImmediateEvaluate("acl_connected:$mac")
                    }
                }
                BluetoothDevice.ACTION_ACL_DISCONNECTED -> {
                    val dev = extractDevice(intent) ?: return
                    val mac = dev.address.uppercase()
                    connectedHidAddresses.remove(mac)
                    notifiedConnectedAddresses.remove(mac)
                    lastConnectAttemptMs.remove(mac)
                    if (isPreferredTargetAddress(mac)) {
                        AppLog.i("BtHidKeypad: Preferred device $mac ACL disconnected; checking if watcher should auto-start")
                        postDelayedEvaluate(1_500L)
                    }
                }
            }
        }
    }

    fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            AppLog.i("BtHidKeypad: BluetoothHidDevice requires API 28+ (current=${Build.VERSION.SDK_INT}); skipping")
            return
        }
        synchronized(this) {
            if (started) return
            started = true
            val thread = HandlerThread("BtHidKeypadWatcher").apply { start() }
            val handler = Handler(thread.looper)
            workerThread = thread
            workerHandler = handler
            workerExecutor = Executor { cmd ->
                if (started) handler.post(cmd)
            }
            try {
                val filter = IntentFilter().apply {
                    addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
                    addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
                    addAction(BluetoothDevice.ACTION_ACL_CONNECTED)
                    addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED)
                }
                ContextCompat.registerReceiver(
                    context,
                    bluetoothReceiver,
                    filter,
                    ContextCompat.RECEIVER_EXPORTED
                )
            } catch (e: Exception) {
                AppLog.w("BtHidKeypad: Failed to register Bluetooth state receiver: ${e.message}")
            }
            handler.post { evaluateAndStep("start") }
            AppLog.i("BtHidKeypad: Initialized background Bluetooth HID dummy keypad manager")
        }
    }

    /**
     * Only called on full `ACTION_STOP_SERVICE` exit; keeps the HID keypad registered and connected
     * across normal AA sessions and backgrounding.
     */
    @SuppressLint("MissingPermission")
    fun stop() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        synchronized(this) {
            if (!started) return
            started = false
            watcherActivelyScanning = false
            try {
                context.unregisterReceiver(bluetoothReceiver)
            } catch (_: Exception) {}

            val proxy = hidProxy
            hidProxy = null
            hidAppRegistered = false
            registerInFlight = false
            connectedHidAddresses.clear()
            notifiedConnectedAddresses.clear()

            if (proxy != null) {
                if (hasBluetoothConnectPermission()) {
                    try {
                        proxy.unregisterApp()
                    } catch (_: Exception) {}
                }
                try {
                    getAdapter()?.closeProfileProxy(BluetoothProfile.HID_DEVICE, proxy)
                } catch (_: Exception) {}
            }

            workerHandler?.removeCallbacksAndMessages(null)
            workerThread?.quitSafely()
            workerHandler = null
            workerThread = null
            workerExecutor = null
            AppLog.i("BtHidKeypad: Stopped dummy keypad manager")
        }
    }

    /**
     * Called by `AapService` whenever Android Auto connects or disconnects so the watcher
     * immediately stops on AA connect and automatically restarts once both AA and preferred
     * Bluetooth devices are disconnected.
     */
    fun onAaConnectionChanged(aaConnected: Boolean) {
        if (!started) return
        if (aaConnected) {
            workerHandler?.post {
                pauseWatcherLoop("Android Auto connected")
            }
        } else {
            // AA disconnected: clear notification latch so if a phone reconnects later (or is
            // re-evaluated after disconnect), watcher checks whether preferred BT is also gone.
            postDelayedEvaluate(1_500L)
        }
    }

    fun noteUserCancelledAa() {
        val h = workerHandler ?: return
        if (!started) return
        h.post {
            val anyBt = anyTargetCurrentlyConnected()
            sawTargetAbsent = !anyBt
            evaluateAndStep("aa_cancelled")
        }
    }

    fun nudge(reason: String) {
        postImmediateEvaluate(reason)
    }

    private fun pauseWatcherLoop(reason: String) {
        workerHandler?.removeCallbacks(periodicTickRunnable)
        if (watcherActivelyScanning) {
            watcherActivelyScanning = false
            AppLog.i("BtHidKeypad: Watcher STOPPED ($reason)")
        }
    }

    private fun postImmediateEvaluate(reason: String) {
        val h = workerHandler ?: return
        if (!started) return
        h.removeCallbacks(periodicTickRunnable)
        h.post { evaluateAndStep(reason) }
    }

    private fun postDelayedEvaluate(delayMs: Long) {
        val h = workerHandler ?: return
        if (!started) return
        h.removeCallbacks(periodicTickRunnable)
        h.postDelayed(periodicTickRunnable, delayMs)
    }

    private val periodicTickRunnable = Runnable {
        evaluateAndStep("periodic_watch")
    }

    private fun hasBluetoothConnectPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return ContextCompat.checkSelfPermission(
            context,
            android.Manifest.permission.BLUETOOTH_CONNECT
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun getAdapter(): BluetoothAdapter? {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return bm?.adapter ?: BluetoothHelper.getBluetoothAdapter(context)
    }

    @SuppressLint("MissingPermission")
    private fun resolveTargetAddresses(): Set<String> {
        val autoStartMacs = Settings.getAutoStartBtMacs(context)
        val candidates = if (hasBluetoothConnectPermission()) {
            BluetoothHelper.driverCandidates(
                context,
                settings.nativePhonesList,
                settings.nativeProvenPhones
            ).offered.map { it.address }
        } else {
            emptyList()
        }
        return BtHidKeypadPolicy.selectTargetAddresses(
            configuredAutoStartMacs = autoStartMacs,
            configuredNativeMacs = settings.nativePhonesList,
            provenNativeMacs = settings.nativeProvenPhones,
            candidatePhoneMacs = candidates,
        )
    }

    private fun isPreferredTargetAddress(macUppercase: String): Boolean =
        resolveTargetAddresses().contains(macUppercase)

    @SuppressLint("MissingPermission")
    private fun resolveTargetDevices(): List<BluetoothDevice> {
        if (!hasBluetoothConnectPermission()) return emptyList()
        val targetAddresses = resolveTargetAddresses()
        if (targetAddresses.isEmpty()) return emptyList()
        return BluetoothHelper.pairedDevicesOrEmpty(context).filter { device ->
            targetAddresses.contains(device.address.uppercase())
        }
    }

    @SuppressLint("MissingPermission")
    private fun anyTargetCurrentlyConnected(): Boolean {
        if (!hasBluetoothConnectPermission()) return false
        val proxy = hidProxy
        for (device in resolveTargetDevices()) {
            val mac = device.address.uppercase()
            if (connectedHidAddresses.contains(mac)) return true
            val hidUp = if (proxy != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    proxy.getConnectionState(device) == BluetoothProfile.STATE_CONNECTED
                } catch (_: Exception) {
                    false
                }
            } else {
                false
            }
            if (hidUp || BluetoothHelper.isDeviceConnected(device)) return true
        }
        return false
    }

    @RequiresApi(Build.VERSION_CODES.P)
    @SuppressLint("MissingPermission")
    private fun evaluateAndStep(reason: String) {
        if (!started) return
        if (!hasBluetoothConnectPermission()) {
            pauseWatcherLoop("missing BLUETOOTH_CONNECT permission")
            return
        }
        val adapter = getAdapter()
        if (adapter == null || !adapter.isEnabled) {
            pauseWatcherLoop("Bluetooth adapter disabled")
            return
        }

        // Always keep the dummy keypad HID app registered so incoming or existing links stay alive
        // without changing profiles.
        if (!ensureHidAppRegistered(adapter)) {
            postDelayedEvaluate(BtHidKeypadPolicy.REGISTER_RETRY_MS)
            return
        }

        val aaUp = isAaSessionUp()
        val proxy = hidProxy ?: return
        val targets = resolveTargetDevices()
        if (targets.isEmpty()) {
            pauseWatcherLoop("no paired target phones")
            return
        }

        // Inspect live connection state of preferred/target phones first.
        var anyPreferredConnected = false
        for (device in targets) {
            val mac = device.address.uppercase()
            val hidState = try {
                proxy.getConnectionState(device)
            } catch (_: Exception) {
                BluetoothProfile.STATE_DISCONNECTED
            }
            val hidConnected = hidState == BluetoothProfile.STATE_CONNECTED
            val aclConnected = BluetoothHelper.isDeviceConnected(device)

            if (hidConnected) {
                connectedHidAddresses.add(mac)
            } else if (hidState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedHidAddresses.remove(mac)
            }

            if (hidConnected || aclConnected) {
                anyPreferredConnected = true
                if (!aaUp && notifiedConnectedAddresses.add(mac)) {
                    val devName = try { device.name } catch (_: Exception) { null }
                    AppLog.i("BtHidKeypad: Preferred phone ${devName ?: mac} is connected — triggering AA auto-connect")
                    onTargetPhoneConnected(device.address, devName, "Preferred Bluetooth phone connected")
                }
            } else {
                notifiedConnectedAddresses.remove(mac)
            }
        }

        if (!anyPreferredConnected) {
            sawTargetAbsent = true
        }

        // Core rule: stop watcher if AA is connected OR preferred Bluetooth phone is connected.
        if (!BtHidKeypadPolicy.shouldWatcherRun(
                aaConnected = aaUp,
                anyPreferredBtConnected = anyPreferredConnected,
            )
        ) {
            val stopWhy = when {
                aaUp -> "Android Auto connected"
                else -> "preferred Bluetooth device connected"
            }
            pauseWatcherLoop(stopWhy)
            return
        }

        // Both AA and all preferred Bluetooth devices are disconnected -> watcher runs!
        if (!watcherActivelyScanning) {
            watcherActivelyScanning = true
            AppLog.i("BtHidKeypad: Watcher STARTED (AA disconnected & preferred Bluetooth disconnected, trigger=$reason)")
        }

        val now = SystemClock.elapsedRealtime()
        for (device in targets) {
            val mac = device.address.uppercase()
            val hidState = try {
                proxy.getConnectionState(device)
            } catch (_: Exception) {
                BluetoothProfile.STATE_DISCONNECTED
            }
            val hidBusyOrUp = hidState == BluetoothProfile.STATE_CONNECTED ||
                hidState == BluetoothProfile.STATE_CONNECTING
            val aclUp = BluetoothHelper.isDeviceConnected(device)
            val lastTry = lastConnectAttemptMs[mac] ?: 0L

            if (BtHidKeypadPolicy.shouldAttemptHidConnect(
                    aaSessionUp = aaUp,
                    hidAppRegistered = hidAppRegistered,
                    hidStateConnectedOrConnecting = hidBusyOrUp,
                    aclAlreadyConnected = aclUp,
                    lastAttemptElapsedMs = lastTry,
                    nowElapsedMs = now,
                )
            ) {
                lastConnectAttemptMs[mac] = now
                val ok = try {
                    proxy.connect(device)
                } catch (e: Exception) {
                    AppLog.w("BtHidKeypad: connect($mac) threw: ${e.message}")
                    false
                }
                val devName = try { device.name } catch (_: Exception) { null }
                AppLog.i("BtHidKeypad: Watcher connecting HID dummy keypad to ${devName ?: mac} ($reason, accepted=$ok)")
            }
        }

        if (started && watcherActivelyScanning) {
            postDelayedEvaluate(BtHidKeypadPolicy.WATCH_INTERVAL_MS)
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    @SuppressLint("MissingPermission")
    private fun ensureHidAppRegistered(adapter: BluetoothAdapter): Boolean {
        val proxy = hidProxy
        if (proxy == null) {
            try {
                adapter.getProfileProxy(context, profileListener, BluetoothProfile.HID_DEVICE)
            } catch (e: Exception) {
                AppLog.w("BtHidKeypad: getProfileProxy(HID_DEVICE) failed: ${e.message}")
            }
            return false
        }
        if (hidAppRegistered) return true

        val now = SystemClock.elapsedRealtime()
        if (registerInFlight && now - lastRegisterAttemptMs < BtHidKeypadPolicy.REGISTER_RETRY_MS) {
            return false
        }
        if (lastRegisterAttemptMs > 0L && now - lastRegisterAttemptMs < BtHidKeypadPolicy.REGISTER_RETRY_MS) {
            return false
        }

        val executor = workerExecutor ?: return false
        lastRegisterAttemptMs = now
        registerInFlight = true

        val sdp = BluetoothHidDeviceAppSdpSettings(
            "OpenHeadunit Keypad",
            "Android Auto Companion Keypad",
            "OpenHeadunit",
            BluetoothHidDevice.SUBCLASS1_KEYBOARD,
            BtHidKeypadPolicy.DUMMY_KEYPAD_DESCRIPTOR
        )
        val qos = BluetoothHidDeviceAppQosSettings(
            BluetoothHidDeviceAppQosSettings.SERVICE_BEST_EFFORT,
            800,
            9,
            0,
            11250,
            BluetoothHidDeviceAppQosSettings.MAX
        )
        val called = try {
            proxy.registerApp(sdp, null, qos, executor, hidCallback)
        } catch (e: Exception) {
            registerInFlight = false
            AppLog.w("BtHidKeypad: registerApp threw: ${e.message}")
            false
        }
        if (!called) {
            registerInFlight = false
            AppLog.w("BtHidKeypad: registerApp returned false; will retry")
        }
        return false
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private val profileListener = object : BluetoothProfile.ServiceListener {
        override fun onServiceConnected(profile: Int, proxy: BluetoothProfile?) {
            if (profile != BluetoothProfile.HID_DEVICE) return
            val hid = proxy as? BluetoothHidDevice ?: return
            if (!started) {
                try {
                    getAdapter()?.closeProfileProxy(BluetoothProfile.HID_DEVICE, hid)
                } catch (_: Exception) {}
                return
            }
            AppLog.i("BtHidKeypad: BluetoothHidDevice profile proxy connected")
            hidProxy = hid
            hidAppRegistered = false
            registerInFlight = false
            lastRegisterAttemptMs = 0L
            postImmediateEvaluate("proxy_connected")
        }

        override fun onServiceDisconnected(profile: Int) {
            if (profile != BluetoothProfile.HID_DEVICE) return
            AppLog.w("BtHidKeypad: BluetoothHidDevice profile proxy disconnected")
            hidProxy = null
            hidAppRegistered = false
            registerInFlight = false
            connectedHidAddresses.clear()
            notifiedConnectedAddresses.clear()
            postDelayedEvaluate(BtHidKeypadPolicy.REGISTER_RETRY_MS)
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private val hidCallback = @RequiresApi(Build.VERSION_CODES.P) object : BluetoothHidDevice.Callback() {
        @SuppressLint("MissingPermission")
        override fun onAppStatusChanged(pluggedDevice: BluetoothDevice?, registered: Boolean) {
            registerInFlight = false
            hidAppRegistered = registered
            val plugged = try { pluggedDevice?.address } catch (_: Exception) { null }
            AppLog.i("BtHidKeypad: HID dummy keypad registration=$registered (pluggedDevice=$plugged)")
            if (registered) {
                postImmediateEvaluate("app_registered")
            } else {
                connectedHidAddresses.clear()
                notifiedConnectedAddresses.clear()
                postDelayedEvaluate(BtHidKeypadPolicy.REGISTER_RETRY_MS)
            }
        }

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChanged(device: BluetoothDevice?, state: Int) {
            val dev = device ?: return
            val mac = dev.address.uppercase()
            val name = try { dev.name } catch (_: Exception) { null }
            when (state) {
                BluetoothProfile.STATE_CONNECTED -> {
                    connectedHidAddresses.add(mac)
                    notifiedConnectedAddresses.add(mac)
                    AppLog.i("BtHidKeypad: HID dummy keypad CONNECTED to ${name ?: mac} — keeping link open & stopping watcher")
                    if (hasBluetoothConnectPermission()) {
                        try {
                            hidProxy?.sendReport(dev, 0, BtHidKeypadPolicy.IDLE_KEYPAD_REPORT)
                        } catch (e: Exception) {
                            AppLog.d("BtHidKeypad: idle report skipped: ${e.message}")
                        }
                    }
                    pauseWatcherLoop("preferred Bluetooth HID keypad connected ($mac)")
                    onTargetPhoneConnected(dev.address, name, "Bluetooth HID keypad connected")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    val wasConnected = connectedHidAddresses.remove(mac)
                    notifiedConnectedAddresses.remove(mac)
                    lastConnectAttemptMs.remove(mac)
                    if (wasConnected || isPreferredTargetAddress(mac)) {
                        AppLog.i("BtHidKeypad: HID dummy keypad DISCONNECTED from ${name ?: mac}; checking if watcher should auto-start")
                        postDelayedEvaluate(1_500L)
                    }
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onGetReport(device: BluetoothDevice?, type: Byte, id: Byte, bufferSize: Int) {
            val dev = device ?: return
            if (!hasBluetoothConnectPermission()) return
            try {
                if (type == BluetoothHidDevice.REPORT_TYPE_INPUT) {
                    hidProxy?.replyReport(dev, type, id, BtHidKeypadPolicy.IDLE_KEYPAD_REPORT)
                } else {
                    hidProxy?.reportError(dev, BluetoothHidDevice.ERROR_RSP_INVALID_RPT_ID)
                }
            } catch (_: Exception) {}
        }

        @SuppressLint("MissingPermission")
        override fun onSetReport(device: BluetoothDevice?, type: Byte, id: Byte, data: ByteArray?) {
            val dev = device ?: return
            if (!hasBluetoothConnectPermission()) return
            try {
                hidProxy?.reportError(dev, BluetoothHidDevice.ERROR_RSP_SUCCESS)
            } catch (_: Exception) {}
        }
    }

    private fun extractDevice(intent: Intent): BluetoothDevice? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
        }
    }
}
