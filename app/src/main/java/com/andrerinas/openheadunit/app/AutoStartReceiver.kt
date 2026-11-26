package com.andrerinas.openheadunit.app

import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.andrerinas.openheadunit.aap.AapService
import com.andrerinas.openheadunit.main.MainActivity
import com.andrerinas.openheadunit.main.SettingsActivity
import com.andrerinas.openheadunit.utils.AppLog
import com.andrerinas.openheadunit.utils.Settings
import android.os.UserManager
import android.os.Build

class AutoStartReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != BluetoothDevice.ACTION_ACL_CONNECTED) return

        val isLocked = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N &&
                      !(context.getSystemService(Context.USER_SERVICE) as UserManager).isUserUnlocked

        // Before the first unlock there is no credential storage, which both the session and the
        // object graph read, so there is nothing to start yet. Nothing replays this event either,
        // so a phone that connected at the lock screen has to reconnect once the user is in.
        if (isLocked) {
            AppLog.w("AutoStartReceiver: device is locked, ignoring the Bluetooth event until the user unlocks.")
            return
        }

        val appComponent = com.andrerinas.openheadunit.App.provide(context)
        val commConnected = appComponent.commManager.isConnected
        val appInForeground = com.andrerinas.openheadunit.App.hasStartedActivity
        if (commConnected && appInForeground) {
            AppLog.d("AutoStartReceiver: Already connected to Android Auto in foreground. Ignoring BT event.")
            return
        }

        val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
        } ?: return

        val settings = appComponent.settings
        val autoStartMacs = Settings.getAutoStartBtMacs(context)
        val candidates = com.andrerinas.openheadunit.utils.BluetoothHelper.driverCandidates(
            context,
            settings.nativePhonesList,
            settings.nativeProvenPhones
        )
        val targetMacs = com.andrerinas.openheadunit.connection.bluetooth.BtHidKeypadPolicy.selectTargetAddresses(
            configuredAutoStartMacs = autoStartMacs,
            configuredNativeMacs = settings.nativePhonesList,
            provenNativeMacs = settings.nativeProvenPhones,
            candidatePhoneMacs = candidates.offered.map { it.address },
        )

        AppLog.i("BT Device connected: ${device.name} (${device.address})")

        if (targetMacs.contains(device.address.uppercase())) {
            AppLog.i("MATCH! Starting AapService via Bluetooth Auto-start...")

            val uiHeld = SettingsActivity.isVisible
            val serviceIntent = Intent(context, AapService::class.java)
                .setAction(AapService.ACTION_BT_AUTO_START)
                .putExtra(AapService.EXTRA_UI_HELD, uiHeld)
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, serviceIntent)
            } catch (e: Exception) {
                AppLog.e("Failed to start AapService from background: ${e.message}")
            }

            // Projection already up or settings open: AapService raises the right activity itself.
            if (uiHeld || commConnected) return

            val launchIntent = Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(MainActivity.EXTRA_LAUNCH_SOURCE, MainActivity.LAUNCH_SOURCE_BLUETOOTH)
            }
            try {
                context.startActivity(launchIntent)
            } catch (e: Exception) {
                AppLog.w("Could not start UI from background (expected on Android 10+): ${e.message}")
            }
        }
    }
}