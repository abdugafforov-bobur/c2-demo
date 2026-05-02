package com.securitydemo.systeminfo

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import java.net.NetworkInterface
import java.util.Locale
import java.util.TimeZone

/**
 * Collects device metadata using ONLY normal (non-dangerous) permissions.
 *
 * TRAINING POINT: All of this data is accessible without ANY runtime
 * permission prompts. The user is never asked to approve anything.
 * Only INTERNET + ACCESS_NETWORK_STATE + ACCESS_WIFI_STATE are needed,
 * and these are auto-granted normal permissions.
 */
class DeviceDataCollector(private val context: Context) {

    fun collectAll(): Map<String, Any> {
        val data = mutableMapOf<String, Any>()
        data["tag"] = "SECURITY_TRAINING_DEMO"
        data["timestamp"] = System.currentTimeMillis()
        data.putAll(getDeviceInfo())
        data.putAll(getBatteryInfo())
        data.putAll(getNetworkInfo())
        data.putAll(getStorageInfo())
        data.putAll(getInstalledApps())
        data.putAll(getSystemInfo())
        data.putAll(getLocaleInfo())
        return data
    }

    fun collectBasic(): Map<String, Any> {
        val data = mutableMapOf<String, Any>()
        data["tag"] = "SECURITY_TRAINING_DEMO"
        data["type"] = "heartbeat"
        data["timestamp"] = System.currentTimeMillis()
        data["device"] = "${Build.MANUFACTURER} ${Build.MODEL}"
        data["android"] = Build.VERSION.RELEASE
        data["api"] = Build.VERSION.SDK_INT
        data["fingerprint"] = Build.FINGERPRINT
        data["android_id"] = getAndroidId()
        return data
    }

    private fun getDeviceInfo(): Map<String, Any> = mapOf(
        "device" to "${Build.MANUFACTURER} ${Build.MODEL}",
        "android" to Build.VERSION.RELEASE,
        "api" to Build.VERSION.SDK_INT,
        "fingerprint" to Build.FINGERPRINT,
        "security_patch" to Build.VERSION.SECURITY_PATCH,
        "bootloader" to Build.BOOTLOADER,
        "hardware" to Build.HARDWARE,
        "board" to Build.BOARD,
        "product" to Build.PRODUCT,
        "display" to Build.DISPLAY,
        "host" to Build.HOST,
        "android_id" to getAndroidId(),
        "uptime_ms" to android.os.SystemClock.elapsedRealtime()
    )

    private fun getBatteryInfo(): Map<String, Any> {
        val batteryIntent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val plugged = batteryIntent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        val temp = batteryIntent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
        val pct = if (level >= 0 && scale > 0) (level * 100) / scale else -1
        val charging = when (plugged) {
            BatteryManager.BATTERY_PLUGGED_AC -> "AC"
            BatteryManager.BATTERY_PLUGGED_USB -> "USB"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "Wireless"
            else -> "Not charging"
        }
        return mapOf(
            "battery_pct" to pct,
            "battery_charging" to charging,
            "battery_temp_c" to (temp / 10.0)
        )
    }

    private fun getNetworkInfo(): Map<String, Any> {
        val info = mutableMapOf<String, Any>()
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(network)
            info["network_type"] = when {
                caps == null -> "None"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                else -> "Other"
            }
            info["has_internet"] = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ?: false
        } catch (e: Exception) {
            info["network_type"] = "Unknown"
        }

        // WiFi SSID requires location permission on newer Android, but we can still get
        // connection info like link speed, frequency, IP without it
        try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wifiInfo = wm.connectionInfo
            if (wifiInfo != null) {
                info["wifi_link_speed_mbps"] = wifiInfo.linkSpeed
                info["wifi_frequency_mhz"] = wifiInfo.frequency
                info["wifi_rssi"] = wifiInfo.rssi
            }
        } catch (_: Exception) {}

        // Get local IP addresses
        try {
            val ips = mutableListOf<String>()
            for (intf in NetworkInterface.getNetworkInterfaces()) {
                for (addr in intf.inetAddresses) {
                    if (!addr.isLoopbackAddress) {
                        val ip = addr.hostAddress
                        if (ip != null && !ip.contains("%")) {
                            ips.add("${intf.name}:$ip")
                        }
                    }
                }
            }
            info["local_ips"] = ips
        } catch (_: Exception) {}

        return info
    }

    private fun getStorageInfo(): Map<String, Any> {
        val stat = StatFs(Environment.getDataDirectory().path)
        val totalBytes = stat.blockSizeLong * stat.blockCountLong
        val freeBytes = stat.blockSizeLong * stat.availableBlocksLong
        val usedBytes = totalBytes - freeBytes

        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)

        return mapOf(
            "storage_total_gb" to String.format("%.1f", totalBytes / 1073741824.0),
            "storage_used_gb" to String.format("%.1f", usedBytes / 1073741824.0),
            "storage_free_gb" to String.format("%.1f", freeBytes / 1073741824.0),
            "ram_total_mb" to (memInfo.totalMem / 1048576),
            "ram_available_mb" to (memInfo.availMem / 1048576),
            "ram_low" to memInfo.lowMemory
        )
    }

    fun getInstalledApps(): Map<String, Any> {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_META_DATA)
        val appList = packages.map { pkg ->
            mapOf(
                "name" to (pm.getApplicationLabel(pkg.applicationInfo).toString()),
                "package" to pkg.packageName,
                "version" to (pkg.versionName ?: "?")
            )
        }.sortedBy { (it["name"] as String).lowercase() }

        return mapOf(
            "installed_apps_count" to appList.size,
            "installed_apps" to appList
        )
    }

    private fun getSystemInfo(): Map<String, Any> {
        val info = mutableMapOf<String, Any>()
        info["is_emulator"] = isEmulator()
        info["screen_density"] = context.resources.displayMetrics.densityDpi
        info["screen_width"] = context.resources.displayMetrics.widthPixels
        info["screen_height"] = context.resources.displayMetrics.heightPixels
        info["supported_abis"] = Build.SUPPORTED_ABIS.toList()
        return info
    }

    private fun getLocaleInfo(): Map<String, Any> = mapOf(
        "locale" to Locale.getDefault().toString(),
        "timezone" to TimeZone.getDefault().id,
        "timezone_offset_hrs" to (TimeZone.getDefault().rawOffset / 3600000)
    )

    private fun getAndroidId(): String {
        return try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    private fun isEmulator(): Boolean {
        return Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("emulator")
    }
}
