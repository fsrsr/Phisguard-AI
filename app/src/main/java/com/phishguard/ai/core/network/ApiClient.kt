package com.phishguard.ai.core.network

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import kotlin.concurrent.thread

/**
 * Real Production-Ready HTTP Client
 * 
 * Features:
 * - GET/POST/PUT/DELETE methods
 * - Configurable timeouts
 * - Retry logic untuk network errors
 * - Better error handling
 * - Response parsing helpers
 */
class ApiClient {

    private val TAG = "ApiClient"
    
    // Default timeouts (dapat di-override per request)
    var defaultConnectTimeout = 10000  // 10 seconds
    var defaultReadTimeout = 15000     // 15 seconds
    var maxRetries = 2

    data class ApiResponse(
        val success: Boolean,
        val statusCode: Int,
        val body: String?,
        val error: String?
    )

    /**
     * GET request dengan retry logic
     */
    fun get(
        endpoint: String, 
        headers: Map<String, String> = emptyMap(),
        timeout: Int = defaultConnectTimeout,
        callback: (Boolean, String?) -> Unit
    ) {
        executeWithRetry(endpoint, "GET", null, headers, timeout, callback)
    }

    /**
     * POST request dengan JSON body
     */
    fun post(
        endpoint: String, 
        jsonBody: String,
        headers: Map<String, String> = emptyMap(),
        timeout: Int = defaultConnectTimeout,
        callback: (Boolean, String?) -> Unit
    ) {
        executeWithRetry(endpoint, "POST", jsonBody, headers, timeout, callback)
    }

    /**
     * PUT request
     */
    fun put(
        endpoint: String,
        jsonBody: String,
        headers: Map<String, String> = emptyMap(),
        timeout: Int = defaultConnectTimeout,
        callback: (Boolean, String?) -> Unit
    ) {
        executeWithRetry(endpoint, "PUT", jsonBody, headers, timeout, callback)
    }

    /**
     * DELETE request
     */
    fun delete(
        endpoint: String,
        headers: Map<String, String> = emptyMap(),
        timeout: Int = defaultConnectTimeout,
        callback: (Boolean, String?) -> Unit
    ) {
        executeWithRetry(endpoint, "DELETE", null, headers, timeout, callback)
    }

    /**
     * Enhanced GET dengan detailed response
     */
    fun getDetailed(
        endpoint: String,
        headers: Map<String, String> = emptyMap(),
        timeout: Int = defaultConnectTimeout,
        callback: (ApiResponse) -> Unit
    ) {
        thread {
            val response = executeRequest(endpoint, "GET", null, headers, timeout)
            callback(response)
        }
    }

    /**
     * Execute request dengan retry logic
     */
    private fun executeWithRetry(
        endpoint: String,
        method: String,
        body: String?,
        headers: Map<String, String>,
        timeout: Int,
        callback: (Boolean, String?) -> Unit
    ) {
        thread {
            var attempt = 0
            var lastError: String? = null
            
            while (attempt <= maxRetries) {
                val response = executeRequest(endpoint, method, body, headers, timeout)
                
                if (response.success) {
                    callback(true, response.body)
                    return@thread
                }
                
                lastError = response.error
                
                // Retry pada network error, tapi tidak untuk client/server error
                if (response.statusCode in 400..599) {
                    // HTTP error, jangan retry
                    break
                }
                
                attempt++
                if (attempt <= maxRetries) {
                    Log.d(TAG, "Retry attempt $attempt/$maxRetries for $endpoint")
                    Thread.sleep(1000L * attempt) // Exponential backoff
                }
            }
            
            callback(false, lastError)
        }
    }

    /**
     * Core request execution
     */
    private fun executeRequest(
        endpoint: String,
        method: String,
        body: String?,
        headers: Map<String, String>,
        timeout: Int
    ): ApiResponse {
        var connection: HttpURLConnection? = null
        
        try {
            Log.d(TAG, "$method: $endpoint")
            
            val url = URL(endpoint)
            connection = url.openConnection() as HttpURLConnection
            
            connection.requestMethod = method
            connection.connectTimeout = timeout
            connection.readTimeout = defaultReadTimeout
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", "PhishGuard-Android/1.0")
            
            // Add custom headers
            headers.forEach { (key, value) ->
                connection.setRequestProperty(key, value)
            }
            
            // Write body untuk POST/PUT
            if (body != null && (method == "POST" || method == "PUT")) {
                connection.doOutput = true
                connection.outputStream.use { outputStream ->
                    outputStream.write(body.toByteArray(Charsets.UTF_8))
                    outputStream.flush()
                }
            }
            
            val statusCode = connection.responseCode
            Log.d(TAG, "$method $endpoint -> HTTP $statusCode")
            
            // Read response
            val responseBody = if (statusCode in 200..299) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                // Try to read error stream
                try {
                    connection.errorStream?.bufferedReader()?.use { it.readText() }
                } catch (e: Exception) {
                    null
                }
            }
            
            return ApiResponse(
                success = statusCode in 200..299,
                statusCode = statusCode,
                body = responseBody,
                error = if (statusCode !in 200..299) "HTTP $statusCode" else null
            )
            
        } catch (e: SocketTimeoutException) {
            Log.e(TAG, "Request timeout: $endpoint", e)
            return ApiResponse(
                success = false,
                statusCode = 0,
                body = null,
                error = "Connection timeout"
            )
        } catch (e: java.net.UnknownHostException) {
            Log.e(TAG, "Unknown host: $endpoint", e)
            return ApiResponse(
                success = false,
                statusCode = 0,
                body = null,
                error = "Cannot resolve host (check internet connection)"
            )
        } catch (e: java.io.IOException) {
            Log.e(TAG, "Network error: $endpoint", e)
            return ApiResponse(
                success = false,
                statusCode = 0,
                body = null,
                error = "Network error: ${e.message}"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Request failed: $endpoint", e)
            return ApiResponse(
                success = false,
                statusCode = 0,
                body = null,
                error = "Request failed: ${e.message}"
            )
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * Download file dari URL (untuk future use)
     */
    fun downloadFile(
        url: String,
        outputPath: String,
        progressCallback: ((bytesDownloaded: Long, totalBytes: Long) -> Unit)? = null,
        callback: (success: Boolean, error: String?) -> Unit
    ) {
        thread {
            var connection: HttpURLConnection? = null
            try {
                connection = URL(url).openConnection() as HttpURLConnection
                connection.connectTimeout = defaultConnectTimeout
                connection.readTimeout = 30000 // 30 seconds untuk download
                
                val statusCode = connection.responseCode
                if (statusCode != 200) {
                    callback(false, "HTTP $statusCode")
                    return@thread
                }
                
                val totalBytes = connection.contentLengthLong
                val outputFile = java.io.File(outputPath)
                
                connection.inputStream.use { input ->
                    outputFile.outputStream().use { output ->
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        var totalRead = 0L
                        
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            output.write(buffer, 0, bytesRead)
                            totalRead += bytesRead
                            progressCallback?.invoke(totalRead, totalBytes)
                        }
                    }
                }
                
                callback(true, null)
                
            } catch (e: Exception) {
                Log.e(TAG, "Download failed: $url", e)
                callback(false, e.message)
            } finally {
                connection?.disconnect()
            }
        }
    }

    /**
     * Check if URL is reachable (HEAD request)
     */
    fun isUrlReachable(url: String, callback: (reachable: Boolean, responseTime: Long) -> Unit) {
        thread {
            var connection: HttpURLConnection? = null
            try {
                val startTime = System.currentTimeMillis()
                connection = URL(url).openConnection() as HttpURLConnection
                connection.requestMethod = "HEAD"
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                
                val statusCode = connection.responseCode
                val responseTime = System.currentTimeMillis() - startTime
                
                callback(statusCode in 200..399, responseTime)
                
            } catch (e: Exception) {
                callback(false, 0)
            } finally {
                connection?.disconnect()
            }
        }
    }
}
