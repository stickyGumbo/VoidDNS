package com.voiddns.app.blocklist

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class BlocklistManager private constructor(private val context: Context) {

    companion object {
        const val TAG = "BlocklistManager"

        // All the best free blocklists
        val BLOCKLIST_SOURCES = mapOf(
            "StevenBlack" to "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "AdGuard" to "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "OISD" to "https://small.oisd.nl/domainswild",
            "Hagezi" to "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"
        )

        @Volatile
        private var instance: BlocklistManager? = null

        fun getInstance(context: Context): BlocklistManager {
            return instance ?: synchronized(this) {
                instance ?: BlocklistManager(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }

    // Trie for ultra fast domain lookup
    private val trie = DomainTrie()
    private val blockedCount = AtomicInteger(0)
    private val totalQueries = AtomicInteger(0)
    private var isLoaded = false

    fun initialize() {
        CoroutineScope(Dispatchers.IO).launch {
            loadFromDisk()
            if (trie.size() == 0) {
                fetchAndSaveLists()
            }
            isLoaded = true
            Log.d(TAG, "Blocklist ready: ${trie.size()} domains")
        }
    }

    fun isBlocked(domain: String): Boolean {
        totalQueries.incrementAndGet()
        return trie.contains(domain)
    }

    fun incrementBlockedCount() {
        blockedCount.incrementAndGet()
    }

    fun getBlockedCount(): Int = blockedCount.get()
    fun getTotalQueries(): Int = totalQueries.get()
    fun getDomainCount(): Int = trie.size()

    private fun loadFromDisk() {
        val file = File(context.filesDir, "blocklist.txt")
        if (!file.exists()) return
        var count = 0
        file.forEachLine { line ->
            val domain = parseLine(line)
            if (domain != null) {
                trie.insert(domain)
                count++
            }
        }
        Log.d(TAG, "Loaded $count domains from disk")
    }

    suspend fun fetchAndSaveLists() {
        val client = OkHttpClient()
        val allDomains = mutableSetOf<String>()

        BLOCKLIST_SOURCES.forEach { (name, url) ->
            try {
                Log.d(TAG, "Fetching $name...")
                val request = Request.Builder().url(url).build()
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: return@forEach
                var count = 0
                body.lines().forEach { line ->
                    val domain = parseLine(line)
                    if (domain != null) {
                        allDomains.add(domain)
                        count++
                    }
                }
                Log.d(TAG, "$name: $count domains")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch $name: ${e.message}")
            }
        }

        // Save to disk
        val file = File(context.filesDir, "blocklist.txt")
        file.writeText(allDomains.joinToString("\n"))

        // Load into trie
        allDomains.forEach { trie.insert(it) }
        Log.d(TAG, "Total domains loaded: ${trie.size()}")
    }

    fun addCustomRule(domain: String) {
        trie.insert(domain.lowercase().trim())
        saveCustomRule(domain)
    }

    private fun saveCustomRule(domain: String) {
        val file = File(context.filesDir, "custom_rules.txt")
        file.appendText("$domain\n")
    }

    private fun parseLine(line: String): String? {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return null

        return when {
            // hosts file format: "0.0.0.0 domain.com"
            trimmed.startsWith("0.0.0.0 ") -> {
                val domain = trimmed.substringAfter("0.0.0.0 ").trim()
                if (isValidDomain(domain)) domain else null
            }
            trimmed.startsWith("127.0.0.1 ") -> {
                val domain = trimmed.substringAfter("127.0.0.1 ").trim()
                if (isValidDomain(domain)) domain else null
            }
            // plain domain format
            isValidDomain(trimmed) -> trimmed
            // wildcard format *.domain.com
            trimmed.startsWith("*.") -> trimmed.substring(2)
            else -> null
        }
    }

    private fun isValidDomain(domain: String): Boolean {
        if (domain.isEmpty() || domain.length > 253) return false
        if (domain == "localhost" || domain == "0.0.0.0") return false
        return domain.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]*[a-zA-Z0-9]$"))
    }
}
