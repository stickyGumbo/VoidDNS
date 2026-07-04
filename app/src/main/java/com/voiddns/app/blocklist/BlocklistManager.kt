package com.voiddns.app.blocklist

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

class BlocklistManager private constructor(private val context: Context) {

    companion object {
        const val TAG = "BlocklistManager"

        // GLOBAL static counters — shared across all instances
        val globalBlockedCount = AtomicInteger(0)
        val globalTotalQueries = AtomicInteger(0)

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

    private val trie = DomainTrie()
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
        globalTotalQueries.incrementAndGet()
        return trie.contains(domain)
    }

    fun incrementBlockedCount() {
        globalBlockedCount.incrementAndGet()
    }

    fun getBlockedCount(): Int = globalBlockedCount.get()
    fun getTotalQueries(): Int = globalTotalQueries.get()
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

        val file = File(context.filesDir, "blocklist.txt")
        file.writeText(allDomains.joinToString("\n"))
        allDomains.forEach { trie.insert(it) }
        Log.d(TAG, "Total domains loaded: ${trie.size()}")
    }

    fun addCustomRule(domain: String) {
        trie.insert(domain.lowercase().trim())
        File(context.filesDir, "custom_rules.txt").appendText("$domain\n")
    }

    private fun parseLine(line: String): String? {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return null
        return when {
            trimmed.startsWith("0.0.0.0 ") -> {
                val d = trimmed.substringAfter("0.0.0.0 ").trim()
                if (isValidDomain(d)) d else null
            }
            trimmed.startsWith("127.0.0.1 ") -> {
                val d = trimmed.substringAfter("127.0.0.1 ").trim()
                if (isValidDomain(d)) d else null
            }
            trimmed.startsWith("*.") -> trimmed.substring(2)
            isValidDomain(trimmed) -> trimmed
            else -> null
        }
    }

    private fun isValidDomain(domain: String): Boolean {
        if (domain.isEmpty() || domain.length > 253) return false
        if (domain == "localhost" || domain == "0.0.0.0") return false
        return domain.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]*[a-zA-Z0-9]$"))
    }
}
