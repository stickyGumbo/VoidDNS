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

    @Volatile
    private var trie = DomainTrie()
    @Volatile
    private var bloomBits: LongArray? = null
    @Volatile
    private var bloomK: Int = 0
    private var isLoaded = false

    fun initialize() {
        CoroutineScope(Dispatchers.IO).launch {
            val disk = readBlocklistFromDisk() + readCustomRulesFromDisk()
            if (disk.isEmpty()) {
                fetchAndSaveLists()
            } else {
                rebuildFromDomains(disk)
            }
            isLoaded = true
            Log.d(TAG, "Blocklist ready: ${trie.size()} domains")
        }
    }

    fun isBlocked(domain: String): Boolean {
        globalTotalQueries.incrementAndGet()
        val b = bloomBits
        val k = bloomK
        if (b != null && k > 0) {
            // bloom check
            val h = domain.hashCode()
            val h1 = (h.toLong() and 0xffffffffL)
            val h2 = (Integer.rotateLeft(h, 16).toLong() and 0xffffffffL)
            val m = b.size * 64
            for (i in 0 until k) {
                var combined = (h1 + i * h2) % m
                if (combined < 0) combined += m
                val word = (combined / 64).toInt()
                val bit = (combined % 64).toInt()
                if ((b[word] and (1L shl bit)) == 0L) return false
            }
            // maybe present; fallthrough to trie
        }
        return trie.contains(domain)
    }

    fun incrementBlockedCount() {
        globalBlockedCount.incrementAndGet()
    }

    fun getBlockedCount(): Int = globalBlockedCount.get()
    fun getTotalQueries(): Int = globalTotalQueries.get()
    fun getDomainCount(): Int = trie.size()

    private fun readBlocklistFromDisk(): Set<String> {
        val file = File(context.filesDir, "blocklist.txt")
        if (!file.exists()) return emptySet()
        val result = mutableSetOf<String>()
        file.forEachLine { line ->
            val domain = parseLine(line)
            if (domain != null) result.add(domain)
        }
        Log.d(TAG, "Loaded ${result.size} domains from disk")
        return result
    }
    fun reloadFromDisk() {
        try {
            val combined = readBlocklistFromDisk() + readCustomRulesFromDisk()
            rebuildFromDomains(combined)
            Log.d(TAG, "Reloaded from disk: ${trie.size()} domains")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to reload from disk: ${e.message}")
        }
    }

    private fun readCustomRulesFromDisk(): Set<String> {
        val file = File(context.filesDir, "custom_rules.txt")
        if (!file.exists()) return emptySet()
        val result = mutableSetOf<String>()
        file.forEachLine { line ->
            val domain = line.trim()
            if (domain.isNotEmpty() && isValidDomain(domain)) result.add(domain.lowercase())
        }
        Log.d(TAG, "Loaded ${result.size} custom rules from disk")
        return result
    }

    suspend fun fetchAndSaveLists(progress: ((String) -> Unit)? = null) {
        val client = OkHttpClient.Builder()
            .callTimeout(java.time.Duration.ofMinutes(2))
            .build()

        val outFile = File(context.filesDir, "blocklist.txt")
        val tmpFile = File(context.filesDir, "blocklist.tmp")
        if (tmpFile.exists()) tmpFile.delete()

        val newTrie = DomainTrie()

        BLOCKLIST_SOURCES.forEach { (name, url) ->
            try {
                Log.d(TAG, "Fetching $name...")
                val request = Request.Builder().url(url).build()
                client.newCall(request).execute().use { response ->
                    val body = response.body ?: return@forEach
                    var count = 0
                    body.byteStream().bufferedReader().useLines { lines ->
                        tmpFile.appendText("") // ensure file exists
                        lines.forEach { line ->
                            val domain = parseLine(line)
                            if (domain != null) {
                                // avoid duplicates across sources
                                if (newTrie.contains(domain)) return@forEach
                                tmpFile.appendText(domain + "\n")
                                if (domain.startsWith("*.") && domain.length > 2) newTrie.insertWildcard(domain)
                                else newTrie.insert(domain)
                                count++
                            }
                        }
                    }
                    Log.d(TAG, "$name: $count domains")
                    progress?.invoke("$name: $count domains")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch $name: ${e.message}")
            }
        }

        // Move tmp file to final
        if (tmpFile.exists()) {
            tmpFile.renameTo(outFile)
        }

        // Atomic swap of trie and build bloom by streaming the saved file
        trie = newTrie
        val n = newTrie.size()
        val (bits, k, m) = if (n > 0) {
            // compute bloom params
            val ln2 = Math.log(2.0)
            val mDouble = -n * Math.log(0.01) / (ln2 * ln2)
            val mInt = Math.max(64, Math.ceil(mDouble).toInt())
            val kInt = Math.max(1, Math.round((mDouble / n * ln2).toFloat()).toInt())
            val bitsArr = LongArray((mInt + 63) / 64)
            // populate bits by streaming file
            if (outFile.exists()) {
                outFile.forEachLine { line ->
                    val d = line.trim()
                    if (d.isEmpty()) return@forEachLine
                    val h = d.hashCode()
                    val h1 = (h.toLong() and 0xffffffffL)
                    val h2 = (Integer.rotateLeft(h, 16).toLong() and 0xffffffffL)
                    for (i in 0 until kInt) {
                        var combined = (h1 + i * h2) % mInt
                        if (combined < 0) combined += mInt
                        val word = (combined / 64).toInt()
                        val bit = (combined % 64).toInt()
                        bitsArr[word] = bitsArr[word] or (1L shl bit)
                    }
                }
            }
            Triple(bitsArr, kInt, mInt)
        } else {
            Triple(LongArray(0), 0, 0)
        }

        bloomBits = bits
        bloomK = k
        Log.d(TAG, "Total domains loaded: ${trie.size()}")
    }

    fun addCustomRule(domain: String) {
        val d = domain.lowercase().trim()
        val existing = readCustomRulesFromDisk()
        if (existing.contains(d)) return
        File(context.filesDir, "custom_rules.txt").appendText("$d\n")
        // rebuild trie + bloom with new custom rules
        val combined = readBlocklistFromDisk() + readCustomRulesFromDisk()
        rebuildFromDomains(combined)
    }

    fun removeCustomRule(domain: String) {
        // Simple approach: rebuild custom_rules.txt without the removed domain
        try {
            val file = File(context.filesDir, "custom_rules.txt")
            if (!file.exists()) return
            val remaining = file.readLines().map { it.trim() }
                .filter { it.isNotEmpty() && it != domain.lowercase().trim() }
            file.writeText(remaining.joinToString("\n") + if (remaining.isNotEmpty()) "\n" else "")
            // Rebuild trie from disk (blocklist + custom)
            val combined = readBlocklistFromDisk() + readCustomRulesFromDisk()
            rebuildFromDomains(combined)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove custom rule: ${e.message}")
        }
    }

    fun getCustomRules(): List<String> {
        val file = File(context.filesDir, "custom_rules.txt")
        if (!file.exists()) return emptyList()
        return file.readLines().map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun rebuildFromDomains(domains: Collection<String>) {
        try {
            val newTrie = DomainTrie()
            domains.forEach { d ->
                if (d.startsWith("*.") && d.length > 2) newTrie.insertWildcard(d)
                else newTrie.insert(d)
            }

            // build bloom filter
            val (bits, k, m) = buildBloom(domains)

            // atomic swap
            trie = newTrie
            bloomBits = bits
            bloomK = k

            Log.d(TAG, "Rebuilt structures: domains=${newTrie.size()} bloomBits=$m k=$k")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to rebuild structures: ${e.message}")
        }
    }

    private fun buildBloom(domains: Collection<String>, falsePositiveRate: Double = 0.01): Triple<LongArray, Int, Int> {
        val n = domains.size
        if (n == 0) return Triple(LongArray(0), 0, 0)
        val ln2 = Math.log(2.0)
        val mDouble = -n * Math.log(falsePositiveRate) / (ln2 * ln2)
        val m = Math.max(64, Math.ceil(mDouble).toInt()) // at least 64 bits
        val k = Math.max(1, Math.round((mDouble / n * ln2).toFloat()).toInt())
        val bits = LongArray((m + 63) / 64)

        domains.forEach { domain ->
            val h = domain.hashCode()
            val h1 = (h.toLong() and 0xffffffffL)
            val h2 = (Integer.rotateLeft(h, 16).toLong() and 0xffffffffL)
            for (i in 0 until k) {
                val combined = (h1 + i * h2) % m
                val idx = if (combined < 0) (combined + m) else combined
                val word = (idx / 64).toInt()
                val bit = (idx % 64).toInt()
                bits[word] = bits[word] or (1L shl bit)
            }
        }
        return Triple(bits, k, m)
    }

    private fun bloomM(): Int = bloomBits?.size?.times(64) ?: 0

    

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
