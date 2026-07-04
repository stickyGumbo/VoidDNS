package com.voiddns.app.stats

import android.content.Context
import android.content.SharedPreferences
import com.voiddns.app.blocklist.BlocklistManager

class StatsManager private constructor(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "voiddns_stats"
        private const val KEY_TOTAL_BLOCKED = "total_blocked"
        private const val KEY_TOTAL_QUERIES = "total_queries"

        @Volatile
        private var instance: StatsManager? = null

        fun getInstance(context: Context): StatsManager {
            return instance ?: synchronized(this) {
                instance ?: StatsManager(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // Read live counts directly from BlocklistManager
    fun getTotalBlocked(): Int {
        val sessionBlocked = BlocklistManager.getInstance(context).getBlockedCount()
        return prefs.getInt(KEY_TOTAL_BLOCKED, 0) + sessionBlocked
    }

    fun getTotalQueries(): Int {
        val sessionQueries = BlocklistManager.getInstance(context).getTotalQueries()
        return prefs.getInt(KEY_TOTAL_QUERIES, 0) + sessionQueries
    }

    fun getBlockRate(): Float {
        val total = getTotalQueries()
        if (total == 0) return 0f
        return (getTotalBlocked().toFloat() / total) * 100
    }

    // Call this when VPN stops to persist session stats
    fun persistSession() {
        val blocked = BlocklistManager.getInstance(context).getBlockedCount()
        val queries = BlocklistManager.getInstance(context).getTotalQueries()
        prefs.edit()
            .putInt(KEY_TOTAL_BLOCKED, prefs.getInt(KEY_TOTAL_BLOCKED, 0) + blocked)
            .putInt(KEY_TOTAL_QUERIES, prefs.getInt(KEY_TOTAL_QUERIES, 0) + queries)
            .apply()
    }

    fun resetStats() {
        prefs.edit().clear().apply()
    }
}
