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

    fun getTotalBlocked(): Int {
        // Read directly from the SAME singleton instance
        val session = BlocklistManager.getInstance(context).getBlockedCount()
        val persisted = prefs.getInt(KEY_TOTAL_BLOCKED, 0)
        return persisted + session
    }

    fun getTotalQueries(): Int {
        val session = BlocklistManager.getInstance(context).getTotalQueries()
        val persisted = prefs.getInt(KEY_TOTAL_QUERIES, 0)
        return persisted + session
    }

    fun getBlockRate(): Float {
        val total = getTotalQueries()
        if (total == 0) return 0f
        return (getTotalBlocked().toFloat() / total) * 100
    }

    fun persistSession() {
        val bm = BlocklistManager.getInstance(context)
        prefs.edit()
            .putInt(KEY_TOTAL_BLOCKED, prefs.getInt(KEY_TOTAL_BLOCKED, 0) + bm.getBlockedCount())
            .putInt(KEY_TOTAL_QUERIES, prefs.getInt(KEY_TOTAL_QUERIES, 0) + bm.getTotalQueries())
            .apply()
    }

    fun resetStats() {
        prefs.edit().clear().apply()
    }
}
