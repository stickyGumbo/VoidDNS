package com.voiddns.app.stats

import android.content.Context
import android.content.SharedPreferences

class StatsManager private constructor(context: Context) {

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

    fun saveStats(blocked: Int, total: Int) {
        prefs.edit()
            .putInt(KEY_TOTAL_BLOCKED, getTotalBlocked() + blocked)
            .putInt(KEY_TOTAL_QUERIES, getTotalQueries() + total)
            .apply()
    }

    fun getTotalBlocked(): Int = prefs.getInt(KEY_TOTAL_BLOCKED, 0)
    fun getTotalQueries(): Int = prefs.getInt(KEY_TOTAL_QUERIES, 0)

    fun getBlockRate(): Float {
        val total = getTotalQueries()
        if (total == 0) return 0f
        return (getTotalBlocked().toFloat() / total) * 100
    }

    fun resetStats() {
        prefs.edit().clear().apply()
    }
}
