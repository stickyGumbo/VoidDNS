package com.voiddns.app.ui

import android.content.Intent
import com.voiddns.app.R
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.voiddns.app.blocklist.BlocklistManager
import com.voiddns.app.stats.StatsManager
import com.voiddns.app.vpn.VoidVpnService
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    companion object {
        const val VPN_REQUEST_CODE = 100
    }

    private lateinit var blocklistManager: BlocklistManager
    private lateinit var statsManager: StatsManager
    private var updateJob: Job? = null

    private lateinit var statusIndicator: View
    private lateinit var statusTitle: TextView
    private lateinit var statusSubtitle: TextView
    private lateinit var toggleButton: Button
    private lateinit var tvBlockedCount: TextView
    private lateinit var tvTotalQueries: TextView
    private lateinit var tvBlockRate: TextView
    private lateinit var tvDomainCount: TextView
    private lateinit var manageListsButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        blocklistManager = BlocklistManager.getInstance(this)
        statsManager = StatsManager.getInstance(this)

        bindViews()
        setupToggleButton()
        blocklistManager.initialize()
        updateUI()
    }

    private fun bindViews() {
        statusIndicator = findViewById(R.id.statusIndicator)
        statusTitle = findViewById<TextView>(R.id.statusTitle)
        statusSubtitle = findViewById<TextView>(R.id.statusSubtitle)
        toggleButton = findViewById(R.id.toggleButton)
        tvBlockedCount = findViewById<TextView>(R.id.tvBlockedCount)
        tvTotalQueries = findViewById<TextView>(R.id.tvTotalQueries)
        tvBlockRate = findViewById<TextView>(R.id.tvBlockRate)
        tvDomainCount = findViewById<TextView>(R.id.tvDomainCount)
        manageListsButton = findViewById(R.id.manageListsButton)
    }

    private fun setupToggleButton() {
        toggleButton.setOnClickListener {
            if (VoidVpnService.isRunning) {
                stopVpn()
            } else {
                requestVpnPermission()
            }
        }
        manageListsButton.setOnClickListener {
            startActivity(Intent(this, BlocklistActivity::class.java))
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            startVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, VoidVpnService::class.java)
        startForegroundService(intent)
        updateUI()
        startStatsUpdate()
    }

    private fun stopVpn() {
        val intent = Intent(this, VoidVpnService::class.java)
        intent.action = "STOP"
        startService(intent)
        updateJob?.cancel()
        updateUI()
    }

    private fun updateUI() {
        val running = VoidVpnService.isRunning
        statusIndicator.setBackgroundResource(
            if (running) R.drawable.circle_green else R.drawable.circle_red
        )
        statusTitle.text = if (running) "Protection Active" else "Protection Inactive"
        statusSubtitle.text = if (running) "Blocking ads system-wide" else "Tap to enable VoidDNS"
        toggleButton.text = if (running) "Stop Protection" else "Start Protection"
        toggleButton.setBackgroundColor(
            if (running)
                getColor(android.R.color.holo_red_dark)
            else
                getColor(android.R.color.holo_green_dark)
        )
        tvDomainCount.text = "${blocklistManager.getDomainCount()} domains loaded"
        tvBlockedCount.text = "${statsManager.getTotalBlocked()}"
        tvTotalQueries.text = "${statsManager.getTotalQueries()}"
        tvBlockRate.text = "%.1f%%".format(statsManager.getBlockRate())
    }

    private fun startStatsUpdate() {
        updateJob = lifecycleScope.launch {
            while (true) {
                delay(1000)
                updateUI()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (VoidVpnService.isRunning) startStatsUpdate()
    }

    override fun onPause() {
        super.onPause()
        updateJob?.cancel()
    }
}
