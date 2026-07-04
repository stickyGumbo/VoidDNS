package com.voiddns.app.ui

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.voiddns.app.R
import com.voiddns.app.blocklist.BlocklistManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader

class BlocklistActivity : AppCompatActivity() {

    private lateinit var lvSources: ListView
    private lateinit var lvCustom: ListView
    private lateinit var etCustomDomain: EditText
    private lateinit var btnAddCustom: Button
    private lateinit var btnRemoveCustom: Button
    private lateinit var etUpstream: EditText
    private lateinit var btnSaveUpstream: Button
    private lateinit var btnFetchLists: Button
    private lateinit var pbFetch: ProgressBar
    private lateinit var tvFetchStatus: TextView
    private lateinit var btnImportFile: Button

    private lateinit var blocklistManager: BlocklistManager
    private val IMPORT_REQUEST = 221

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_blocklist)

        blocklistManager = BlocklistManager.getInstance(this)

        lvSources = findViewById(R.id.lvSources)
        lvCustom = findViewById(R.id.lvCustomRules)
        etCustomDomain = findViewById(R.id.etCustomDomain)
        btnAddCustom = findViewById(R.id.btnAddCustom)
        btnRemoveCustom = findViewById(R.id.btnRemoveCustom)
        etUpstream = findViewById(R.id.etUpstreamDns)
        btnSaveUpstream = findViewById(R.id.btnSaveUpstream)
        btnFetchLists = findViewById(R.id.btnFetchLists)

        // Populate sources
        val sources = BlocklistManager.BLOCKLIST_SOURCES.keys.toList()
        lvSources.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, sources)

        refreshCustomList()

        btnAddCustom.setOnClickListener {
            val d = etCustomDomain.text.toString().trim().lowercase()
            if (d.isNotEmpty()) {
                blocklistManager.addCustomRule(d)
                etCustomDomain.setText("")
                refreshCustomList()
                Toast.makeText(this, "Added $d", Toast.LENGTH_SHORT).show()
            }
        }

        btnRemoveCustom.setOnClickListener {
            val pos = lvCustom.checkedItemPosition
            if (pos != ListView.INVALID_POSITION) {
                val domain = lvCustom.adapter.getItem(pos) as String
                blocklistManager.removeCustomRule(domain)
                refreshCustomList()
                Toast.makeText(this, "Removed $domain", Toast.LENGTH_SHORT).show()
            }
        }

        val prefs = getSharedPreferences("voiddns_prefs", Context.MODE_PRIVATE)
        etUpstream.setText(prefs.getString("upstream_dns", "1.1.1.1"))

        btnSaveUpstream.setOnClickListener {
            val v = etUpstream.text.toString().trim()
            prefs.edit().putString("upstream_dns", v).apply()
            Toast.makeText(this, "Upstream DNS saved: $v", Toast.LENGTH_SHORT).show()
        }

        btnFetchLists.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Fetch Lists")
                .setMessage("This will download and rebuild the full blocklist. Continue?")
                .setPositiveButton("Yes") { _, _ ->
                    pbFetch.visibility = ProgressBar.VISIBLE
                    tvFetchStatus.visibility = TextView.VISIBLE
                    btnFetchLists.isEnabled = false
                    btnAddCustom.isEnabled = false
                    btnRemoveCustom.isEnabled = false
                    btnSaveUpstream.isEnabled = false
                    btnImportFile.isEnabled = false
                    CoroutineScope(Dispatchers.IO).launch {
                        blocklistManager.fetchAndSaveLists { status ->
                            runOnUiThread {
                                tvFetchStatus.text = status
                            }
                        }
                        runOnUiThread {
                            refreshCustomList()
                            pbFetch.visibility = ProgressBar.GONE
                            tvFetchStatus.visibility = TextView.GONE
                            btnFetchLists.isEnabled = true
                            btnAddCustom.isEnabled = true
                            btnRemoveCustom.isEnabled = true
                            btnSaveUpstream.isEnabled = true
                            btnImportFile.isEnabled = true
                            Toast.makeText(this@BlocklistActivity, "Lists fetched", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        btnImportFile.setOnClickListener {
            val i = Intent(Intent.ACTION_GET_CONTENT)
            i.type = "text/*"
            startActivityForResult(Intent.createChooser(i, "Select rules file"), IMPORT_REQUEST)
        }
    }

    private fun refreshCustomList() {
        val items = blocklistManager.getCustomRules()
        lvCustom.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_single_choice, items)
        lvCustom.choiceMode = ListView.CHOICE_MODE_SINGLE
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == IMPORT_REQUEST && data != null && data.data != null) {
            val uri: Uri = data.data!!
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val existing = blocklistManager.getCustomRules().map { it.lowercase().trim() }.toMutableSet()
                    var added = 0
                    contentResolver.openInputStream(uri)?.use { stream ->
                        val reader = BufferedReader(InputStreamReader(stream))
                        val file = java.io.File(filesDir, "custom_rules.txt")
                        reader.forEachLine { line ->
                            val d = line.trim().lowercase()
                            if (d.isNotEmpty() && !existing.contains(d)) {
                                file.appendText(d + "\n")
                                existing.add(d)
                                added++
                            }
                        }
                    }
                    if (added > 0) blocklistManager.reloadFromDisk()
                    runOnUiThread {
                        refreshCustomList()
                        Toast.makeText(this@BlocklistActivity, "Imported $added rules", Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        Toast.makeText(this@BlocklistActivity, "Import failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }
}
