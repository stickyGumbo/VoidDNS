package com.voiddns.app.blocklist

class DomainTrie {

    private val root = TrieNode()
    private var domainCount = 0

    inner class TrieNode {
        val children = HashMap<String, TrieNode>()
        var isBlocked = false
        var isWildcard = false
    }

    // Insert domain into trie
    // Domains are stored reversed by label for efficient wildcard matching
    // e.g. "ads.google.com" stored as ["com", "google", "ads"]
    fun insert(domain: String) {
        val labels = domain.lowercase().trim().split(".").reversed()
        var node = root
        for (label in labels) {
            if (label.isEmpty()) continue
            node = node.children.getOrPut(label) { TrieNode() }
        }
        if (!node.isBlocked) {
            node.isBlocked = true
            domainCount++
        }
    }

    // Insert wildcard rule e.g. *.doubleclick.net
    fun insertWildcard(domain: String) {
        val cleaned = domain.removePrefix("*.").lowercase().trim()
        val labels = cleaned.split(".").reversed()
        var node = root
        for (label in labels) {
            if (label.isEmpty()) continue
            node = node.children.getOrPut(label) { TrieNode() }
        }
        node.isWildcard = true
        if (!node.isBlocked) {
            node.isBlocked = true
            domainCount++
        }
    }

    // Check if domain is blocked
    // Also matches subdomains if parent is wildcard
    fun contains(domain: String): Boolean {
        val labels = domain.lowercase().trim().split(".").reversed()
        var node = root
        for (label in labels) {
            if (label.isEmpty()) continue
            // If current node is wildcard, block everything under it
            if (node.isWildcard) return true
            val child = node.children[label] ?: return false
            node = child
        }
        return node.isBlocked
    }

    fun size(): Int = domainCount

    fun clear() {
        root.children.clear()
        domainCount = 0
    }
}
