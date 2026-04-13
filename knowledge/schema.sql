-- protoPen security knowledge base schema

-- CVEs: tracked vulnerabilities
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY,                -- CVE ID (e.g., "CVE-2024-12345")
    title TEXT,
    description TEXT,
    severity TEXT,                       -- critical/high/medium/low
    cvss_score REAL,
    cvss_vector TEXT,
    affected_products TEXT,              -- JSON array
    "references" TEXT,                   -- JSON array of URLs
    exploit_available INTEGER DEFAULT 0,
    exploit_maturity TEXT,               -- poc/weaponized/active/none
    tags TEXT,                           -- JSON array of custom tags
    published_at TEXT,
    discovered_at TEXT NOT NULL,
    analyzed_at TEXT,
    notes TEXT
);

-- Exploits: tracked PoCs and exploit code
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,                          -- linked CVE (nullable)
    title TEXT NOT NULL,
    description TEXT,
    source TEXT,                          -- exploit-db/github/custom
    source_url TEXT,
    platform TEXT,                        -- linux/windows/multi/hardware
    exploit_type TEXT,                    -- remote/local/webapps/dos/shellcode
    verified INTEGER DEFAULT 0,
    code_path TEXT,                       -- local path if downloaded
    discovered_at TEXT NOT NULL,
    tested_at TEXT,
    notes TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

-- Advisories: vendor and CERT advisories
CREATE TABLE IF NOT EXISTS advisories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,                 -- vendor/CERT/researcher
    title TEXT NOT NULL,
    content TEXT,
    severity TEXT,
    affected_products TEXT,               -- JSON array
    cve_ids TEXT,                         -- JSON array of linked CVEs
    url TEXT,
    published_at TEXT,
    discovered_at TEXT NOT NULL,
    notes TEXT
);

-- Topics: security areas being tracked
CREATE TABLE IF NOT EXISTS topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    keywords TEXT,                        -- JSON array of search terms
    priority INTEGER DEFAULT 2,           -- 0=critical, 4=backlog
    active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    last_scanned_at TEXT
);

-- Threat intel: findings and correlations
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    source TEXT,                           -- CVE ID, advisory, engagement
    source_type TEXT,                      -- cve/advisory/exploit/engagement/osint
    topic TEXT,
    intel_type TEXT,                       -- indicator/technique/correlation/recommendation
    severity TEXT,
    target_relevance TEXT,                 -- JSON: which targets this affects
    created_at TEXT NOT NULL
);

-- Digests: generated security intelligence summaries
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    digest_type TEXT,                      -- daily/weekly/threat_brief/engagement_summary
    topic TEXT,
    cves_referenced TEXT,                  -- JSON array of CVE IDs
    created_at TEXT NOT NULL
);

-- Sources: tracked security feeds
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    source_type TEXT,                      -- nvd/exploit_db/github/rss/advisory
    url TEXT,
    scan_schedule TEXT,
    last_scanned_at TEXT,
    config TEXT                            -- JSON config
);

-- FTS5 full-text search index for BM25 keyword search (hybrid search)
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    content,
    source_table UNINDEXED,
    source_id UNINDEXED,
    tokenize='porter unicode61'
);
