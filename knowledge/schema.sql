-- protoPen knowledge base schema

-- Papers: tracked arxiv papers and their summaries
CREATE TABLE IF NOT EXISTS papers (
    id TEXT PRIMARY KEY,                -- arxiv ID (e.g., "2401.12345")
    title TEXT NOT NULL,
    authors TEXT,                        -- JSON array
    abstract TEXT,
    summary TEXT,                        -- agent-generated summary
    significance TEXT DEFAULT 'unknown', -- breakthrough/significant/incremental/noise
    categories TEXT,                     -- JSON array of arxiv categories
    tags TEXT,                           -- JSON array of custom tags
    pdf_path TEXT,                       -- local path if downloaded
    source_url TEXT,
    published_at TEXT,
    discovered_at TEXT NOT NULL,
    read_at TEXT,
    notes TEXT
);

-- Findings: extracted insights, methods, results
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    source TEXT,                          -- paper ID, URL, or other source
    source_type TEXT,                     -- paper/blog/github/model_release
    topic TEXT,
    finding_type TEXT,                    -- insight/result/method/benchmark/recommendation
    significance TEXT,
    created_at TEXT NOT NULL
);

-- Topics: research areas being tracked
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

-- Digests: generated research summaries
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    digest_type TEXT,                     -- daily/weekly/deep_dive/comparison
    topic TEXT,
    papers_referenced TEXT,               -- JSON array of paper IDs
    created_at TEXT NOT NULL
);

-- Model releases: tracked from HF/GitHub
CREATE TABLE IF NOT EXISTS model_releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL,
    name TEXT,
    organization TEXT,
    description TEXT,
    parameters TEXT,
    architecture TEXT,
    license TEXT,
    downloads INTEGER,
    likes INTEGER,
    source TEXT,                           -- huggingface/github
    released_at TEXT,
    discovered_at TEXT NOT NULL,
    notes TEXT
);

-- Sources: tracked external sources
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    source_type TEXT,                      -- arxiv/huggingface/github/blog/newsletter
    url TEXT,
    scan_schedule TEXT,
    last_scanned_at TEXT,
    config TEXT                            -- JSON config
);

-- FTS5 full-text search index for BM25 keyword search (hybrid search)
-- Populated alongside knowledge_vec at insert time
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    content,
    source_table UNINDEXED,
    source_id UNINDEXED,
    tokenize='porter unicode61'
);
