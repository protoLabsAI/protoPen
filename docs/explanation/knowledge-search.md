# Knowledge Search

protoPen uses a hybrid search system that combines vector similarity with keyword matching, fused via Reciprocal Rank Fusion (RRF). This provides significantly better retrieval quality than either approach alone.

## Stack

| Component | Role |
|---|---|
| **SQLite** | Core database engine |
| **sqlite-vec** | Vector similarity search extension (float32 embeddings) |
| **FTS5** | Full-text search with BM25 ranking |
| **nomic-embed-text / Qwen3-Embedding-0.6B** | Embedding model (served via OpenAI-compatible endpoint) |

The knowledge store lives at `/sandbox/knowledge/security.db` and stores advisories, threat intel, exploits, digests, and their vector embeddings in a single database file.

## How Hybrid Search Works

When a query arrives, protoPen runs two independent retrieval paths:

### 1. Vector Search (Semantic)

1. The query is embedded using the configured embedding model (default: `Qwen3-Embedding-0.6B`, 1024 dimensions)
2. sqlite-vec performs approximate nearest-neighbor search against the `knowledge_vec` virtual table
3. Returns the top-k results ranked by cosine similarity

### 2. Keyword Search (BM25)

1. The query is passed to the FTS5 `knowledge_fts` virtual table
2. SQLite's built-in BM25 ranking scores documents by term frequency and inverse document frequency
3. Returns the top-k results ranked by BM25 score

### 3. Reciprocal Rank Fusion

The two result lists are merged using RRF:

```
RRF_score(d) = sum( 1 / (k + rank_i(d)) )  for each retrieval system i
```

where `k` is a constant (default: 60) that controls how much weight is given to top-ranked results versus lower-ranked ones.

Documents that appear in both lists get a combined score, pushing truly relevant results to the top. Documents that only appear in one list still surface, but at lower priority.

## Search Modes

Configured via `knowledge.search_mode` in `langgraph-config.yaml`:

| Mode | Description |
|---|---|
| `hybrid` | Vector + BM25 with RRF fusion (default, recommended) |
| `vector` | Vector similarity only |
| `keyword` | FTS5 keyword search only |

## Contextual Enrichment

When `knowledge.enrich_chunks` is enabled, each chunk is prepended with a contextual header before embedding. This is inspired by Anthropic's "contextual retrieval" technique.

For an advisory chunk, the enrichment step asks the LLM to produce 1-2 sentences that situate the chunk within its parent document:

```
Given a document and a chunk from it, write 1-2 sentences of context
to situate the chunk within the document for search retrieval.
```

The contextual header is prepended to the chunk text before it is sent to the embedding model. This gives the resulting vector a richer representation of the chunk's meaning in context.

## Why Hybrid Beats Vector-Only

Vector search excels at semantic similarity ("find advisories about privilege escalation") but struggles with:

- **Exact terms**: Searching for `"CVE-2024-3094"` or `"CVSS 9.8"` fails when the embedding does not capture the literal string
- **Acronyms and jargon**: BM25 catches `"RCE"`, `"SSRF"`, `"PMKID"` literally, while vector search may conflate them with related but different concepts
- **Rare tokens**: Embedding models have diminishing returns on rare or novel tokens that appear infrequently in training data

Keyword search excels at exact matching but struggles with:

- **Synonyms**: "privilege escalation" vs. "vertical access control bypass" vs. "root escalation"
- **Paraphrases**: "how to exploit this service" vs. "vulnerability exploitation techniques"
- **Conceptual queries**: "latest wireless attack techniques" has no single keyword to match

RRF fusion captures the strengths of both. In practice, hybrid retrieval consistently outperforms either component alone on the mixed workloads protoPen handles -- from precise CVE lookups to broad threat intelligence queries.

## Data Flow

```
User query
    │
    ├──► Embed query ──► sqlite-vec KNN ──► ranked list A
    │
    ├──► FTS5 BM25 match ──► ranked list B
    │
    └──► RRF fusion (list A, list B) ──► merged results ──► top-k returned
```

The KnowledgeMiddleware in the LangGraph pipeline automatically searches on every turn and injects relevant results into the system prompt as "Security Context", giving the agent access to stored knowledge without explicit tool calls.
