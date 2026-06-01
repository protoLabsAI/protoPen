---
outline: deep
---

# Explanation

Background knowledge and design rationale for protoPen's architecture and subsystems.

- **[Architecture](./architecture.md)** -- System architecture: backends, subagents, tool layer, engagement lifecycle, observability.
- **[The Control Stack](./control-stack.md)** -- How goals, workflows, playbooks, subagents, and skills relate -- and when to reach for which.
- **[Knowledge Search](./knowledge-search.md)** -- Hybrid search with SQLite, sqlite-vec, FTS5, and Reciprocal Rank Fusion.
- **[Auto-Ingestion](./auto-ingestion.md)** -- How tool output is automatically parsed and stored in the target intelligence database.
- **[Security Model](./security-model.md)** -- Risk gating, guardrails, audit trail, Docker hardening, and alerting.
