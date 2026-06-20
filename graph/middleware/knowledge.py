"""KnowledgeMiddleware — retrieve knowledge + learned skills before each LLM call.

``before_model`` writes the combined context (retrieved knowledge + matching
``<learned_skills>``) to ``state["context"]``; PromptCacheMiddleware delivers it
into the system message at the model-call boundary (the static system prompt
can't read state, so this is how it reaches the LLM). Works with knowledge,
skills, or both — and no-ops cleanly when neither yields a hit.
"""

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import HumanMessage

_SKILLS_MAX_TOKENS = 1500  # budget for the <learned_skills> block (chars // 4)
_SKILLS_CONTEXT_CHARS = 2000  # chars of the latest message used as the skills query


class KnowledgeMiddleware(AgentMiddleware):
    """Inject knowledge-store context + relevant learned skills before each LLM call.

    Uses hybrid search (vector + BM25 keyword via RRF) for knowledge; FTS5 for
    skills. A None knowledge_store is fine — skills still work on a KB-less agent.
    """

    def __init__(
        self,
        knowledge_store=None,
        top_k: int = 10,
        search_mode: str = "hybrid",
        skills_index=None,
        progressive_skills: bool = True,
    ):
        super().__init__()
        self._store = knowledge_store
        self._top_k = top_k
        self._search_mode = search_mode
        self._skills_index = skills_index
        # Progressive disclosure (protopen-1hw.13): inject a name+description catalog
        # and let the agent load_skill bodies on demand, vs. the legacy full-body
        # top-k injection.
        self._progressive_skills = progressive_skills

    def _search(self, query: str) -> list[dict]:
        if self._search_mode == "hybrid" and hasattr(self._store, "hybrid_search"):
            return self._store.hybrid_search(query, k=self._top_k)
        return self._store.search(query, k=self._top_k)

    def _last_human(self, messages) -> str | None:
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage):
                return msg.content if isinstance(msg.content, str) else str(msg.content)
        return None

    def _format_learned_skills(self, skills) -> str:
        """Format retrieved skills as a <learned_skills> block, under a token budget."""
        if not skills:
            return ""

        def _tokens(text: str) -> int:
            return max(1, len(text) // 4)

        def _fmt(s) -> str:
            pt = (s.prompt_template or "")[:500]
            # Surface the skill's declared tools so the model knows which of its
            # (already-bound) tools this skill relies on — a relevance hint, not
            # a gate. See ADR 0005 (tool pollution / progressive disclosure).
            tools = getattr(s, "tools_used", ()) or ()
            tools_line = f"    <relevant_tools>{', '.join(tools)}</relevant_tools>\n" if tools else ""
            return (
                f'  <skill name="{s.name}">\n'
                f"    <description>{s.description}</description>\n"
                f"{tools_line}"
                f"    <prompt_template>{pt}</prompt_template>\n"
                f"  </skill>"
            )

        formatted = [_fmt(s) for s in sorted(skills, key=lambda s: s.score)]  # most relevant first
        while formatted:
            block = "<learned_skills>\n" + "\n".join(formatted) + "\n</learned_skills>"
            if _tokens(block) <= _SKILLS_MAX_TOKENS:
                return block
            formatted.pop()  # drop the least-relevant skill and retry
        return ""

    def _format_skill_catalog(self, query: str) -> str:
        """Progressive disclosure: a lightweight <available_skills> catalog (name +
        description) the agent scans, then pulls a full body via load_skill on demand.
        Lists the whole library when it fits the token budget; otherwise the top FTS
        matches for this turn. user_only skills are hidden (load via /skill)."""
        idx = self._skills_index
        try:
            catalog = [s for s in idx.all_skills() if not s.get("user_only")]
        except Exception:  # noqa: BLE001
            return ""
        if not catalog:
            return ""

        def _render(rows) -> str:
            lines = [f"  - {r['name']}: {(r.get('description') or '').strip()}" for r in rows]
            return (
                '<available_skills> (use load_skill("<name>") to get a skill\'s full '
                "instructions before applying it)\n" + "\n".join(lines) + "\n</available_skills>"
            )

        block = _render(catalog)
        if len(block) // 4 <= _SKILLS_MAX_TOKENS:
            return block
        # Library too big for the budget — fall back to the most relevant matches.
        try:
            ranked = self._skills_index.load_skills(query, k=12) if query else []
        except Exception:  # noqa: BLE001
            ranked = []
        rows = [{"name": s.name, "description": s.description} for s in ranked]
        block = _render(rows)
        while rows and len(block) // 4 > _SKILLS_MAX_TOKENS:
            rows.pop()
            block = _render(rows)
        return block if rows else ""

    def before_model(self, state, runtime) -> dict | None:
        """Stage retrieved knowledge + learned skills into state['context']."""
        messages = state.get("messages", [])
        if not messages:
            return None
        parts: list[str] = []

        # Learned skills. Progressive disclosure → a name+description catalog the
        # agent loads bodies from on demand; legacy → matched full bodies inline.
        if self._skills_index is not None:
            query = (self._last_human(messages) or "")[:_SKILLS_CONTEXT_CHARS]
            try:
                if self._progressive_skills:
                    block = self._format_skill_catalog(query)
                elif query:
                    block = self._format_learned_skills(self._skills_index.load_skills(query))
                else:
                    block = ""
                if block:
                    parts.append(block)
            except Exception:  # noqa: BLE001 — never break the turn on skill retrieval
                pass

        # Knowledge store hits.
        if self._store is not None:
            last_human = self._last_human(messages)
            if last_human:
                try:
                    results = self._search(last_human)
                except Exception:  # noqa: BLE001 — never break the turn on retrieval
                    results = []
                # Split semantic facts (ADR 0021) from research knowledge: facts
                # are authoritative memory *about the operator* and the model
                # should answer from them directly, not treat them as one more
                # research hit to weigh.
                facts = [r for r in results if r.get("table") == "facts"]
                other = [r for r in results if r.get("table") != "facts"]
                if facts:
                    fb = ["[Known facts about the operator — authoritative; recall and answer from these directly:]"]
                    for r in facts:
                        fb.append(f"- {(r.get('preview') or '')[:500]}")
                    parts.append("\n".join(fb))
                if other:
                    kn = ["[Relevant knowledge from previous research:]"]
                    for r in other:
                        preview = (r.get("preview") or "")[:500]
                        kn.append(f"- [{r.get('table')}:{r.get('source_id')}] {preview}")
                    parts.append("\n".join(kn))

        if not parts:
            return None
        return {"context": "\n\n".join(parts)}

    async def abefore_model(self, state, runtime) -> dict | None:
        return self.before_model(state, runtime)
