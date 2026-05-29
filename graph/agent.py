"""Main LangGraph agent for protoPen.

Builds the research agent graph with middleware, tools, and subagent support.
Uses langchain's create_agent() with AgentMiddleware for the DeerFlow pattern.
"""

from typing import Any

from langchain.agents import create_agent
from langchain_core.tools import BaseTool

from graph.config import LangGraphConfig
from graph.llm import create_llm
from graph.prompts import build_system_prompt, build_subagent_prompt
from graph.middleware.audit import AuditMiddleware
from graph.middleware.enforcement import EnforcementMiddleware
from graph.middleware.knowledge import KnowledgeMiddleware
from graph.middleware.knowledge_ingest import KnowledgeIngestMiddleware
from graph.middleware.memory import MemoryMiddleware
from graph.middleware.message_capture import MessageCaptureMiddleware
from graph.subagents.config import SUBAGENT_REGISTRY
from tools.lg_tools import get_all_tools, get_combined_tools, get_engagement_manager


def _build_middleware(config: LangGraphConfig, knowledge_store=None):
    """Build the ordered middleware chain.

    Enforcement runs first — blocks disallowed tool calls before any other
    middleware (audit, knowledge enrichment, etc.) can process them.
    """
    middleware = []

    if config.enforcement_middleware:
        from enforcement.scope import ScopeValidator
        from enforcement.phases import KillChainPhase

        mgr = get_engagement_manager()
        max_phase = None
        if config.enforcement_max_phase:
            max_phase = KillChainPhase[config.enforcement_max_phase.upper()]
        middleware.append(EnforcementMiddleware(mgr, max_phase=max_phase))

    if config.knowledge_middleware and knowledge_store:
        middleware.append(
            KnowledgeMiddleware(
                knowledge_store,
                top_k=config.knowledge_top_k,
                search_mode=config.knowledge_search_mode,
            )
        )

    if config.knowledge_ingest_middleware and knowledge_store:
        middleware.append(KnowledgeIngestMiddleware(knowledge_store))

    if config.audit_middleware:
        middleware.append(AuditMiddleware())

    if config.memory_middleware and knowledge_store:
        middleware.append(MemoryMiddleware(knowledge_store))

    middleware.append(MessageCaptureMiddleware())

    return middleware


def _build_task_tool(config: LangGraphConfig, all_tools: list[BaseTool]):
    """Build the task tool for subagent delegation.

    This is a simplified version of DeerFlow's task tool — it runs
    subagents synchronously (blocking) since our Gradio UI doesn't
    support async streaming of subagent progress yet.
    """
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    llm = create_llm(config)

    # Build tool registries for each subagent
    tool_map = {t.name: t for t in all_tools}

    @tool
    async def task(
        description: str,
        prompt: str,
        subagent_type: str = "threat_scanner",
    ) -> str:
        """Delegate a task to a specialized subagent.

        Available subagents:
        - threat_scanner: Scans CVE feeds, security RSS, GitHub for new threats
        - vuln_analyst: Deep-reads advisories and PoCs, correlates with target intel
        - intel_reporter: Synthesizes threat intel reports, publishes to Discord

        Args:
            description: Short description of what this task will accomplish
            prompt: Detailed instructions for the subagent
            subagent_type: Which subagent to use (threat_scanner, vuln_analyst, intel_reporter)
        """
        sub_config = SUBAGENT_REGISTRY.get(subagent_type)
        if not sub_config:
            available = ", ".join(SUBAGENT_REGISTRY.keys())
            return f"Error: Unknown subagent '{subagent_type}'. Available: {available}"

        # Filter tools for this subagent
        sub_tools = [tool_map[name] for name in sub_config.tools if name in tool_map]

        if not sub_tools:
            return f"Error: No tools available for subagent '{subagent_type}'."

        # Create subagent graph
        subagent = create_react_agent(
            model=llm,
            tools=sub_tools,
            prompt=build_subagent_prompt(subagent_type),
        )

        # Run subagent
        try:
            result = await subagent.ainvoke(
                {"messages": [{"role": "user", "content": prompt}]},
                config={"recursion_limit": sub_config.max_turns},
            )

            # Extract the last AI message as the result
            messages = result.get("messages", [])
            for msg in reversed(messages):
                if hasattr(msg, "content") and msg.content:
                    content = msg.content if isinstance(msg.content, str) else str(msg.content)
                    if content and not content.startswith("Error"):
                        return f"[{subagent_type} completed: {description}]\n\n{content}"

            return f"[{subagent_type} completed: {description}] — no output produced."
        except Exception as e:
            return f"Error: Subagent '{subagent_type}' failed: {e}"

    return task


async def run_manual_subagent(
    config: LangGraphConfig,
    knowledge_store=None,
    scheduler=None,
    *,
    description: str,
    prompt: str,
    subagent_type: str = "threat_scanner",
    emit_skill: bool = False,
) -> str:
    """Run a single subagent outside the lead agent's ``task`` tool.

    Used by the React operator console's manual launch. Mirrors
    ``_build_task_tool``'s runner: build the subagent from SUBAGENT_REGISTRY +
    create_react_agent and run it. ``scheduler`` / ``emit_skill`` are accepted
    for operator-API parity but unused in protoPen.
    """
    from langgraph.prebuilt import create_react_agent

    if not prompt or not prompt.strip():
        raise ValueError("prompt is required")
    sub_config = SUBAGENT_REGISTRY.get(subagent_type)
    if not sub_config:
        available = ", ".join(SUBAGENT_REGISTRY.keys())
        raise ValueError(f"Unknown subagent '{subagent_type}'. Available: {available}")

    llm = create_llm(config)
    tool_map = {t.name: t for t in get_combined_tools(knowledge_store)}
    sub_tools = [tool_map[name] for name in sub_config.tools if name in tool_map]
    subagent = create_react_agent(
        model=llm,
        tools=sub_tools,
        prompt=build_subagent_prompt(subagent_type),
    )
    result = await subagent.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
        config={"recursion_limit": sub_config.max_turns},
    )
    for msg in reversed(result.get("messages", [])):
        content = getattr(msg, "content", None)
        if content:
            text = content if isinstance(content, str) else str(content)
            if text:
                return f"[{subagent_type} completed: {description}]\n\n{text}"
    return f"[{subagent_type} completed: {description}] — no output produced."


async def run_manual_subagent_batch(
    config: LangGraphConfig,
    knowledge_store=None,
    scheduler=None,
    *,
    tasks: list[dict],
) -> str:
    """Run independent manual subagent jobs concurrently (operator console)."""
    import asyncio

    if not isinstance(tasks, list) or not tasks:
        raise ValueError("tasks must be a non-empty list")
    sem = asyncio.Semaphore(max(1, getattr(config, "subagent_max_concurrency", 3)))

    async def _one(spec: dict) -> str:
        if not isinstance(spec, dict):
            return f"Error: each task must be an object, got {type(spec).__name__}."
        desc = spec.get("description") or "(no description)"
        prm = spec.get("prompt")
        if not prm:
            return f"Error: task '{desc}' is missing 'prompt'."
        async with sem:
            try:
                return await run_manual_subagent(
                    config,
                    knowledge_store=knowledge_store,
                    scheduler=scheduler,
                    description=desc,
                    prompt=prm,
                    subagent_type=spec.get("type") or spec.get("subagent_type", "threat_scanner"),
                )
            except Exception as e:
                return f"Error: task '{desc}' failed: {e}"

    results = await asyncio.gather(*[_one(t) for t in tasks])
    return "\n\n---\n\n".join(results)


def create_researcher_graph(
    config: LangGraphConfig,
    knowledge_store=None,
    include_subagents: bool = True,
    sitrep: str = "",
):
    """Create the main protoPen LangGraph agent.

    Returns a compiled graph that can be invoked with:
        graph.ainvoke({"messages": [HumanMessage(content="...")]})
    """
    llm = create_llm(config)

    # Build tools — combined research + pentest
    all_tools = get_combined_tools(knowledge_store)

    # Add task tool if subagents enabled
    if include_subagents:
        task_tool = _build_task_tool(config, all_tools)
        all_tools.append(task_tool)

    # Build middleware
    middleware = _build_middleware(config, knowledge_store)

    # Build system prompt
    system_prompt = build_system_prompt(
        include_subagents=include_subagents,
        hardware_status=sitrep,
    )

    # Create agent with middleware (DeerFlow pattern)
    # Note: state_schema omitted — create_agent manages its own AgentState.
    # Custom state (research_context, findings) flows via system prompt + tool results.
    agent = create_agent(
        model=llm,
        tools=all_tools,
        middleware=middleware,
        system_prompt=system_prompt,
    )

    return agent


def create_simple_agent(config: LangGraphConfig, knowledge_store=None):
    """Create a simple agent without subagents (for debugging/testing).

    Uses create_react_agent from langgraph.prebuilt — simpler but no middleware.
    """
    from langgraph.prebuilt import create_react_agent

    llm = create_llm(config)
    all_tools = get_all_tools(knowledge_store)

    system_prompt = build_system_prompt(include_subagents=False)

    return create_react_agent(
        model=llm,
        tools=all_tools,
        prompt=system_prompt,
    )
