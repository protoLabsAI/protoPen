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
from graph.middleware.timeout import ToolTimeoutMiddleware
from graph.subagents.config import SUBAGENT_REGISTRY
from tools.lg_tools import get_all_tools, get_combined_tools, get_engagement_manager


def _resolve_aux_model(config, specific: str = "") -> str | None:
    """Pick the model for an auxiliary (non-reasoning) call: a specific override,
    else the shared ``routing.aux_model`` fast alias, else None (→ main model)."""
    for candidate in (specific, getattr(config, "aux_model", "")):
        cleaned = (candidate or "").strip()
        if cleaned:
            return cleaned
    return None


def _parse_compaction_trigger(spec: str):
    """Parse 'fraction:0.8' / 'tokens:120000' / 'messages:80' → langchain trigger tuple."""
    try:
        kind, _, val = spec.partition(":")
        kind = kind.strip().lower()
        if kind == "fraction":
            return ("fraction", float(val))
        if kind in ("tokens", "messages"):
            return (kind, int(val))
    except (ValueError, AttributeError):
        pass
    return ("fraction", 0.8)


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

    if config.compaction_enabled:
        from langchain.agents.middleware import SummarizationMiddleware

        summ_model = create_llm(config, model_name=_resolve_aux_model(config, config.compaction_model))
        keep = ("messages", config.compaction_keep_messages)
        try:
            mw = SummarizationMiddleware(
                model=summ_model,
                trigger=_parse_compaction_trigger(config.compaction_trigger),
                keep=keep,
            )
        except ValueError:
            # "fraction:"/"tokens:" triggers need the model's context-window
            # profile, which custom gateway aliases don't expose — langchain
            # raises here. Fall back to a message-count trigger so compaction
            # still runs instead of taking down the whole graph at load.
            import logging

            fallback = max(config.compaction_keep_messages * 3, 60)
            logging.getLogger(__name__).warning(
                "[compaction] trigger %r needs a model profile that %r lacks; falling back to messages:%d",
                config.compaction_trigger,
                config.model_name,
                fallback,
            )
            mw = SummarizationMiddleware(model=summ_model, trigger=("messages", fallback), keep=keep)
        middleware.append(mw)

    middleware.append(MessageCaptureMiddleware())

    # Last in the chain = innermost = wraps tool execution most tightly, so it
    # times the tool itself. Enforcement (first) still blocks before this runs.
    if config.tool_timeout_middleware:
        middleware.append(ToolTimeoutMiddleware(timeout_seconds=config.tool_timeout_seconds))

    return middleware


def _build_task_tool(config: LangGraphConfig, all_tools: list[BaseTool]):
    """Build the task tool for subagent delegation.

    This is a simplified version of DeerFlow's task tool — it runs
    subagents synchronously (blocking) since our Gradio UI doesn't
    support async streaming of subagent progress yet.
    """
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

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

        # Subagent model: per-subagent override → routing.aux_model → main model.
        sub_llm = create_llm(config, model_name=_resolve_aux_model(config, getattr(sub_config, "model", "")))

        # Create subagent graph
        subagent = create_react_agent(
            model=sub_llm,
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

    # Subagent model: per-subagent override → routing.aux_model → main model.
    sub_llm = create_llm(config, model_name=_resolve_aux_model(config, getattr(sub_config, "model", "")))
    tool_map = {t.name: t for t in get_combined_tools(knowledge_store)}
    sub_tools = [tool_map[name] for name in sub_config.tools if name in tool_map]
    if not sub_tools:
        raise ValueError(f"No tools available for subagent '{subagent_type}'.")
    subagent = create_react_agent(
        model=sub_llm,
        tools=sub_tools,
        prompt=build_subagent_prompt(subagent_type),
    )
    try:
        result = await subagent.ainvoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"recursion_limit": sub_config.max_turns},
        )
    except Exception as e:
        raise ValueError(f"Subagent '{subagent_type}' failed: {e}") from e
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


async def run_manual_workflow(
    config: LangGraphConfig,
    registry,
    *,
    knowledge_store=None,
    scheduler=None,
    name: str,
    inputs: dict | None = None,
) -> dict:
    """Run a saved workflow recipe outside the lead agent's tool (operator UI).

    Returns the engine result ``{"output", "steps", "failed"}``. Raises
    ``ValueError`` for an unknown / invalid recipe or missing required inputs.
    """
    from graph.workflows.engine import execute_workflow, resolve_inputs, validate_recipe

    if registry is None:
        raise ValueError("workflows are not enabled")
    recipe = registry.get(name)
    if recipe is None:
        raise ValueError(f"no workflow named {name!r}")
    errs = validate_recipe(recipe, known_subagents=set(SUBAGENT_REGISTRY))
    if errs:
        raise ValueError("invalid workflow: " + "; ".join(errs))
    resolved, missing = resolve_inputs(recipe, inputs or {})
    if missing:
        raise ValueError(f"missing required input(s): {', '.join(missing)}")

    async def _run_step(subagent_type: str, prompt: str, step_id: str) -> str:
        return await run_manual_subagent(
            config,
            knowledge_store=knowledge_store,
            scheduler=scheduler,
            description=f"workflow {name}:{step_id}",
            prompt=prompt,
            subagent_type=subagent_type,
        )

    return await execute_workflow(
        recipe,
        resolved,
        run_step=_run_step,
        max_concurrency=max(1, getattr(config, "subagent_max_concurrency", 3)),
    )


def _build_workflow_tools(config: LangGraphConfig, knowledge_store, workflow_registry):
    """Workflow tools (ADR 0002) for the lead agent: run_workflow runs a saved
    declarative recipe over subagents (each step delegates to run_manual_subagent;
    outputs thread into dependents), and save_workflow persists a new recipe (the
    closed emission loop). Lead-agent only, so workflows can't recurse."""
    from langchain_core.tools import tool

    from graph.workflows.engine import execute_workflow, resolve_inputs, validate_recipe

    max_concurrency = max(1, getattr(config, "subagent_max_concurrency", 3))

    @tool
    async def run_workflow(name: str = "", inputs: dict | None = None) -> str:
        """Run a saved multi-step workflow recipe over subagents.

        Workflows chain subagent steps (some in parallel), threading each step's
        output into the next — for repeatable jobs like research→synthesize→write.
        Pass an empty ``name`` to list the available workflows and their inputs.

        Args:
            name: The workflow name (see the list with an empty name).
            inputs: Mapping of the workflow's declared inputs to values.
        """
        if not name.strip():
            summaries = workflow_registry.list()
            if not summaries:
                return "No workflows are available."
            lines = ["Available workflows:"]
            for s in summaries:
                req = [i["name"] for i in s["inputs"] if i["required"]]
                lines.append(f"- {s['name']}: {s['description']} (inputs: {', '.join(req) or 'none required'})")
            return "\n".join(lines)
        recipe = workflow_registry.get(name)
        if recipe is None:
            return f"No workflow named {name!r}. Available: {', '.join(workflow_registry.names()) or '(none)'}."
        errs = validate_recipe(recipe, known_subagents=set(SUBAGENT_REGISTRY))
        if errs:
            return f"Workflow {name!r} is invalid: " + "; ".join(errs)
        resolved, missing = resolve_inputs(recipe, inputs or {})
        if missing:
            return f"Workflow {name!r} needs input(s): {', '.join(missing)}."

        async def _run_step(subagent_type: str, prompt: str, step_id: str) -> str:
            return await run_manual_subagent(
                config,
                knowledge_store=knowledge_store,
                description=f"workflow {name}:{step_id}",
                prompt=prompt,
                subagent_type=subagent_type,
            )

        result = await execute_workflow(recipe, resolved, run_step=_run_step, max_concurrency=max_concurrency)
        return result["output"]

    @tool
    async def save_workflow(
        name: str,
        description: str,
        steps: list[dict],
        inputs: list[dict] | None = None,
        output: str = "",
    ) -> str:
        """Save a reusable multi-step workflow so it can be re-run later with
        run_workflow — capture a multi-step subagent process you just worked out
        (the closed loop). Saving overwrites any existing workflow of the same name.

        Args:
            name: Unique slug for the workflow.
            description: One-line summary of what it does.
            steps: Ordered list of step objects, each with ``id`` (str),
                ``subagent`` (a configured subagent type), ``prompt`` (str, may
                reference {{inputs.x}} and {{steps.<id>.output}}), and optional
                ``depends_on`` (list of earlier step ids that run first —
                independent steps run in parallel).
            inputs: Optional list of {name, required?, default?} the workflow
                accepts (referenced as {{inputs.name}} in prompts).
            output: Optional final-output template (default = last step's output).
        """
        recipe: dict = {"name": name, "description": description, "version": 1, "steps": steps}
        if inputs:
            recipe["inputs"] = inputs
        if output:
            recipe["output"] = output
        errs = validate_recipe(recipe, known_subagents=set(SUBAGENT_REGISTRY))
        if errs:
            return "Cannot save — the workflow is invalid: " + "; ".join(errs)
        try:
            path = workflow_registry.save(recipe)
        except Exception as exc:  # noqa: BLE001 — readable tool error
            return f"Error saving workflow: {exc}"
        return f"Saved workflow {name!r} ({len(steps)} step(s)) to {path}. Run it with run_workflow({name!r}, ...)."

    return [run_workflow, save_workflow]


def create_researcher_graph(
    config: LangGraphConfig,
    knowledge_store=None,
    include_subagents: bool = True,
    sitrep: str = "",
    checkpointer=None,
    workflow_registry=None,
):
    """Create the main protoPen LangGraph agent.

    ``checkpointer`` persists conversation state per ``thread_id``: pass one so
    multi-turn chats keep their history (the agent sees prior turns instead of
    starting fresh each message). Compaction middleware summarizes the old part
    of that history near the context limit. A checkpointer set only in the invoke
    ``config`` is ignored by LangGraph — it must be bound here at compile time.

    Returns a compiled graph that can be invoked with:
        graph.ainvoke({"messages": [HumanMessage(content="...")]},
                      config={"configurable": {"thread_id": "..."}})
    """
    llm = create_llm(config)

    # Build tools — combined research + pentest
    all_tools = get_combined_tools(knowledge_store)

    # Add task tool if subagents enabled
    if include_subagents:
        task_tool = _build_task_tool(config, all_tools)
        all_tools.append(task_tool)

        # Reusable declarative workflows (ADR 0002) — only the lead agent gets
        # run_workflow; subagents don't, so workflows can't recurse.
        if getattr(config, "workflows_enabled", False) and workflow_registry is not None:
            all_tools.extend(_build_workflow_tools(config, knowledge_store, workflow_registry))

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
        checkpointer=checkpointer,
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
