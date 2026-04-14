"""System prompt composer for protoPen LangGraph agent.

Composes the system prompt from:
1. SOUL.md content (identity, personality, values)
2. Security research skills (from skills/security-research/SKILL.md)
3. Subagent instructions (available types + delegation rules)
4. Dynamic research context (from KnowledgeMiddleware)
"""

from pathlib import Path
from typing import Union

from graph.subagents.config import SUBAGENT_REGISTRY


def _read_file(path: Union[str, Path]) -> str:
    """Read a file if it exists, return empty string otherwise."""
    p = Path(path)
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    return ""


def build_system_prompt(
    workspace: str = "/sandbox",
    include_subagents: bool = True,
    research_context: str = "",
    hardware_status: str = "",
) -> str:
    """Build the complete system prompt for the lead agent."""
    parts = []

    # 1. Identity from SOUL.md
    soul = _read_file(f"{workspace}/SOUL.md")
    if soul:
        parts.append(soul)
    else:
        parts.append(
            "# protoPen 🔒\n\n"
            "You are protoPen, an autonomous pen-testing and research agent built by protoLabs.\n"
            "You operate hardware-in-the-loop security assessments and conduct AI/ML research."
        )

    # 2. Hardware / network / engagement status (injected at boot)
    if hardware_status:
        parts.append(hardware_status)

    # 3. Skills
    skill = _read_file(f"{workspace}/skills/security-research/SKILL.md")
    if skill:
        parts.append(f"\n# Security Research Methodology\n\n{skill}")

    pentest_skill = _read_file(f"{workspace}/skills/pentest/SKILL.md")
    if pentest_skill:
        parts.append(f"\n{pentest_skill}")

    blue_team_skill = _read_file(f"{workspace}/skills/blue-team/SKILL.md")
    if blue_team_skill:
        parts.append(f"\n{blue_team_skill}")

    # 3. Subagent instructions
    if include_subagents:
        parts.append(_build_subagent_section())

    # 4. Dynamic security context (injected by KnowledgeMiddleware)
    if research_context:
        parts.append(f"\n# Security Context\n\n{research_context}")

    # 5. Guidelines
    parts.append("""
# Guidelines

- Think before acting. Break down complex tasks.
- For pentest tasks, delegate to subagents: Recon maps, Exploit attacks, Reporter writes.
- For threat intel tasks, delegate to subagents: Threat Scanner scans, Vuln Analyst reads, Intel Reporter synthesizes.
- For defensive tasks, delegate to subagents: Defender audits, Incident Responder investigates, Purple Team correlates.
- For container/K8s security tasks, delegate to the Defender subagent (container_audit tool).
- For WebSocket security testing, use websocket_test directly or delegate to the Exploit subagent.
- Always check engagement mode before executing actions on hardware.
- Log every finding in real time via the engagement tool.
- Rate threat severity: [critical / high / medium / low / info]
- Rate exploitability: [critical / high / medium / low]
- Always store important findings in security_memory.
- Reply directly with text for conversations. Use the task tool to delegate parallel work.
""")

    return "\n\n".join(parts)


def _build_subagent_section() -> str:
    """Build the subagent delegation instructions."""
    lines = [
        "# Subagent Delegation",
        "",
        "You can delegate tasks to specialized subagents using the `task` tool.",
        "Each subagent has focused tools and expertise:",
        "",
    ]

    for name, config in SUBAGENT_REGISTRY.items():
        lines.append(f"- **{name}**: {config.description}")
        lines.append(f"  Tools: {', '.join(config.tools)}")
        lines.append("")

    lines.extend([
        "**Rules:**",
        "- Delegate threat scanning/discovery to Threat Scanner",
        "- Delegate deep vulnerability analysis to Vuln Analyst",
        "- Delegate report writing/publishing to Intel Reporter",
        "- For simple questions, answer directly without delegation",
        "- Max 3 concurrent subagent tasks",
        "- Subagents cannot spawn further subagents",
    ])

    return "\n".join(lines)


def build_subagent_prompt(agent_name: str, workspace: str = "/sandbox") -> str:
    """Build system prompt for a specific subagent."""
    config = SUBAGENT_REGISTRY.get(agent_name)
    if not config:
        return "You are a security subagent. Complete the delegated task efficiently."
    return config.system_prompt
