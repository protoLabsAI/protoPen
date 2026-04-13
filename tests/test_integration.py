"""Integration smoke tests — tool registration, subagent wiring, prompt composition.

These tests verify that all pieces connect without requiring live hardware,
network access, or an LLM. They mock external deps and test the wiring.

Tests that need langchain_core (only installed in Docker) are skipped locally.
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

try:
    import langchain_core  # noqa: F401
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

needs_langchain = pytest.mark.skipif(not HAS_LANGCHAIN, reason="langchain_core not installed")


# ─── Tool Registration ────────────────────────────────────────────────────────

@needs_langchain
class TestToolRegistration:
    def test_get_research_tools_returns_list(self):
        from tools.lg_tools import get_research_tools
        tools = get_research_tools(knowledge_store=None)
        assert isinstance(tools, list)
        assert len(tools) >= 5
        names = [t.name for t in tools]
        assert "paper_reader" in names
        assert "huggingface" in names
        assert "github_trending" in names
        assert "browser" in names
        assert "lab_monitor" in names

    def test_get_pentest_tools_returns_list(self):
        from tools.lg_tools import get_pentest_tools
        tools = get_pentest_tools()
        assert isinstance(tools, list)
        assert len(tools) == 6
        names = [t.name for t in tools]
        assert "device_manager" in names
        assert "portapack" in names
        assert "flipper" in names
        assert "marauder" in names
        assert "blackarch" in names
        assert "engagement" in names

    def test_get_combined_tools_merges_both(self):
        from tools.lg_tools import get_combined_tools
        tools = get_combined_tools(knowledge_store=None)
        names = [t.name for t in tools]
        assert "paper_reader" in names
        assert "huggingface" in names
        assert "device_manager" in names
        assert "portapack" in names
        assert "flipper" in names
        assert "blackarch" in names
        assert "engagement" in names

    def test_backward_compat_get_all_tools(self):
        from tools.lg_tools import get_all_tools, get_research_tools
        assert get_all_tools is get_research_tools

    def test_all_tools_have_descriptions(self):
        from tools.lg_tools import get_combined_tools
        for t in get_combined_tools(knowledge_store=None):
            assert t.description, f"Tool {t.name} has no description"
            assert len(t.description) > 10, f"Tool {t.name} description too short"

    def test_all_tools_have_unique_names(self):
        from tools.lg_tools import get_combined_tools
        tools = get_combined_tools(knowledge_store=None)
        names = [t.name for t in tools]
        assert len(names) == len(set(names)), f"Duplicate tool names: {names}"


# ─── Subagent Registry ────────────────────────────────────────────────────────

class TestSubagentRegistry:
    def test_registry_has_six_agents(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        assert len(SUBAGENT_REGISTRY) == 6

    def test_research_subagents_present(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        assert "explorer" in SUBAGENT_REGISTRY
        assert "analyst" in SUBAGENT_REGISTRY
        assert "writer" in SUBAGENT_REGISTRY

    def test_pentest_subagents_present(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        assert "recon" in SUBAGENT_REGISTRY
        assert "exploit" in SUBAGENT_REGISTRY
        assert "reporter" in SUBAGENT_REGISTRY

    def test_all_subagents_have_tools(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        for name, config in SUBAGENT_REGISTRY.items():
            assert len(config.tools) > 0, f"Subagent {name} has no tools"

    def test_all_subagents_disallow_task(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        for name, config in SUBAGENT_REGISTRY.items():
            assert "task" in config.disallowed_tools, f"Subagent {name} can spawn sub-subagents"

    def test_recon_has_hardware_tools(self):
        from graph.subagents.config import RECON_CONFIG
        assert "portapack" in RECON_CONFIG.tools
        assert "flipper" in RECON_CONFIG.tools
        assert "marauder" in RECON_CONFIG.tools
        assert "blackarch" in RECON_CONFIG.tools
        assert "device_manager" in RECON_CONFIG.tools

    def test_exploit_has_hardware_tools(self):
        from graph.subagents.config import EXPLOIT_CONFIG
        assert "portapack" in EXPLOIT_CONFIG.tools
        assert "flipper" in EXPLOIT_CONFIG.tools
        assert "marauder" in EXPLOIT_CONFIG.tools

    def test_reporter_has_engagement(self):
        from graph.subagents.config import REPORTER_CONFIG
        assert "engagement" in REPORTER_CONFIG.tools

    def test_all_subagents_have_system_prompts(self):
        from graph.subagents.config import SUBAGENT_REGISTRY
        for name, config in SUBAGENT_REGISTRY.items():
            assert len(config.system_prompt) > 50, f"Subagent {name} has weak system prompt"

    @needs_langchain
    def test_subagent_tool_names_are_valid(self):
        """All tool names referenced by subagents should be real tools."""
        from graph.subagents.config import SUBAGENT_REGISTRY
        from tools.lg_tools import get_combined_tools
        valid_names = {t.name for t in get_combined_tools(knowledge_store=None)}
        # Also include tools that may only be available conditionally
        valid_names.update({"discord_feed", "rabbit_hole_bridge", "research_memory"})
        for name, config in SUBAGENT_REGISTRY.items():
            for tool_name in config.tools:
                assert tool_name in valid_names, (
                    f"Subagent {name} references unknown tool: {tool_name}"
                )


# ─── Prompt Composition ──────────────────────────────────────────────────────

class TestPromptComposition:
    def test_build_system_prompt_with_subagents(self):
        from graph.prompts import build_system_prompt
        prompt = build_system_prompt(
            workspace=str(Path(__file__).parent.parent),
            include_subagents=True,
        )
        assert "protoPen" in prompt
        assert "recon" in prompt.lower()
        assert "exploit" in prompt.lower()
        assert "reporter" in prompt.lower()
        assert "explorer" in prompt.lower()
        assert "analyst" in prompt.lower()
        assert "writer" in prompt.lower()

    def test_build_system_prompt_without_subagents(self):
        from graph.prompts import build_system_prompt
        prompt = build_system_prompt(
            workspace=str(Path(__file__).parent.parent),
            include_subagents=False,
        )
        assert "Subagent Delegation" not in prompt

    def test_build_system_prompt_loads_soul(self):
        from graph.prompts import build_system_prompt
        prompt = build_system_prompt(
            workspace=str(Path(__file__).parent.parent / "config"),
        )
        # SOUL.md lives in config/ — the function reads {workspace}/SOUL.md
        assert "protoPen" in prompt

    def test_build_subagent_prompt(self):
        from graph.prompts import build_subagent_prompt
        for agent_name in ["explorer", "analyst", "writer", "recon", "exploit", "reporter"]:
            prompt = build_subagent_prompt(agent_name)
            assert len(prompt) > 50, f"Subagent prompt for {agent_name} is too short"

    def test_build_subagent_prompt_unknown(self):
        from graph.prompts import build_subagent_prompt
        prompt = build_subagent_prompt("nonexistent")
        assert "research subagent" in prompt.lower()

    def test_pentest_skill_loaded_in_prompt(self):
        from graph.prompts import build_system_prompt
        prompt = build_system_prompt(
            workspace=str(Path(__file__).parent.parent),
            include_subagents=False,
        )
        assert "Passive Reconnaissance" in prompt or "Scope & Setup" in prompt


# ─── Pentest Singleton Init ──────────────────────────────────────────────────

@needs_langchain
class TestPentestSingletonInit:
    def test_init_loads_config(self):
        """_init_pentest_singletons should create DeviceManager and friends."""
        import tools.lg_tools as lg
        lg._device_manager = None
        lg._engagement = None
        lg._blackarch = None
        lg._portapack = None
        lg._flipper = None
        lg._marauder = None

        lg._init_pentest_singletons()

        assert lg._device_manager is not None
        assert lg._engagement is not None
        assert lg._blackarch is not None

    def test_init_idempotent(self):
        """Calling _init_pentest_singletons twice should not recreate objects."""
        import tools.lg_tools as lg
        lg._device_manager = None
        lg._init_pentest_singletons()
        dm1 = lg._device_manager
        lg._init_pentest_singletons()
        assert lg._device_manager is dm1


# ─── Config File Integrity ────────────────────────────────────────────────────

class TestConfigIntegrity:
    def test_engagement_config_loads(self):
        import json
        with open("config/engagement-config.json") as f:
            config = json.load(f)
        assert "devices" in config
        assert "engagement" in config
        assert "portapack" in config["devices"]
        assert "flipper" in config["devices"]

    def test_soul_md_exists(self):
        assert Path("config/SOUL.md").exists()
        content = Path("config/SOUL.md").read_text()
        assert "protoPen" in content

    def test_pentest_skill_exists(self):
        assert Path("skills/pentest/SKILL.md").exists()
        content = Path("skills/pentest/SKILL.md").read_text()
        assert "Passive Reconnaissance" in content

    def test_security_research_skill_exists(self):
        assert Path("skills/security-research/SKILL.md").exists()
