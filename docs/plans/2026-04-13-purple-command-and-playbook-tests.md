# `/purple` Command & Playbook Integration Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `/purple` chat command (last Phase 5 item) and validate playbooks end-to-end through integration tests.

**Architecture:** `/purple <scope>` is a chat command in server.py that loads the `purple_team_exercise` playbook, runs it via the playbook runner with tool dispatch, and returns a formatted ATT&CK coverage report. Playbook integration tests validate the runner+loader+schema pipeline with mocked tool dispatch.

**Tech Stack:** Python, pytest, asyncio, YAML playbooks

---

### Task 1: Playbook integration tests

**Files:**

- Create: `tests/test_playbook_integration.py`
- Read: `playbooks/runner.py`, `playbooks/loader.py`, `playbooks/schema.py`
- Read: `playbooks/library/purple_team_exercise.yaml`

- [ ] **Step 1: Write test for playbook loader**

```python
"""Tests for the playbook system — loader, runner, schema integration."""
import pytest
from playbooks.loader import load_playbook, list_playbooks
from playbooks.schema import Playbook, StepStatus


class TestPlaybookLoader:
    def test_list_playbooks_returns_all(self):
        names = list_playbooks()
        assert len(names) >= 6
        assert "full_recon" in names
        assert "purple_team_exercise" in names
        assert "defensive_assessment" in names
        assert "incident_response" in names

    def test_load_purple_team_exercise(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert pb.name == "Purple Team Exercise"
        assert len(pb.steps) == 9
        assert all(s.status == StepStatus.PENDING for s in pb.steps)

    def test_load_with_variable_substitution(self):
        pb = load_playbook("purple_team_exercise", {"target": "192.168.4.0/24"})
        nmap_step = pb.steps[0]
        assert nmap_step.params.get("target") == "192.168.4.0/24"

    def test_load_nonexistent_playbook(self):
        with pytest.raises(FileNotFoundError):
            load_playbook("does_not_exist")

    def test_load_defensive_assessment(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert len(pb.steps) >= 5

    def test_load_incident_response(self):
        pb = load_playbook("incident_response", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert len(pb.steps) >= 4
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_playbook_integration.py::TestPlaybookLoader -v`
Expected: All PASS (these are pure loader tests, no mocking needed)

- [ ] **Step 3: Write test for playbook runner with mocked dispatch**

Add to the same file:

```python
from playbooks.runner import run_playbook


class TestPlaybookRunner:
    @pytest.mark.asyncio
    async def test_run_purple_team_all_succeed(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        call_log = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((tool, action))
            if tool == "purple_team" and action == "coverage_matrix":
                return '{"matrix": [], "summary": {"detection_rate": 0.75}}'
            if tool == "purple_team" and action == "exercise_report":
                return '{"rating": "NEEDS IMPROVEMENT", "detection_rate": 0.75}'
            return '{"status": "ok", "results": []}'

        await run_playbook(pb, mock_dispatch)
        assert pb.completed
        assert len(call_log) == 9
        tools_called = [t for t, a in call_log]
        assert "blackarch" in tools_called
        assert "cis_audit" in tools_called
        assert "purple_team" in tools_called

    @pytest.mark.asyncio
    async def test_run_with_step_failure_continues(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def failing_dispatch(tool: str, action: str, params: dict) -> str:
            if action == "nmap_scan":
                raise RuntimeError("Connection refused")
            return '{"status": "ok"}'

        await run_playbook(pb, failing_dispatch)
        # nmap step should be FAILED, rest should still run (on_fail: continue)
        assert pb.steps[0].status == StepStatus.FAILED
        assert any(s.status == StepStatus.COMPLETED for s in pb.steps[1:])

    @pytest.mark.asyncio
    async def test_run_defensive_assessment(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        call_log = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((tool, action))
            return '{"checks": [], "passed": true}'

        await run_playbook(pb, mock_dispatch)
        assert pb.completed
        assert len(call_log) >= 5

    @pytest.mark.asyncio
    async def test_on_step_complete_callback(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        completed_steps = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            return '{"ok": true}'

        def on_complete(step):
            completed_steps.append(step.name)

        await run_playbook(pb, mock_dispatch, on_step_complete=on_complete)
        assert len(completed_steps) == len(pb.steps)

    @pytest.mark.asyncio
    async def test_progress_tracking(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        assert pb.progress == 0.0

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            return '{"ok": true}'

        await run_playbook(pb, mock_dispatch)
        assert pb.progress == 1.0
```

- [ ] **Step 4: Run all playbook tests**

Run: `python3 -m pytest tests/test_playbook_integration.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_playbook_integration.py
git commit -m "test: playbook integration tests — loader, runner, all 3 blue-team playbooks"
```

---

### Task 2: `/purple` command handler

**Files:**

- Modify: `server.py` (add to `_HELP_TEXT`, add `_handle_purple_command`, add dispatch in `_handle_command`)
- Read: `playbooks/loader.py`, `playbooks/runner.py`

- [ ] **Step 1: Add `/purple` to help text and command dispatch**

In `server.py`, add to `_HELP_TEXT` table:

```
| `/purple <scope>` | Run a purple team exercise against the given scope |
```

Add to `_handle_command` after the last `elif`:

```python
    elif cmd == "purple":
        return await _handle_purple_command(args, session_id)
```

- [ ] **Step 2: Implement `_handle_purple_command`**

Add this function near the other `_handle_*` functions:

```python
async def _handle_purple_command(args: str, session_id: str) -> list[dict[str, Any]]:
    """Run a purple team exercise via the playbook runner."""
    scope = args.strip()
    if not scope:
        return _msg(
            "**Usage:** `/purple <scope>`\n\n"
            "Example: `/purple 192.168.4.0/24`\n\n"
            "Runs the purple team exercise playbook: red team recon → "
            "blue team defensive checks → ATT&CK coverage matrix."
        )

    from playbooks.loader import load_playbook
    from playbooks.runner import run_playbook
    from playbooks.schema import StepStatus

    try:
        pb = load_playbook("purple_team_exercise", {
            "target": scope,
            "exercise_name": f"purple-{session_id[:8]}",
        })
    except FileNotFoundError:
        return _msg("❌ Purple team exercise playbook not found.")

    progress_lines = [f"## 🟣 Purple Team Exercise\n**Scope:** `{scope}`\n"]

    def on_step_complete(step):
        icon = "✅" if step.status == StepStatus.COMPLETED else "❌"
        progress_lines.append(f"{icon} **{step.name}** ({step.tool}.{step.action})")

    # Build dispatch function from registered tools
    async def _dispatch(tool_name: str, action: str, params: dict) -> str:
        if _BACKEND == "langgraph" and _graph is not None:
            # Route through the agent so enforcement + audit middleware apply
            prompt = (
                f"Run the {tool_name} tool with action={action} "
                f"and parameters: {json.dumps(params)}. "
                f"Return only the raw tool output."
            )
            results = await _chat_langgraph(prompt, session_id)
            return results[-1].get("content", "") if results else ""
        else:
            # Direct tool dispatch fallback
            from tools.lg_tools import get_pentest_tools, get_combined_tools
            all_tools = get_combined_tools()
            for t in all_tools:
                if t.name == tool_name:
                    return await t.ainvoke({"action": action, **params})
            return f"Error: Tool '{tool_name}' not found"

    await run_playbook(pb, _dispatch, on_step_complete=on_step_complete)

    # Build summary
    completed = sum(1 for s in pb.steps if s.status == StepStatus.COMPLETED)
    failed = sum(1 for s in pb.steps if s.status == StepStatus.FAILED)
    total = len(pb.steps)

    progress_lines.append(f"\n**Results:** {completed}/{total} steps completed, {failed} failed")
    progress_lines.append(f"**Progress:** {pb.progress:.0%}")

    # Extract coverage report from the last step's output if available
    report_step = next(
        (s for s in reversed(pb.steps)
         if s.tool == "purple_team" and s.action == "exercise_report"
         and s.status == StepStatus.COMPLETED),
        None,
    )
    if report_step and report_step.output:
        try:
            report = json.loads(report_step.output)
            rate = report.get("detection_rate", 0)
            rating = report.get("rating", "UNKNOWN")
            progress_lines.append(f"\n### ATT&CK Coverage")
            progress_lines.append(f"**Rating:** {rating} ({rate:.0%} detection rate)")
            if report.get("critical_findings"):
                progress_lines.append(f"**Critical gaps:** {len(report['critical_findings'])}")
        except (json.JSONDecodeError, TypeError):
            progress_lines.append(f"\n### Raw Report Output\n```\n{report_step.output[:2000]}\n```")

    return _msg("\n".join(progress_lines))
```

- [ ] **Step 3: Syntax check**

Run: `python3 -c "import ast; ast.parse(open('server.py').read()); print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add server.py
git commit -m "feat: /purple chat command — runs purple team exercise playbook"
```

---

### Task 3: `/purple` command tests

**Files:**

- Create: `tests/test_purple_command.py`
- Read: `server.py`

- [ ] **Step 1: Write tests for the /purple command**

```python
"""Tests for the /purple chat command."""
import sys
from types import ModuleType
from unittest.mock import AsyncMock, patch, MagicMock
import json
import pytest

# Stub langchain if not installed locally
if "langchain_core" not in sys.modules:
    _lc_core = ModuleType("langchain_core")
    _lc_core.__path__ = []
    _lc_core_tools = ModuleType("langchain_core.tools")
    _lc_core_tools.tool = lambda f: f
    _lc_core.tools = _lc_core_tools
    _lc_core_msgs = ModuleType("langchain_core.messages")
    class _ToolMessage:
        def __init__(self, content="", tool_call_id="", **kw):
            self.content = content
            self.tool_call_id = tool_call_id
    _lc_core_msgs.ToolMessage = _ToolMessage
    _lc_core.messages = _lc_core_msgs
    sys.modules["langchain_core"] = _lc_core
    sys.modules["langchain_core.tools"] = _lc_core_tools
    sys.modules["langchain_core.messages"] = _lc_core_msgs


class TestPurpleCommandParsing:
    """Test /purple argument parsing without running the full server."""

    @pytest.mark.asyncio
    async def test_no_args_shows_usage(self):
        from server import _handle_purple_command
        result = await _handle_purple_command("", "test-session")
        assert len(result) == 1
        assert "Usage" in result[0]["content"]

    @pytest.mark.asyncio
    async def test_whitespace_only_shows_usage(self):
        from server import _handle_purple_command
        result = await _handle_purple_command("   ", "test-session")
        assert "Usage" in result[0]["content"]


class TestPurpleCommandExecution:
    @pytest.mark.asyncio
    async def test_runs_playbook_and_returns_report(self):
        from server import _handle_purple_command

        mock_results = [{"role": "assistant", "content": '{"status":"ok"}'}]

        with patch("server._BACKEND", "langgraph"), \
             patch("server._graph", MagicMock()), \
             patch("server._chat_langgraph", AsyncMock(return_value=mock_results)):
            result = await _handle_purple_command("192.168.4.0/24", "test-session")

        content = result[0]["content"]
        assert "Purple Team Exercise" in content
        assert "192.168.4.0/24" in content
        assert "Results:" in content

    @pytest.mark.asyncio
    async def test_missing_playbook_returns_error(self):
        from server import _handle_purple_command

        with patch("playbooks.loader.load_playbook", side_effect=FileNotFoundError):
            result = await _handle_purple_command("10.0.0.0/8", "test-session")

        assert "not found" in result[0]["content"].lower()
```

- [ ] **Step 2: Run tests**

Run: `python3 -m pytest tests/test_purple_command.py -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_purple_command.py
git commit -m "test: /purple command tests — parsing, execution, error handling"
```

---

### Task 4: Run full test suite + deploy

- [ ] **Step 1: Run full test suite**

Run: `python3 -m pytest tests/ --ignore=tests/test_integration.py -v`
Expected: All pass, no regressions

- [ ] **Step 2: Push and deploy**

```bash
git push origin main
ssh deck@steamdeck 'cd /home/deck/protoPen && git pull && systemctl --user restart protopen && sleep 5 && systemctl --user is-active protopen'
```

- [ ] **Step 3: Live test on the Deck**

```bash
curl -s http://steamdeck:7870/a2a -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"/purple 192.168.4.0/24"}]},"contextId":"purple-live-test"}}'
```

- [ ] **Step 4: Update STATUS.md — Phase 5 complete**

Change Phase 5 status to ✅ Done.

- [ ] **Step 5: Final commit**

```bash
git add STATUS.md
git commit -m "docs: Phase 5 complete — all integration items shipped"
git push
```
