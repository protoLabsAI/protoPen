# Step Output References — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow playbook step params to reference prior step outputs via `${steps.<name>.output}` syntax, so correlation steps receive real data from earlier phases.

**Architecture:** Extend `_resolve_params` in the loader with a new resolver in the runner. At load time, `${steps.*}` refs are left as-is (the step hasn't run yet). At runtime, before dispatching each step, the runner resolves any `${steps.<name>.output}` references against the completed step outputs in the playbook. The YAML playbook is updated to use these refs.

**Tech Stack:** Python, YAML, pytest

---

## File Map

| File | Change | Responsibility |
|------|--------|----------------|
| `playbooks/runner.py` | Modify | Add `_resolve_step_refs()` called before each dispatch |
| `playbooks/library/purple_team_exercise.yaml` | Modify | Replace hardcoded `"[]"` with `${steps.*.output}` refs |
| `tests/test_playbook_integration.py` | Modify | Add tests for step output reference resolution |

---

### Task 1: Step output resolution in the runner

**Files:**

- Modify: `playbooks/runner.py`
- Test: `tests/test_playbook_integration.py`

- [ ] **Step 1: Write the failing test for step output refs**

Add to `tests/test_playbook_integration.py`:

```python
class TestStepOutputReferences:
    """Test ${steps.<name>.output} param resolution at runtime."""

    @pytest.mark.asyncio
    async def test_step_ref_resolved_from_prior_output(self):
        """A step can reference a prior step's output in its params."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(name="producer", tool="t", action="produce", on_fail="continue"),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="consume",
                    params={"data": "${steps.producer.output}"},
                    on_fail="continue",
                ),
            ],
        )
        call_log = []

        async def dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((action, params))
            if action == "produce":
                return '{"findings": ["CVE-2024-1234"]}'
            return json.dumps({"received": params.get("data", "")})

        await run_playbook(pb, dispatch)
        # The consumer step should have received the producer's output
        assert call_log[1][1]["data"] == '{"findings": ["CVE-2024-1234"]}'

    @pytest.mark.asyncio
    async def test_unresolved_ref_left_as_is(self):
        """If the referenced step hasn't run or doesn't exist, leave the ref."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(
                    name="lonely",
                    tool="t",
                    action="a",
                    params={"data": "${steps.nonexistent.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps({"got": params.get("data", "")})

        await run_playbook(pb, dispatch)
        # Ref stays as literal — no crash
        assert pb.steps[0].status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_failed_step_ref_resolves_to_empty(self):
        """If referenced step failed (no output), resolve to empty string."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(name="broken", tool="t", action="fail", on_fail="continue"),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="consume",
                    params={"data": "${steps.broken.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "fail":
                raise RuntimeError("boom")
            return json.dumps({"got": params.get("data", "")})

        await run_playbook(pb, dispatch)
        assert pb.steps[0].status == StepStatus.FAILED
        assert pb.steps[1].status == StepStatus.COMPLETED
        # Failed step has empty output, so ref resolves to ""
        parsed = json.loads(pb.steps[1].output)
        assert parsed["got"] == ""

    @pytest.mark.asyncio
    async def test_multiple_refs_in_one_param(self):
        """A single param value can contain multiple step refs."""
        pb = Playbook(
            name="multi-ref",
            steps=[
                PlaybookStep(name="red", tool="t", action="r", on_fail="continue"),
                PlaybookStep(name="blue", tool="t", action="b", on_fail="continue"),
                PlaybookStep(
                    name="combine",
                    tool="t",
                    action="c",
                    params={"red": "${steps.red.output}", "blue": "${steps.blue.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "r":
                return '[{"technique_id":"T1046"}]'
            if action == "b":
                return '[{"technique_id":"T1046","detected":true}]'
            return json.dumps({"red": params["red"], "blue": params["blue"]})

        await run_playbook(pb, dispatch)
        result = json.loads(pb.steps[2].output)
        assert "T1046" in result["red"]
        assert "detected" in result["blue"]

    @pytest.mark.asyncio
    async def test_non_string_params_untouched(self):
        """Integer/bool params should not be affected by ref resolution."""
        pb = Playbook(
            name="types-test",
            steps=[
                PlaybookStep(
                    name="s1",
                    tool="t",
                    action="a",
                    params={"port": 443, "verbose": True, "name": "${steps.x.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps(params, default=str)

        await run_playbook(pb, dispatch)
        result = json.loads(pb.steps[0].output)
        assert result["port"] == 443
        assert result["verbose"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_playbook_integration.py::TestStepOutputReferences -v`
Expected: FAIL — `${steps.producer.output}` is passed through as a literal string, not resolved.

- [ ] **Step 3: Implement `_resolve_step_refs` in runner.py**

Add this function to `playbooks/runner.py` and call it before dispatch:

```python
import re

_STEP_REF_RE = re.compile(r"\$\{steps\.([a-zA-Z0-9_]+)\.output\}")


def _resolve_step_refs(params: dict[str, Any], playbook: Playbook) -> dict[str, Any]:
    """Resolve ${steps.<name>.output} references in step params."""
    resolved = {}
    for key, value in params.items():
        if isinstance(value, str) and "${steps." in value:
            def _replace(match):
                step_name = match.group(1)
                for step in playbook.steps:
                    if step.name == step_name:
                        return step.output  # "" if step failed/hasn't run
                return match.group(0)  # leave unresolved
            resolved[key] = _STEP_REF_RE.sub(_replace, value)
        else:
            resolved[key] = value
    return resolved
```

In `run_playbook`, add one line before the dispatch call:

```python
        # Resolve step output references before dispatching
        resolved_params = _resolve_step_refs(step.params, playbook)
        ...
        output = await dispatch(step.tool, step.action, resolved_params)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_playbook_integration.py::TestStepOutputReferences -v`
Expected: All PASS

- [ ] **Step 5: Run full playbook integration tests (no regressions)**

Run: `python3 -m pytest tests/test_playbook_integration.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add playbooks/runner.py tests/test_playbook_integration.py
git commit -m "feat: step output references — \${steps.<name>.output} resolved at runtime"
```

---

### Task 2: Update purple_team_exercise.yaml to use step refs

**Files:**

- Modify: `playbooks/library/purple_team_exercise.yaml`
- Test: `tests/test_playbook_integration.py`

- [ ] **Step 1: Write test that verifies refs are in the YAML**

Add to `tests/test_playbook_integration.py`:

```python
class TestPurpleTeamStepRefs:
    """Verify purple_team_exercise uses step output refs for correlation."""

    def test_coverage_matrix_refs_red_and_blue(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        matrix_step = next(s for s in pb.steps if s.name == "coverage_matrix")
        # Params should contain step refs, not hardcoded "[]"
        assert "${steps." in matrix_step.params["red_results"]
        assert "${steps." in matrix_step.params["blue_results"]

    def test_exercise_report_refs_red_and_blue(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        report_step = next(s for s in pb.steps if s.name == "exercise_report")
        assert "${steps." in report_step.params["red_results"]
        assert "${steps." in report_step.params["blue_results"]

    @pytest.mark.asyncio
    async def test_correlation_receives_real_data(self):
        """End-to-end: red/blue outputs flow into correlation steps."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        correlation_params = {}

        async def tracking_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "blackarch" and action == "nmap_scan":
                return '[{"technique_id":"T1046","technique_name":"Network Service Scanning","success":true}]'
            if tool == "cis_audit":
                return '[{"technique_id":"T1046","detected":true}]'
            if tool == "purple_team":
                correlation_params[action] = params
                return json.dumps({"rating": "GOOD", "detection_rate": 1.0})
            return "[]"

        await run_playbook(pb, tracking_dispatch)

        # coverage_matrix should have received the nmap output as red_results
        matrix_params = correlation_params.get("coverage_matrix", {})
        assert "T1046" in matrix_params.get("red_results", "")

        # exercise_report should also have received real data
        report_params = correlation_params.get("exercise_report", {})
        assert "T1046" in report_params.get("red_results", "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_playbook_integration.py::TestPurpleTeamStepRefs -v`
Expected: FAIL — params still contain `"[]"` not step refs.

- [ ] **Step 3: Update the YAML to use step refs**

Replace the correlation section in `playbooks/library/purple_team_exercise.yaml`:

```yaml
  # ── Correlation Phase ──
  - name: coverage_matrix
    tool: purple_team
    action: coverage_matrix
    params:
      red_results: "${steps.red_nmap_scan.output}"
      blue_results: "${steps.blue_ssh_audit.output}"
    timeout: 5
    on_fail: continue

  - name: exercise_report
    tool: purple_team
    action: exercise_report
    params:
      exercise_name: "${exercise_name}"
      target_scope: "${target}"
      red_results: "${steps.red_nmap_scan.output}"
      blue_results: "${steps.blue_ssh_audit.output}"
    timeout: 5
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_playbook_integration.py::TestPurpleTeamStepRefs -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ --ignore=tests/test_integration.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add playbooks/library/purple_team_exercise.yaml tests/test_playbook_integration.py
git commit -m "feat: purple team playbook uses step output refs for correlation"
```

---

### Task 3: Deploy and live test

- [ ] **Step 1: Push**

```bash
git push origin main
```

- [ ] **Step 2: Deploy to Deck**

```bash
ssh deck@steamdeck 'cd /home/deck/protoPen && git pull && systemctl --user restart protopen && sleep 5 && systemctl --user is-active protopen'
```

- [ ] **Step 3: Live test**

```bash
curl -s --max-time 120 -X POST http://steamdeck:7870/a2a -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"/purple 192.168.4.0/24"}]},"contextId":"purple-piping-test"}}'
```

Verify: ATT&CK Coverage section shows a real detection rate (not 0%) because the correlation steps received actual nmap/CIS data.

- [ ] **Step 4: Commit updated docs if needed**
