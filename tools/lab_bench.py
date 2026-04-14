"""Lab bench tool — autonomous experiment runner for protoPen.

Inspired by karpathy/autoresearch. Gives the agent access to GPU compute
for running training experiments via LLaMA-Factory on tiny Qwen models.

Toggled on/off via /lab command. Only available when running with the
'lab' docker compose profile (GPU access required).
"""

from typing import Any

from tools._tool_base import Tool

from lab.runner import ExperimentRunner


class LabBenchTool(Tool):
    """Run autonomous training experiments on tiny Qwen models."""

    def __init__(self, runner: ExperimentRunner | None = None):
        self._runner = runner or ExperimentRunner()

    @property
    def name(self) -> str:
        return "lab_bench"

    @property
    def description(self) -> str:
        return (
            "Autonomous experiment runner for training ML models. "
            "Uses LLaMA-Factory with tiny Qwen models (0.8B, 2B) on local GPU.\n"
            "Workflow: init -> edit config -> run -> keep/discard -> repeat.\n\n"
            "Actions:\n"
            "- init: Create experiment workspace from template\n"
            "- templates: List available templates\n"
            "- config: Show current LLaMA-Factory config\n"
            "- edit: Change a config value (key + value)\n"
            "- commit: Commit config changes with a description\n"
            "- run: Run training experiment\n"
            "- results: Show experiment history (results.tsv)\n"
            "- keep: Accept current experiment\n"
            "- discard: Revert current experiment\n"
            "- log: Show training log\n"
            "- status: Show all experiments\n\n"
            "Each experiment is tracked via git. The agent modifies config.yaml "
            "(the single modifiable file), commits, runs, then keeps or discards."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "init", "templates", "config", "edit", "commit",
                        "run", "results", "keep", "discard", "log", "status",
                    ],
                    "description": "Action to perform.",
                },
                "experiment": {
                    "type": "string",
                    "description": "Experiment name (required for most actions).",
                },
                "template": {
                    "type": "string",
                    "description": "Template name for init (e.g. 'dpo_qwen_0.8b').",
                },
                "key": {
                    "type": "string",
                    "description": "Config key to edit (for 'edit' action).",
                },
                "value": {
                    "type": "string",
                    "description": "New value for the config key (for 'edit' action).",
                },
                "description": {
                    "type": "string",
                    "description": "Description of the experiment/change (for 'commit' and 'run').",
                },
                "gpu": {
                    "type": "string",
                    "description": "GPU ID to use (default: '1').",
                },
                "time_budget": {
                    "type": "integer",
                    "description": "Time budget in seconds (default: 300 = 5 min).",
                },
                "tail": {
                    "type": "integer",
                    "description": "Number of log lines to show (default: 50).",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]
        experiment = kwargs.get("experiment", "")

        if action == "init":
            if not experiment:
                return "Error: 'experiment' name is required."
            template = kwargs.get("template", "dpo_qwen_0.8b")
            return self._runner.init_experiment(experiment, template)

        if action == "templates":
            return self._runner.list_templates()

        if action == "status":
            return self._runner.get_status()

        if action == "config":
            if not experiment:
                return "Error: 'experiment' name is required."
            return self._runner.get_config(experiment)

        if action == "edit":
            if not experiment:
                return "Error: 'experiment' name is required."
            key = kwargs.get("key", "")
            value = kwargs.get("value", "")
            if not key or not value:
                return "Error: 'key' and 'value' are required for edit."
            return self._runner.edit_config(experiment, key, value)

        if action == "commit":
            if not experiment:
                return "Error: 'experiment' name is required."
            desc = kwargs.get("description", "config change")
            return self._runner.commit_config(experiment, desc)

        if action == "run":
            if not experiment:
                return "Error: 'experiment' name is required."
            desc = kwargs.get("description", "")
            gpu = kwargs.get("gpu", "1")
            time_budget = kwargs.get("time_budget", 300)
            return await self._runner.run_experiment(
                experiment, description=desc, gpu=gpu, time_budget=time_budget,
            )

        if action == "results":
            if not experiment:
                return "Error: 'experiment' name is required."
            return self._runner.get_results(experiment)

        if action == "keep":
            if not experiment:
                return "Error: 'experiment' name is required."
            return self._runner.keep(experiment)

        if action == "discard":
            if not experiment:
                return "Error: 'experiment' name is required."
            return self._runner.discard(experiment)

        if action == "log":
            if not experiment:
                return "Error: 'experiment' name is required."
            tail = kwargs.get("tail", 50)
            return self._runner.get_log(experiment, tail=tail)

        return f"Error: Unknown action '{action}'."
