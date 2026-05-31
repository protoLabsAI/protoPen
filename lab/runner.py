"""Experiment runner for protoPen lab mode.

Manages autonomous training experiments using LLaMA-Factory:
- Git-based experiment tracking (commit per hypothesis, reset on discard)
- Fixed time/step budget per experiment
- Results ledger (results.tsv) with metrics
- Inspired by karpathy/autoresearch
"""

import asyncio
import csv
import io
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from tools._subprocess import communicate_or_kill

_LAB_ROOT = Path("/sandbox/lab")
_TEMPLATES_DIR = Path(__file__).parent / "templates"
_LLAMA_FACTORY = "/opt/llama-factory"
_LAB_DATA = "/opt/lab-data"
_TRAINING_OUTPUT = "/mnt/data/training/researcher"
_DEFAULT_GPU = os.environ.get("LAB_GPU", "1")
_DEFAULT_TIME_BUDGET = 300  # 5 minutes


class ExperimentRunner:
    """Manages experiment lifecycle: init, run, track, keep/discard."""

    def __init__(self, lab_root: Path = _LAB_ROOT):
        self.lab_root = lab_root

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def init_experiment(self, name: str, template: str = "dpo_qwen_0.8b") -> str:
        """Create a new experiment workspace from a template."""
        workspace = self.lab_root / name
        if workspace.exists():
            return f"Error: Experiment '{name}' already exists at {workspace}"

        template_dir = _TEMPLATES_DIR / template
        if not template_dir.exists():
            available = [d.name for d in _TEMPLATES_DIR.iterdir() if d.is_dir()]
            return f"Error: Template '{template}' not found. Available: {', '.join(available)}"

        # Copy template
        workspace.mkdir(parents=True)
        for item in template_dir.iterdir():
            if item.is_file():
                dest = workspace / item.name
                content = item.read_text()
                # Substitute placeholders
                content = content.replace("{experiment_name}", name)
                content = content.replace("{output_dir}", f"{_TRAINING_OUTPUT}/{name}")
                content = content.replace("{lab_data}", _LAB_DATA)
                dest.write_text(content)

        # Init results.tsv
        results_path = workspace / "results.tsv"
        results_path.write_text("commit\teval_loss\ttrain_loss\tpeak_vram_mb\tsteps\tstatus\tdescription\n")

        # Init git repo
        subprocess.run(["git", "init"], cwd=workspace, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=workspace, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init: baseline from template " + template],
            cwd=workspace,
            capture_output=True,
        )

        # Create output dir
        output_dir = Path(f"{_TRAINING_OUTPUT}/{name}")
        output_dir.mkdir(parents=True, exist_ok=True)

        return (
            f"Experiment '{name}' initialized from template '{template}'.\n"
            f"Workspace: {workspace}\n"
            f"Output dir: {output_dir}\n"
            f"Config: {workspace / 'config.yaml'}\n\n"
            f"Read program.md for experiment instructions, then use 'run' to start."
        )

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def get_config(self, name: str) -> str:
        """Read the current config.yaml."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace
        config_path = workspace / "config.yaml"
        if not config_path.exists():
            return "Error: config.yaml not found."
        return config_path.read_text()

    def edit_config(self, name: str, key: str, value: str) -> str:
        """Edit a key in config.yaml and commit."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        config_path = workspace / "config.yaml"
        config = yaml.safe_load(config_path.read_text())

        # Parse value type
        parsed_value: Any = value
        if value.lower() in ("true", "false"):
            parsed_value = value.lower() == "true"
        else:
            try:
                parsed_value = int(value)
            except ValueError:
                try:
                    parsed_value = float(value)
                except ValueError:
                    pass

        old_value = config.get(key, "(not set)")
        config[key] = parsed_value
        config_path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))

        return f"Updated `{key}`: {old_value} -> {parsed_value}"

    def commit_config(self, name: str, description: str) -> str:
        """Commit the current config change with a description."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        subprocess.run(["git", "add", "config.yaml"], cwd=workspace, capture_output=True)
        result = subprocess.run(
            ["git", "commit", "-m", f"experiment: {description}"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            if "nothing to commit" in result.stdout + result.stderr:
                return "No changes to commit."
            return f"Error: {result.stderr}"

        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=workspace,
            capture_output=True,
            text=True,
        ).stdout.strip()

        return f"Committed as `{commit}`: {description}"

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run_experiment(
        self,
        name: str,
        description: str = "",
        gpu: str = _DEFAULT_GPU,
        time_budget: int = _DEFAULT_TIME_BUDGET,
    ) -> str:
        """Run a training experiment with LLaMA-Factory."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        config_path = workspace / "config.yaml"
        log_path = workspace / "run.log"
        output_dir = Path(f"{_TRAINING_OUTPUT}/{name}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Commit current state if there are changes
        subprocess.run(["git", "add", "config.yaml"], cwd=workspace, capture_output=True)
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=workspace,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if status:
            msg = description or "experiment run"
            subprocess.run(
                ["git", "commit", "-m", f"experiment: {msg}"],
                cwd=workspace,
                capture_output=True,
            )

        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=workspace,
            capture_output=True,
            text=True,
        ).stdout.strip()

        # Build environment
        env = {
            **os.environ,
            "CUDA_VISIBLE_DEVICES": gpu,
            "HF_HOME": "/mnt/models/huggingface",
            "PYTHONPATH": _LLAMA_FACTORY,
        }

        # Run LLaMA-Factory training
        cmd = [
            "python",
            "-m",
            "llamafactory.cli",
            "train",
            str(config_path),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=str(workspace),
            )
            result = await communicate_or_kill(proc, time_budget + 120)
            if result is None:
                log_path.write_text("TIMEOUT: Training exceeded time budget.")
                self._log_result(workspace, commit, status="TIMEOUT", description=description)
                return f"Experiment timed out after {time_budget}s. Check `log` for details."
            stdout, _ = result
            log_text = stdout.decode(errors="replace")
            log_path.write_text(log_text)
        except Exception as e:
            self._log_result(workspace, commit, status="CRASH", description=f"{description} — {e}")
            return f"Error running experiment: {e}"

        if proc.returncode != 0:
            self._log_result(workspace, commit, status="CRASH", description=description)
            # Show last 20 lines of log
            lines = log_text.strip().splitlines()
            tail = "\n".join(lines[-20:])
            return f"Training crashed (exit {proc.returncode}).\n\n```\n{tail}\n```"

        # Parse metrics from log
        metrics = self._parse_metrics(log_text)
        self._log_result(
            workspace,
            commit,
            eval_loss=metrics.get("eval_loss", ""),
            train_loss=metrics.get("train_loss", ""),
            peak_vram_mb=metrics.get("peak_vram_mb", ""),
            steps=metrics.get("steps", ""),
            status="PENDING",
            description=description,
        )

        # Format result
        lines = [f"**Experiment complete** (`{commit}`): {description}"]
        if metrics.get("eval_loss"):
            lines.append(f"- Eval loss: **{metrics['eval_loss']}**")
        if metrics.get("train_loss"):
            lines.append(f"- Train loss: {metrics['train_loss']}")
        if metrics.get("peak_vram_mb"):
            lines.append(f"- Peak VRAM: {metrics['peak_vram_mb']} MB")
        if metrics.get("steps"):
            lines.append(f"- Steps: {metrics['steps']}")
        lines.append("\nUse `keep` to accept or `discard` to revert.")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Keep / Discard
    # ------------------------------------------------------------------

    def keep(self, name: str) -> str:
        """Mark the latest experiment as KEEP."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace
        return self._update_last_status(workspace, "KEEP")

    def discard(self, name: str) -> str:
        """Discard the latest experiment — revert to previous commit."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        self._update_last_status(workspace, "DISCARD")

        # Reset to previous commit
        result = subprocess.run(
            ["git", "reset", "--hard", "HEAD~1"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return f"Error reverting: {result.stderr}"

        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=workspace,
            capture_output=True,
            text=True,
        ).stdout.strip()

        return f"Discarded. Reverted to `{commit}`."

    # ------------------------------------------------------------------
    # Status / Results / Log
    # ------------------------------------------------------------------

    def get_results(self, name: str) -> str:
        """Show results.tsv for an experiment."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        results_path = workspace / "results.tsv"
        if not results_path.exists():
            return "No results yet."

        content = results_path.read_text().strip()
        if content.count("\n") < 1:
            return "No experiments run yet."

        return f"```\n{content}\n```"

    def get_log(self, name: str, tail: int = 50) -> str:
        """Show the last N lines of the training log."""
        workspace = self._get_workspace(name)
        if isinstance(workspace, str):
            return workspace

        log_path = workspace / "run.log"
        if not log_path.exists():
            return "No training log yet."

        lines = log_path.read_text().strip().splitlines()
        shown = lines[-tail:]
        return "```\n" + "\n".join(shown) + "\n```"

    def get_status(self) -> str:
        """Show all experiments and their status."""
        if not self.lab_root.exists():
            return "No experiments. Use `init` to create one."

        experiments = [d for d in self.lab_root.iterdir() if d.is_dir() and (d / ".git").exists()]
        if not experiments:
            return "No experiments. Use `init` to create one."

        lines = [f"**Lab experiments ({len(experiments)}):**"]
        for exp in sorted(experiments):
            results_path = exp / "results.tsv"
            run_count = 0
            last_status = ""
            last_metric = ""
            if results_path.exists():
                tsv_lines = results_path.read_text().strip().splitlines()[1:]  # skip header
                run_count = len(tsv_lines)
                if tsv_lines:
                    parts = tsv_lines[-1].split("\t")
                    last_status = parts[5] if len(parts) > 5 else ""
                    last_metric = parts[1] if len(parts) > 1 else ""

            lines.append(
                f"- **{exp.name}** — {run_count} runs"
                + (f", last: {last_status} (eval_loss={last_metric})" if last_status else "")
            )

        gpu = os.environ.get("CUDA_VISIBLE_DEVICES", _DEFAULT_GPU)
        lines.append(f"\nGPU: `CUDA_VISIBLE_DEVICES={gpu}`")

        return "\n".join(lines)

    def list_templates(self) -> str:
        """List available experiment templates."""
        if not _TEMPLATES_DIR.exists():
            return "No templates found."

        templates = [d.name for d in _TEMPLATES_DIR.iterdir() if d.is_dir()]
        if not templates:
            return "No templates found."

        lines = ["**Available templates:**"]
        for t in sorted(templates):
            program = _TEMPLATES_DIR / t / "program.md"
            desc = ""
            if program.exists():
                # First non-empty, non-heading line
                for line in program.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        desc = line[:100]
                        break
            lines.append(f"- `{t}` — {desc}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_workspace(self, name: str) -> Path | str:
        workspace = self.lab_root / name
        if not workspace.exists():
            experiments = []
            if self.lab_root.exists():
                experiments = [d.name for d in self.lab_root.iterdir() if d.is_dir()]
            if experiments:
                return f"Error: Experiment '{name}' not found. Available: {', '.join(experiments)}"
            return f"Error: Experiment '{name}' not found. Use `init` to create one."
        return workspace

    def _parse_metrics(self, log_text: str) -> dict[str, str]:
        """Parse training metrics from LLaMA-Factory log output."""
        metrics: dict[str, str] = {}

        # LLaMA-Factory logs eval metrics like:
        # ***** eval metrics *****
        #   eval_loss  =  2.3456
        eval_loss_match = re.findall(r"eval_loss\s*=\s*([\d.]+)", log_text)
        if eval_loss_match:
            metrics["eval_loss"] = eval_loss_match[-1]  # last eval

        train_loss_match = re.findall(r"'loss':\s*([\d.]+)", log_text)
        if train_loss_match:
            metrics["train_loss"] = train_loss_match[-1]

        # VRAM from torch
        vram_match = re.findall(r"peak.*?(\d+)\s*MB", log_text, re.IGNORECASE)
        if vram_match:
            metrics["peak_vram_mb"] = vram_match[-1]

        # Steps
        steps_match = re.findall(r"global_step\s*=\s*(\d+)", log_text)
        if not steps_match:
            steps_match = re.findall(r"(\d+)/\d+\s*\[", log_text)
        if steps_match:
            metrics["steps"] = steps_match[-1]

        return metrics

    def _log_result(
        self,
        workspace: Path,
        commit: str,
        eval_loss: str = "",
        train_loss: str = "",
        peak_vram_mb: str = "",
        steps: str = "",
        status: str = "",
        description: str = "",
    ):
        """Append a row to results.tsv."""
        results_path = workspace / "results.tsv"
        with results_path.open("a") as f:
            row = "\t".join(
                [
                    commit,
                    eval_loss,
                    train_loss,
                    peak_vram_mb,
                    steps,
                    status,
                    description,
                ]
            )
            f.write(row + "\n")

    def _update_last_status(self, workspace: Path, new_status: str) -> str:
        """Update the status of the last results.tsv entry."""
        results_path = workspace / "results.tsv"
        if not results_path.exists():
            return "No results to update."

        lines = results_path.read_text().strip().splitlines()
        if len(lines) < 2:
            return "No experiments to update."

        # Update last line's status field (index 5)
        parts = lines[-1].split("\t")
        old_status = parts[5] if len(parts) > 5 else "?"
        if len(parts) > 5:
            parts[5] = new_status
        lines[-1] = "\t".join(parts)

        results_path.write_text("\n".join(lines) + "\n")
        return f"Marked as **{new_status}** (was {old_status})."
