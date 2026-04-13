# Lab Mode

Lab mode gives the agent access to on-device GPU compute for running LoRA DPO training experiments via LLaMA-Factory. It is toggled on/off at runtime and only available when running the `lab` Docker Compose profile.

## Prerequisites

- The `researcher-lab` service running with GPU access:
  ```bash
  docker compose --profile lab up --build -d researcher-lab
  ```
- LLaMA-Factory installed at `/opt/llama-factory`
- `LAB_GPU` environment variable set (defaults to `1`)

## Enabling Lab Mode

In the chat UI, toggle lab mode on:

```
/lab on
```

The agent responds with GPU info and confirms the `lab_bench` tool is registered:

```
Lab mode ON. lab_bench tool registered.
GPU: CUDA_VISIBLE_DEVICES=1
Models: Qwen3.5-0.8B, Qwen3.5-2B
Stack: LLaMA-Factory (LoRA DPO)
```

Check status at any time:

```
/lab status
```

Disable when done:

```
/lab off
```

## Experiment Workflow

Every experiment follows the **init -> edit -> run -> keep/discard** cycle. Each step is tracked in git so you can always revert.

### 1. List Available Templates

Ask the agent or use the tool directly:

```
What experiment templates are available?
```

Built-in templates:

| Template | Description |
|---|---|
| `dpo_qwen_0.8b` | DPO fine-tune on Qwen3.5-0.8B (fast, ~3 min) |
| `dpo_qwen_2b` | DPO fine-tune on Qwen3.5-2B (longer, ~8 min) |

### 2. Initialize an Experiment

```
Initialize a new experiment called "reward-shaping-v1" from the dpo_qwen_0.8b template
```

This creates a workspace with a `config.yaml` (the only modifiable file) and commits the initial state to git.

### 3. Edit Configuration

```
In experiment reward-shaping-v1, set learning_rate to 5e-6 and num_train_epochs to 3
```

The agent calls `lab_bench edit` for each key, then `lab_bench commit` to snapshot the changes.

### 4. Run Training

```
Run the reward-shaping-v1 experiment with a 5-minute time budget
```

The `lab_bench run` action starts training via LLaMA-Factory. Default time budget is 300 seconds (5 minutes).

### 5. Review Results

```
Show me the results for reward-shaping-v1
```

Returns the `results.tsv` history, training logs, and metrics.

### 6. Keep or Discard

```
Keep the reward-shaping-v1 experiment
```

- **keep**: Accepts the experiment. Results are preserved.
- **discard**: Reverts via git to the pre-run state.

::: tip
You can run the full cycle conversationally. Ask the agent: "Run a DPO experiment on the 0.8B model with a lower learning rate and tell me if it beats the baseline."
:::

## Checking Logs

```
Show me the training log for reward-shaping-v1, last 100 lines
```

The agent calls `lab_bench log` with the `tail` parameter.
