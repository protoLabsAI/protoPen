import {
  Bot,
  Check,
  ChevronLeft,
  ChevronRight,
  KeyRound,
  Loader2,
  Network,
  Search,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../lib/api";
import type { AgentConfig, ConfigPayload } from "../lib/types";

type Step = "welcome" | "identity" | "model" | "finish";

const steps: Step[] = ["welcome", "identity", "model", "finish"];

type WizardState = {
  agentName: string;
  operatorName: string;
  apiBase: string;
  apiKey: string;
  modelName: string;
  temperature: number;
  maxTokens: number;
  maxIterations: number;
};

function defaultState(): WizardState {
  return {
    agentName: "protopen",
    operatorName: "",
    apiBase: "https://api.proto-labs.ai/v1",
    apiKey: "",
    modelName: "protolabs/reasoning",
    temperature: 0.2,
    maxTokens: 32768,
    maxIterations: 50,
  };
}

function hydrateState(payload: ConfigPayload): WizardState {
  const config = payload.config;
  return {
    agentName: config.identity.name || "protopen",
    operatorName: config.identity.operator || "",
    apiBase: config.model.api_base || "https://api.proto-labs.ai/v1",
    apiKey: "",
    modelName: config.model.name || "protolabs/reasoning",
    temperature: Number(config.model.temperature ?? 0.2),
    maxTokens: Number(config.model.max_tokens ?? 32768),
    maxIterations: Number(config.model.max_iterations ?? 50),
  };
}

export function SetupWizard({
  open,
  onFinished,
}: {
  open: boolean;
  projectPath: string;
  onProjectPathChange: (value: string) => void;
  onFinished: () => void;
}) {
  const [step, setStep] = useState<Step>("welcome");
  const [state, setState] = useState<WizardState>(() => defaultState());
  // First-time setup (no key yet) must collect a key; a reconfigure may leave it
  // blank to preserve the existing one.
  const [needsKey, setNeedsKey] = useState(true);
  const [models, setModels] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const index = steps.indexOf(step);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    async function load() {
      setBusy(true);
      setError("");
      try {
        const [status, config] = await Promise.all([api.setupStatus(), api.config()]);
        if (!alive) return;
        setNeedsKey(!status.setup_complete);
        setState(hydrateState(config));
      } catch (exc) {
        if (alive) setError(exc instanceof Error ? exc.message : String(exc));
      } finally {
        if (alive) setBusy(false);
      }
    }
    void load();
    return () => {
      alive = false;
    };
  }, [open]);

  const keyOk = !needsKey || Boolean(state.apiKey.trim());

  const canGoNext = useMemo(() => {
    if (step === "model") return Boolean(state.apiBase.trim() && state.modelName.trim() && keyOk);
    return true;
  }, [state.apiBase, state.modelName, keyOk, step]);

  function update(patch: Partial<WizardState>) {
    setState((current) => ({ ...current, ...patch }));
  }

  async function probeModels() {
    setBusy(true);
    setError("");
    setModels([]);
    try {
      const response = await api.models(state.apiBase, state.apiKey);
      if (response.error) {
        setError(response.error);
        return;
      }
      setModels(response.models);
      if (response.models.length && !response.models.includes(state.modelName)) {
        update({ modelName: response.models[0] });
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  async function finishSetup() {
    if (!keyOk) {
      setError("Enter your API key to finish setup.");
      setStep("model");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const model: AgentConfig["model"] = {
        provider: "openai",
        name: state.modelName.trim(),
        api_base: state.apiBase.trim(),
        temperature: Number(state.temperature),
        max_tokens: Number(state.maxTokens),
        max_iterations: Number(state.maxIterations),
      };
      if (state.apiKey.trim()) {
        model.api_key = state.apiKey.trim();
      }
      const response = await api.finishSetup(
        {
          model,
          identity: {
            name: state.agentName.trim() || "protopen",
            operator: state.operatorName.trim(),
          },
        },
        "",
      );
      if (!response.ok) {
        setError(response.message);
        return;
      }
      setMessage(response.message);
      onFinished();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;

  return (
    <div className="setup-overlay" role="dialog" aria-modal="true" aria-label="Setup">
      <div className="setup-frame">
        <div className="setup-progress" aria-label="Setup progress">
          {steps.map((item, itemIndex) => (
            <span
              key={item}
              className={itemIndex < index ? "done" : itemIndex === index ? "active" : ""}
            />
          ))}
        </div>

        <section className="setup-card">
          {step === "welcome" ? (
            <StepBody icon={<Bot size={20} />} title="protoPen" kicker="Quick setup">
              <div className="setup-summary">
                <StatusLine icon={<KeyRound size={15} />} label="Model gateway" />
                <StatusLine icon={<Network size={15} />} label="Your own API key" />
              </div>
            </StepBody>
          ) : null}

          {step === "identity" ? (
            <StepBody icon={<Bot size={20} />} title="Identity" kicker="Agent">
              <div className="setup-grid two">
                <label className="field">
                  <span>Agent name</span>
                  <input value={state.agentName} onChange={(event) => update({ agentName: event.target.value })} />
                </label>
                <label className="field">
                  <span>Operator</span>
                  <input value={state.operatorName} onChange={(event) => update({ operatorName: event.target.value })} />
                </label>
              </div>
            </StepBody>
          ) : null}

          {step === "model" ? (
            <StepBody icon={<KeyRound size={20} />} title="Model Gateway" kicker="OpenAI-compatible">
              <div className="setup-grid two">
                <label className="field">
                  <span>API base</span>
                  <input value={state.apiBase} onChange={(event) => update({ apiBase: event.target.value })} />
                </label>
                <label className="field">
                  <span>API key{needsKey ? " *" : ""}</span>
                  <input
                    type="password"
                    value={state.apiKey}
                    onChange={(event) => update({ apiKey: event.target.value })}
                    autoComplete="off"
                    placeholder={needsKey ? "Enter your API key" : "Leave blank to keep current key"}
                  />
                </label>
              </div>
              <div className="setup-grid model-row">
                <label className="field">
                  <span>Model</span>
                  <input list="model-options" value={state.modelName} onChange={(event) => update({ modelName: event.target.value })} />
                  <datalist id="model-options">
                    {models.map((model) => (
                      <option key={model} value={model} />
                    ))}
                  </datalist>
                </label>
                <button className="secondary-button" type="button" onClick={() => void probeModels()} disabled={busy || !state.apiBase.trim()}>
                  {busy ? <Loader2 className="spin" size={15} /> : <Search size={15} />}
                  Probe
                </button>
              </div>
              <div className="setup-grid three">
                <label className="field">
                  <span>Temperature</span>
                  <input type="number" min="0" max="2" step="0.1" value={state.temperature} onChange={(event) => update({ temperature: Number(event.target.value) })} />
                </label>
                <label className="field">
                  <span>Max tokens</span>
                  <input type="number" min="1" value={state.maxTokens} onChange={(event) => update({ maxTokens: Number(event.target.value) })} />
                </label>
                <label className="field">
                  <span>Max turns</span>
                  <input type="number" min="1" value={state.maxIterations} onChange={(event) => update({ maxIterations: Number(event.target.value) })} />
                </label>
              </div>
            </StepBody>
          ) : null}

          {step === "finish" ? (
            <StepBody icon={<Check size={20} />} title="Finish" kicker="Write config">
              <div className="finish-list">
                <StatusLine icon={<Bot size={15} />} label={state.agentName || "protopen"} />
                <StatusLine icon={<KeyRound size={15} />} label={state.modelName || "model"} />
                <StatusLine icon={<Network size={15} />} label={state.apiBase || "gateway"} />
              </div>
              {message ? <div className="setup-message">{message}</div> : null}
            </StepBody>
          ) : null}

          {error ? <div className="setup-error">{error}</div> : null}

          <div className="setup-actions">
            <button className="secondary-button" type="button" onClick={() => setStep(steps[Math.max(0, index - 1)])} disabled={index === 0 || busy}>
              <ChevronLeft size={15} />
              Back
            </button>
            {step === "finish" ? (
              <button className="primary-button" type="button" onClick={() => void finishSetup()} disabled={busy || !keyOk}>
                {busy ? <Loader2 className="spin" size={15} /> : <Check size={15} />}
                Finish
              </button>
            ) : (
              <button className="primary-button" type="button" onClick={() => setStep(steps[Math.min(steps.length - 1, index + 1)])} disabled={!canGoNext || busy}>
                Next
                <ChevronRight size={15} />
              </button>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function StepBody({
  icon,
  title,
  kicker,
  children,
}: {
  icon: ReactNode;
  title: string;
  kicker: string;
  children: ReactNode;
}) {
  return (
    <div className="setup-step">
      <div className="setup-heading">
        <div className="setup-icon">{icon}</div>
        <div>
          <h1>{title}</h1>
          <p>{kicker}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function StatusLine({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="status-line">
      {icon}
      <span>{label}</span>
    </div>
  );
}
