import {
  Bot,
  Check,
  ChevronLeft,
  ChevronRight,
  Cloud,
  ExternalLink,
  KeyRound,
  Loader2,
  LogIn,
  Network,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../lib/api";
import type { AgentConfig, ConfigPayload, OAuthProviderStatus } from "../lib/types";

type Step = "welcome" | "identity" | "model" | "finish";

const steps: Step[] = ["welcome", "identity", "model", "finish"];

// Provider choices offered in the wizard. "gateway" covers the OpenAI-compatible
// LiteLLM gateway (the openai/vllm/gateway labels are equivalent there); the two
// *-oauth values run Claude/ChatGPT on the operator's own subscription (ADR 0097).
const PROVIDERS = [
  { value: "gateway", label: "Model gateway (API key)", hint: "Any OpenAI-compatible endpoint" },
  { value: "anthropic-oauth", label: "Claude subscription", hint: "Claude Pro / Max via Claude Code sign-in" },
  { value: "openai-codex", label: "ChatGPT / Codex subscription", hint: "Sign in with your ChatGPT plan (opt-in)" },
] as const;

const OAUTH_PROVIDERS = new Set(["anthropic-oauth", "openai-codex"]);
const isOAuthProvider = (p: string) => OAUTH_PROVIDERS.has(p);

// The example model id shown per OAuth provider (real ids, not gateway aliases).
const OAUTH_MODEL_HINT: Record<string, string> = {
  "anthropic-oauth": "e.g. claude-sonnet-4-5, claude-opus-4-1",
  "openai-codex": "e.g. gpt-5-codex (ids are per-account)",
};

type WizardState = {
  provider: string;
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
    provider: "gateway",
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
    provider: config.model.provider || "gateway",
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

  // Native OAuth sign-in (ADR 0097) — status per provider + the in-progress flow.
  const [oauthStatuses, setOauthStatuses] = useState<Record<string, OAuthProviderStatus>>({});
  const [signinBusy, setSigninBusy] = useState(false);
  const [device, setDevice] = useState<{ flowId: string; userCode: string; uri: string; interval: number } | null>(null);
  const [pasteFlow, setPasteFlow] = useState<string | null>(null);
  const [pasteCode, setPasteCode] = useState("");
  // The last non-OAuth provider seen, so switching the dropdown back to "gateway"
  // restores it (rather than clobbering an "openai"/"vllm" label with "gateway").
  const [gatewayProvider, setGatewayProvider] = useState("gateway");

  const index = steps.indexOf(step);
  const isOAuth = isOAuthProvider(state.provider);
  const currentStatus = oauthStatuses[state.provider];
  const oauthSignedIn = Boolean(currentStatus?.signed_in);

  const refreshOauthStatus = useCallback(async () => {
    try {
      const res = await api.oauthStatus();
      const map: Record<string, OAuthProviderStatus> = {};
      for (const p of res.providers) map[p.provider] = p;
      setOauthStatuses(map);
    } catch {
      // A transient status probe failure is non-fatal — the panel just shows unknown.
    }
  }, []);

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
        const hydrated = hydrateState(config);
        setState(hydrated);
        if (!isOAuthProvider(hydrated.provider)) setGatewayProvider(hydrated.provider);
        void refreshOauthStatus();
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
  }, [open, refreshOauthStatus]);

  // Device-code (openai-codex) polling: once a device flow starts, poll until the
  // user approves it in the browser, then refresh status. Cleared on unmount / cancel.
  useEffect(() => {
    if (!device) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const res = await api.oauthPoll(device.flowId);
        if (cancelled) return;
        if (res.status === "complete") {
          setDevice(null);
          setMessage("Signed in.");
          await refreshOauthStatus();
        } else if (res.status === "error") {
          setDevice(null);
          setError(res.error || "Sign-in failed.");
        }
      } catch {
        // transient poll error — the next tick retries
      }
    };
    void tick();
    const handle = window.setInterval(() => void tick(), Math.max(3, device.interval) * 1000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [device, refreshOauthStatus]);

  const keyOk = isOAuth ? oauthSignedIn : !needsKey || Boolean(state.apiKey.trim());

  const canGoNext = useMemo(() => {
    if (step !== "model") return true;
    if (isOAuth) return Boolean(state.modelName.trim() && oauthSignedIn);
    return Boolean(state.apiBase.trim() && state.modelName.trim() && keyOk);
  }, [state.apiBase, state.modelName, keyOk, step, isOAuth, oauthSignedIn]);

  function update(patch: Partial<WizardState>) {
    setState((current) => ({ ...current, ...patch }));
  }

  function changeProvider(value: string) {
    // Abandon any pending sign-in for the previous provider.
    if (device) void api.oauthCancel(device.flowId).catch(() => {});
    if (pasteFlow) void api.oauthCancel(pasteFlow).catch(() => {});
    setDevice(null);
    setPasteFlow(null);
    setPasteCode("");
    setError("");
    setMessage("");
    if (value === "gateway") {
      update({ provider: gatewayProvider });
    } else {
      update({ provider: value });
      void refreshOauthStatus();
    }
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

  async function startSignin() {
    setSigninBusy(true);
    setError("");
    setMessage("");
    setDevice(null);
    setPasteFlow(null);
    setPasteCode("");
    try {
      const res = await api.oauthStart(state.provider);
      if (!res.ok) {
        setError(res.error || "Sign-in could not start.");
        return;
      }
      if (res.mode === "device" && res.flow_id) {
        setDevice({
          flowId: res.flow_id,
          userCode: res.user_code || "",
          uri: res.verification_uri || "",
          interval: res.interval || 5,
        });
        if (res.verification_uri) window.open(res.verification_uri, "_blank", "noopener");
      } else if (res.mode === "redirect" && res.flow_id) {
        setPasteFlow(res.flow_id);
        if (res.authorize_url) window.open(res.authorize_url, "_blank", "noopener");
      } else {
        setError("Sign-in returned an unexpected response.");
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setSigninBusy(false);
    }
  }

  async function completePaste() {
    if (!pasteFlow) return;
    setSigninBusy(true);
    setError("");
    try {
      const res = await api.oauthComplete(pasteFlow, pasteCode.trim());
      if (res.status === "complete") {
        setPasteFlow(null);
        setPasteCode("");
        setMessage("Signed in.");
        await refreshOauthStatus();
      } else {
        setError(res.error || "Sign-in failed.");
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setSigninBusy(false);
    }
  }

  async function disconnectProvider() {
    setSigninBusy(true);
    setError("");
    try {
      await api.oauthDisconnect(state.provider);
      setMessage("Disconnected.");
      await refreshOauthStatus();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setSigninBusy(false);
    }
  }

  async function finishSetup() {
    if (!keyOk) {
      setError(isOAuth ? "Sign in to finish setup." : "Enter your API key to finish setup.");
      setStep("model");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const model: AgentConfig["model"] = {
        provider: state.provider,
        name: state.modelName.trim(),
        api_base: state.apiBase.trim(),
        temperature: Number(state.temperature),
        max_tokens: Number(state.maxTokens),
        max_iterations: Number(state.maxIterations),
      };
      // The gateway path needs a key; OAuth providers authenticate from their store.
      if (!isOAuth && state.apiKey.trim()) {
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

  const providerLabel = PROVIDERS.find((p) => p.value === (isOAuth ? state.provider : "gateway"))?.label ?? "Model gateway";

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
                <StatusLine icon={<KeyRound size={15} />} label="Model gateway or your own Claude / ChatGPT plan" />
                <StatusLine icon={<Network size={15} />} label="Your own key or subscription" />
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
            <StepBody icon={<KeyRound size={20} />} title="Model" kicker="Provider">
              <label className="field">
                <span>Provider</span>
                <select value={isOAuth ? state.provider : "gateway"} onChange={(event) => changeProvider(event.target.value)}>
                  {PROVIDERS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </label>

              {isOAuth ? (
                <OAuthSignIn
                  provider={state.provider}
                  status={currentStatus}
                  busy={signinBusy}
                  device={device}
                  pasteActive={Boolean(pasteFlow)}
                  pasteCode={pasteCode}
                  onPasteCodeChange={setPasteCode}
                  onStart={() => void startSignin()}
                  onComplete={() => void completePaste()}
                  onDisconnect={() => void disconnectProvider()}
                />
              ) : (
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
              )}

              <div className="setup-grid model-row">
                <label className="field">
                  <span>Model</span>
                  <input
                    list="model-options"
                    value={state.modelName}
                    onChange={(event) => update({ modelName: event.target.value })}
                    placeholder={isOAuth ? OAUTH_MODEL_HINT[state.provider] : undefined}
                  />
                  <datalist id="model-options">
                    {models.map((model) => (
                      <option key={model} value={model} />
                    ))}
                  </datalist>
                </label>
                {!isOAuth ? (
                  <button className="secondary-button" type="button" onClick={() => void probeModels()} disabled={busy || !state.apiBase.trim()}>
                    {busy ? <Loader2 className="spin" size={15} /> : <Search size={15} />}
                    Probe
                  </button>
                ) : null}
              </div>
              {isOAuth ? (
                <p className="setup-hint">{OAUTH_MODEL_HINT[state.provider]} — the aux/subagent slots inherit this provider, so use a real model id.</p>
              ) : null}

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
                <StatusLine icon={<Cloud size={15} />} label={providerLabel} />
                <StatusLine icon={<KeyRound size={15} />} label={state.modelName || "model"} />
                {!isOAuth ? <StatusLine icon={<Network size={15} />} label={state.apiBase || "gateway"} /> : null}
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

function OAuthSignIn({
  provider,
  status,
  busy,
  device,
  pasteActive,
  pasteCode,
  onPasteCodeChange,
  onStart,
  onComplete,
  onDisconnect,
}: {
  provider: string;
  status: OAuthProviderStatus | undefined;
  busy: boolean;
  device: { flowId: string; userCode: string; uri: string; interval: number } | null;
  pasteActive: boolean;
  pasteCode: string;
  onPasteCodeChange: (value: string) => void;
  onStart: () => void;
  onComplete: () => void;
  onDisconnect: () => void;
}) {
  const signedIn = Boolean(status?.signed_in);
  const label = provider === "anthropic-oauth" ? "Claude" : "ChatGPT";

  return (
    <div className="setup-oauth">
      <div className="setup-oauth-status">
        {signedIn ? <ShieldCheck size={16} /> : <LogIn size={16} />}
        <span>
          {signedIn
            ? `Signed in — ${status?.detail || "connected"}`
            : status?.hint || `Sign in with your ${label} subscription to continue.`}
        </span>
      </div>

      {device ? (
        <div className="setup-oauth-device">
          <p>
            Enter this code at{" "}
            <a href={device.uri} target="_blank" rel="noreferrer">
              {device.uri} <ExternalLink size={12} />
            </a>
          </p>
          <code className="setup-oauth-code">{device.userCode}</code>
          <p className="setup-hint">
            <Loader2 className="spin" size={13} /> Waiting for approval…
          </p>
        </div>
      ) : null}

      {pasteActive ? (
        <div className="setup-oauth-paste">
          <p className="setup-hint">Approve in the browser tab that opened, then paste the code Anthropic shows here:</p>
          <div className="setup-grid model-row">
            <label className="field">
              <span>Authorization code</span>
              <input value={pasteCode} onChange={(event) => onPasteCodeChange(event.target.value)} autoComplete="off" placeholder="code#state" />
            </label>
            <button className="primary-button" type="button" onClick={onComplete} disabled={busy || !pasteCode.trim()}>
              {busy ? <Loader2 className="spin" size={15} /> : <Check size={15} />}
              Complete
            </button>
          </div>
        </div>
      ) : null}

      {!device && !pasteActive ? (
        <div className="setup-oauth-actions">
          <button className="primary-button" type="button" onClick={onStart} disabled={busy}>
            {busy ? <Loader2 className="spin" size={15} /> : <LogIn size={15} />}
            {signedIn ? `Re-sign in with ${label}` : `Sign in with ${label}`}
          </button>
          {signedIn ? (
            <button className="secondary-button" type="button" onClick={onDisconnect} disabled={busy}>
              Disconnect
            </button>
          ) : null}
        </div>
      ) : null}
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
