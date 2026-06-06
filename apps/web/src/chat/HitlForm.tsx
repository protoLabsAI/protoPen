import { useState } from "react";

import type { HitlFormStep, HitlPayload } from "../lib/types";

// Lightweight HITL renderer for protoPen's `hitl-v1` DataPart:
//  - a **form** (request_user_input) — a flat list of fields, one per step
//    ({id, label, type, enum?, required?}), submitted together as a {id: value} map;
//  - an **Approve / Deny** card (run_command, and the passive→active /
//    destructive-tool escalation gate);
//  - a free-text **question** (ask_human).
// Field types handled: string/number/integer/boolean/enum/textarea — enough for
// the choice/config/approval prompts agents actually ask for.

function Field({
  step,
  value,
  onChange,
}: {
  step: HitlFormStep;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const label = (step.label || step.id) + (step.required ? " *" : "");

  if (step.type === "boolean") {
    return (
      <label className="hitl-field hitl-field-bool">
        <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <span>{label}</span>
      </label>
    );
  }

  let control;
  if (Array.isArray(step.enum)) {
    control = (
      <select value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>
        <option value="" disabled>
          Select…
        </option>
        {step.enum.map((opt) => (
          <option key={String(opt)} value={String(opt)}>
            {String(opt)}
          </option>
        ))}
      </select>
    );
  } else if (step.type === "number" || step.type === "integer") {
    control = (
      <input
        type="number"
        value={value === undefined || value === null ? "" : String(value)}
        onChange={(e) => onChange(e.target.value === "" ? undefined : Number(e.target.value))}
      />
    );
  } else if (step.type === "textarea") {
    control = <textarea value={String(value ?? "")} onChange={(e) => onChange(e.target.value)} rows={3} />;
  } else {
    control = <input type="text" value={String(value ?? "")} onChange={(e) => onChange(e.target.value)} />;
  }

  return (
    <label className="hitl-field">
      <span>{label}</span>
      {control}
      {step.description && <small>{step.description}</small>}
    </label>
  );
}

export function HitlForm({
  payload,
  busy,
  onSubmit,
  onCancel,
}: {
  payload: HitlPayload;
  busy?: boolean;
  onSubmit: (response: Record<string, unknown> | string) => void;
  onCancel: () => void;
}) {
  const steps = payload.steps || [];
  const isForm = payload.kind === "form" && steps.length > 0;
  const isApproval = payload.kind === "approval";
  const [values, setValues] = useState<Record<string, unknown>>(() => {
    const init: Record<string, unknown> = {};
    for (const step of payload.steps || []) {
      if (step.default !== undefined) init[step.id] = step.default;
    }
    return init;
  });
  const [text, setText] = useState("");

  // Approval gate (e.g. run_command, passive→active escalation) — Approve / Deny.
  if (isApproval) {
    return (
      <div className="hitl-card hitl-approval" role="dialog" aria-label="Approval requested">
        <div className="hitl-title">{payload.title || "Approve this action?"}</div>
        {payload.description && <div className="hitl-prompt">{payload.description}</div>}
        {payload.detail && <pre className="hitl-detail">{payload.detail}</pre>}
        <div className="hitl-actions">
          <button type="button" className="secondary-button" onClick={() => onSubmit("denied")} disabled={busy}>
            Deny
          </button>
          <button type="button" className="primary-button" onClick={() => onSubmit("approved")} disabled={busy}>
            Approve
          </button>
        </div>
      </div>
    );
  }

  // ask_human / free-text question.
  if (!isForm) {
    const prompt = payload.question || payload.description || payload.title || "Input requested.";
    return (
      <div className="hitl-card" role="dialog" aria-label="Input requested">
        <div className="hitl-title">{payload.title || "Input requested"}</div>
        <div className="hitl-prompt">{prompt}</div>
        <textarea
          className="hitl-freetext"
          value={text}
          autoFocus
          placeholder="Your answer…"
          onChange={(e) => setText(e.target.value)}
        />
        <div className="hitl-actions">
          <button type="button" className="secondary-button" onClick={onCancel} disabled={busy}>
            Dismiss
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={() => onSubmit(text.trim())}
            disabled={busy || !text.trim()}
          >
            Send
          </button>
        </div>
      </div>
    );
  }

  const set = (id: string, v: unknown) => setValues((prev) => ({ ...prev, [id]: v }));
  // Required fields must be filled before submit.
  const missing = steps.some((step) => step.required && (values[step.id] === undefined || values[step.id] === ""));

  return (
    <div className="hitl-card" role="dialog" aria-label={payload.title || "Form requested"}>
      <div className="hitl-title">{payload.title || "Input requested"}</div>
      {payload.description && <div className="hitl-prompt">{payload.description}</div>}
      {steps.map((step) => (
        <Field key={step.id} step={step} value={values[step.id]} onChange={(v) => set(step.id, v)} />
      ))}
      <div className="hitl-actions">
        <button type="button" className="secondary-button" onClick={onCancel} disabled={busy}>
          Dismiss
        </button>
        <button type="button" className="primary-button" onClick={() => onSubmit(values)} disabled={busy || missing}>
          Submit
        </button>
      </div>
    </div>
  );
}
