import { AlertTriangle, ExternalLink } from "lucide-react";
import type { ReactNode } from "react";

// Renders a tool's input/output as real components instead of a raw JSON blob.
//
// A generic structured renderer: objects become key/value field rows, arrays
// become lists, URLs become links, scalars become chips, and plain text wraps
// with inline link detection. This handles every tool *input* (they're JSON
// objects) and any JSON output. protoPen's recon/pentest tools mostly emit
// text or JSON, so the generic renderer carries the load; a uniform error
// block fronts any output that starts with "Error:".

type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

const URL_RE = /\bhttps?:\/\/[^\s)<>"']+/g;

function tryParseJson(raw: string): JsonValue | undefined {
  const t = raw.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return undefined;
  try {
    return JSON.parse(t) as JsonValue;
  } catch {
    return undefined;
  }
}

const isUrl = (s: string) => /^https?:\/\/\S+$/.test(s.trim());

/** Render a tool input or output as components. */
export function ToolValue({
  raw,
  role,
}: {
  raw: string;
  role: "input" | "output";
  tool: string;
}) {
  const text = raw ?? "";

  // Tool errors render uniformly regardless of which tool produced them.
  if (role === "output" && /^error\b/i.test(text.trim())) {
    return <ErrorBlock text={text} />;
  }
  // Generic structured rendering.
  const parsed = tryParseJson(text);
  if (parsed !== undefined && typeof parsed === "object" && parsed !== null) {
    return Array.isArray(parsed) ? <ValueList items={parsed} /> : <KeyValueGrid obj={parsed} />;
  }
  return <TextBlock text={text} />;
}

// ── Generic structured primitives ───────────────────────────────────────────

function KeyValueGrid({ obj }: { obj: { [k: string]: JsonValue } }) {
  const entries = Object.entries(obj);
  if (!entries.length) return <TextBlock text="(empty)" />;
  return (
    <dl className="tool-kv">
      {entries.map(([k, v]) => (
        <div className="tool-kv-row" key={k}>
          <dt className="tool-kv-key">{k}</dt>
          <dd className="tool-kv-val">
            <ValueCell value={v} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function ValueList({ items }: { items: JsonValue[] }) {
  if (!items.length) return <TextBlock text="(empty list)" />;
  return (
    <ul className="tool-vlist">
      {items.map((v, i) => (
        <li key={i}>
          <ValueCell value={v} />
        </li>
      ))}
    </ul>
  );
}

function ValueCell({ value }: { value: JsonValue }): ReactNode {
  if (value === null) return <span className="tool-null">null</span>;
  if (typeof value === "boolean" || typeof value === "number") {
    return <span className="tool-chip">{String(value)}</span>;
  }
  if (typeof value === "string") {
    return isUrl(value) ? <Link href={value} /> : <span className="tool-scalar">{value}</span>;
  }
  if (Array.isArray(value)) return <ValueList items={value} />;
  return <KeyValueGrid obj={value} />;
}

function Link({ href, label }: { href: string; label?: string }) {
  return (
    <a className="tool-link" href={href} target="_blank" rel="noreferrer noopener">
      {label ?? href}
      <ExternalLink size={11} />
    </a>
  );
}

function linkify(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(<Link key={key++} href={m[0]} />);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function TextBlock({ text }: { text: string }) {
  return <div className="tool-text">{linkify(text)}</div>;
}

function ErrorBlock({ text }: { text: string }) {
  return (
    <div className="tool-error">
      <AlertTriangle size={13} />
      <span>{text.replace(/^error:\s*/i, "")}</span>
    </div>
  );
}
