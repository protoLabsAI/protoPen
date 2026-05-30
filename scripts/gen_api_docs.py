#!/usr/bin/env python3
"""Render the REST API reference from the committed OpenAPI spec.

The spec at ``docs/public/openapi.json`` is the source of truth — produce it
from the live app with::

    python server.py --dump-openapi docs/public/openapi.json

This script then renders that spec into the generated block of
``docs/reference/api-endpoints.md`` (stdlib only — no app import needed, so it
runs in CI):

    python scripts/gen_api_docs.py            # rewrite the page in place
    python scripts/gen_api_docs.py --check    # CI: fail if the page is stale
    python scripts/gen_api_docs.py --print    # print the block to stdout

The A2A (JSON-RPC) surface and the Gradio/observability routes are not part of
the OpenAPI schema; they stay hand-written, outside the generated markers.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "docs" / "public" / "openapi.json"
TARGET = REPO_ROOT / "docs" / "reference" / "api-endpoints.md"
BEGIN = "<!-- BEGIN GENERATED API — run: python scripts/gen_api_docs.py -->"
END = "<!-- END GENERATED API -->"

METHODS = ("get", "post", "put", "patch", "delete")

# Friendly group title per /api/<segment>; /v1/* is handled separately. Groups
# render in this order; anything unmapped is appended alphabetically.
GROUPS: list[tuple[str, str]] = [
    ("chat", "Chat"),
    ("v1", "OpenAI-Compatible API"),
    ("runtime", "Runtime"),
    ("subagents", "Subagents"),
    ("agents", "Live Agents"),
    ("engagement", "Engagement"),
    ("knowledge", "Knowledge"),
    ("audit", "Audit"),
    ("scheduler", "Scheduler"),
    ("notes", "Notes"),
    ("beads", "Beads"),
]
GROUP_ORDER = [title for _, title in GROUPS]
GROUP_TITLE = {key: title for key, title in GROUPS}


def group_for(path: str) -> str:
    """Bucket a path by its leading segment."""
    seg = path.strip("/").split("/")[0]
    if seg == "v1":
        return GROUP_TITLE["v1"]
    seg = path.strip("/").split("/")[1] if path.startswith("/api/") else seg
    return GROUP_TITLE.get(seg, seg.replace("_", " ").title())


def ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def type_str(schema: dict, spec: dict) -> str:
    """Best-effort one-token type for a property schema."""
    if not isinstance(schema, dict):
        return "any"
    if "$ref" in schema:
        return ref_name(schema["$ref"])
    if "anyOf" in schema or "oneOf" in schema:
        parts = [type_str(s, spec) for s in schema.get("anyOf", schema.get("oneOf", []))]
        parts = [p for p in parts if p != "null"]
        return " | ".join(dict.fromkeys(parts)) or "any"
    t = schema.get("type")
    if t == "array":
        return f"{type_str(schema.get('items', {}), spec)}[]"
    if t == "null":
        return "null"
    return t or "object"


def resolve(schema: dict, spec: dict) -> dict:
    """Resolve a top-level $ref to its component schema."""
    if isinstance(schema, dict) and "$ref" in schema:
        return spec["components"]["schemas"].get(ref_name(schema["$ref"]), {})
    return schema or {}


def esc(text: str) -> str:
    return (text or "").replace("|", r"\|").replace("\n", " ").strip()


def render_op(method: str, path: str, op: dict, spec: dict) -> list[str]:
    lines = [f"#### `{method.upper()} {path}`", ""]
    summary = op.get("summary") or op.get("operationId") or ""
    if summary:
        lines += [esc(summary), ""]

    params = [p for p in op.get("parameters", []) if p.get("in") in ("query", "path")]
    if params:
        lines += [
            "**Parameters**",
            "",
            "| Name | In | Required | Type | Default |",
            "|---|---|---|---|---|",
        ]
        for p in params:
            req = "yes" if p.get("required") else "no"
            schema = p.get("schema", {})
            default = schema.get("default")
            default = "" if default in (None, "") else f"`{default}`"
            lines.append(f"| `{p['name']}` | {p.get('in')} | {req} | {type_str(schema, spec)} | {default} |")
        lines.append("")

    body = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
    if body:
        resolved = resolve(body, spec)
        name = ref_name(body["$ref"]) if "$ref" in body else None
        props = resolved.get("properties", {})
        required = set(resolved.get("required", []))
        head = f"**Request body** (`{name}`)" if name else "**Request body**"
        lines += [head, ""]
        if props:
            lines += ["| Field | Type | Required |", "|---|---|---|"]
            for field, schema in props.items():
                req = "yes" if field in required else "no"
                lines.append(f"| `{field}` | {type_str(schema, spec)} | {req} |")
            lines.append("")

    responses = op.get("responses", {})
    if responses:
        codes = ", ".join(
            f"`{code}` {esc(meta.get('description', ''))}".strip() for code, meta in sorted(responses.items())
        )
        lines += [f"**Responses:** {codes}", ""]
    return lines


def render(spec: dict) -> str:
    paths = spec.get("paths", {})
    buckets: dict[str, list[tuple[str, str, dict]]] = {}
    for path in paths:
        for method, op in paths[path].items():
            if method not in METHODS:
                continue
            buckets.setdefault(group_for(path), []).append((method, path, op))

    ordered = [g for g in GROUP_ORDER if g in buckets]
    ordered += sorted(g for g in buckets if g not in GROUP_ORDER)

    info = spec.get("info", {})
    n_ops = sum(len(v) for v in buckets.values())
    lines = [
        BEGIN,
        "",
        f"_{n_ops} endpoints, generated from [`openapi.json`](/openapi.json) "
        f"(spec {spec.get('openapi', '')}, {info.get('title', '')} "
        f"{info.get('version', '')}) — do not edit by hand._",
        "",
    ]
    for group in ordered:
        lines += [f"### {group}", ""]
        for method, path, op in sorted(buckets[group], key=lambda t: (t[1], t[0])):
            lines += render_op(method, path, op, spec)
    lines.append(END)
    return "\n".join(lines)


def splice(text: str, block: str) -> str:
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"markers not found in {TARGET} — add a block bounded by:\n  {BEGIN}\n  {END}")
    return pattern.sub(lambda _: block, text)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "--write"
    if not SPEC.exists():
        raise SystemExit(
            f"{SPEC} not found — generate it first:\n  python server.py --dump-openapi docs/public/openapi.json"
        )
    block = render(json.loads(SPEC.read_text()))

    if mode == "--print":
        print(block)
        return 0

    current = TARGET.read_text()
    updated = splice(current, block)

    if mode == "--check":
        if current != updated:
            sys.stderr.write("API reference is stale — run: python scripts/gen_api_docs.py\n")
            return 1
        print("API reference is up to date.")
        return 0

    if current != updated:
        TARGET.write_text(updated)
        print(f"Updated API reference in {TARGET}.")
    else:
        print("API reference already up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
