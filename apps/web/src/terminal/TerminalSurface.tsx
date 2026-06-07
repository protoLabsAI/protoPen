import { Plus, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

import { apiUrl, getOperatorKey } from "../lib/api";

// Integrated terminal (MVP) — tabbed xterm.js panes bridged to a real PTY over
// /ws/terminal (see server/terminal.py). Run tools directly when the agent's
// loop isn't the fit. Tabs stay mounted (hidden) so a running command survives
// tab switches; App keeps the whole surface mounted so it survives rail nav too.
// Split panes are a fast follow-up. Themed to the Pilot Protocol terminal skin.

// xterm theme from the app palette (theme.css). Green-forward, near-black bg.
const THEME = {
  background: "#08080a",
  foreground: "#e8e8ea",
  cursor: "#3ee07a",
  cursorAccent: "#08080a",
  selectionBackground: "rgba(62, 224, 122, 0.24)",
  black: "#08080a",
  brightBlack: "#52525b",
  red: "#f87171",
  brightRed: "#fca5a5",
  green: "#3ee07a",
  brightGreen: "#6ee7b7",
  yellow: "#fbbf24",
  brightYellow: "#fde68a",
  blue: "#60a5fa",
  brightBlue: "#93c5fd",
  magenta: "#c084fc",
  brightMagenta: "#d8b4fe",
  cyan: "#2dd4bf",
  brightCyan: "#5eead4",
  white: "#e8e8ea",
  brightWhite: "#ffffff",
} as const;

const FONT = '"Berkeley Mono", "Geist Mono", "JetBrains Mono", ui-monospace, monospace';

/** ws(s):// URL for the terminal bridge, carrying the operator key (browser WS
 *  can't set headers). Mirrors lib/api's base resolution. */
function terminalWsUrl(): string {
  const httpBase = apiUrl("/ws/terminal");
  let url: string;
  if (/^https?:\/\//.test(httpBase)) {
    url = httpBase.replace(/^http/, "ws");
  } else {
    const { protocol, host } = window.location;
    url = `${protocol === "https:" ? "wss" : "ws"}://${host}${httpBase}`;
  }
  const key = getOperatorKey();
  return key ? `${url}?key=${encodeURIComponent(key)}` : url;
}

let tabSeq = 0;
type Tab = { id: string; title: string };

export function TerminalSurface({ active = true }: { active?: boolean }) {
  const [tabs, setTabs] = useState<Tab[]>(() => [{ id: `term-${++tabSeq}`, title: "shell 1" }]);
  const [currentId, setCurrentId] = useState(tabs[0].id);

  function newTab() {
    const tab = { id: `term-${++tabSeq}`, title: `shell ${tabs.length + 1}` };
    setTabs((prev) => [...prev, tab]);
    setCurrentId(tab.id);
  }

  function closeTab(id: string) {
    setTabs((prev) => {
      const next = prev.filter((tab) => tab.id !== id);
      if (next.length === 0) {
        const fresh = { id: `term-${++tabSeq}`, title: "shell 1" };
        setCurrentId(fresh.id);
        return [fresh];
      }
      if (id === currentId) setCurrentId(next[next.length - 1].id);
      return next;
    });
  }

  return (
    <section
      className="panel stage-panel term-stage"
      style={active ? undefined : { display: "none" }}
      aria-hidden={!active}
    >
      <div className="chat-header" role="tablist" aria-label="Terminals">
        <div className="chat-session-tabs">
          {tabs.map((tab) => (
            <div className={`chat-tab ${tab.id === currentId ? "active" : ""}`} key={tab.id}>
              <span className="session-dot idle" />
              <button
                type="button"
                role="tab"
                aria-selected={tab.id === currentId}
                className="chat-tab-label"
                onClick={() => setCurrentId(tab.id)}
              >
                {tab.title}
              </button>
              <button
                type="button"
                className="chat-tab-close"
                title="Close terminal"
                onClick={() => closeTab(tab.id)}
              >
                <X size={13} />
              </button>
            </div>
          ))}
        </div>
        <button className="chat-tab-new" type="button" onClick={newTab} title="New terminal">
          <Plus size={15} />
          New
        </button>
      </div>

      <div className="term-pool">
        {tabs.map((tab) => (
          <TerminalPane key={tab.id} visible={active && tab.id === currentId} />
        ))}
      </div>
    </section>
  );
}

function TerminalPane({ visible }: { visible: boolean }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitResizeRef = useRef<() => void>(() => {});

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const term = new Terminal({
      fontFamily: FONT,
      fontSize: 13,
      theme: THEME,
      cursorBlink: true,
      scrollback: 5000,
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(host);
    termRef.current = term;

    const ws = new WebSocket(terminalWsUrl());
    let pingTimer: number | undefined;

    const sendResize = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };
    fitResizeRef.current = () => {
      try {
        fit.fit();
        sendResize();
      } catch {
        /* element not measurable yet (hidden) */
      }
    };

    ws.onopen = () => {
      fitResizeRef.current();
      pingTimer = window.setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "ping" }));
      }, 30000);
    };
    ws.onmessage = (event) => {
      let msg: { type?: string; data?: string; code?: number };
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if (msg.type === "data" && msg.data) term.write(msg.data);
      else if (msg.type === "exit") {
        term.write(`\r\n\x1b[90m[process exited${msg.code ? ` (${msg.code})` : ""}]\x1b[0m\r\n`);
      }
    };
    ws.onclose = () => term.write("\r\n\x1b[90m[disconnected]\x1b[0m\r\n");
    ws.onerror = () => term.write("\r\n\x1b[31m[connection error]\x1b[0m\r\n");

    const dataDisp = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "input", data }));
    });

    const ro = new ResizeObserver(() => fitResizeRef.current());
    ro.observe(host);

    return () => {
      if (pingTimer) window.clearInterval(pingTimer);
      ro.disconnect();
      dataDisp.dispose();
      try {
        ws.close();
      } catch {
        /* already closed */
      }
      term.dispose();
    };
  }, []);

  // xterm can't measure a display:none element, so (re)fit + focus when this
  // pane becomes the visible one.
  useEffect(() => {
    if (!visible) return;
    const id = window.setTimeout(() => {
      fitResizeRef.current();
      termRef.current?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [visible]);

  return <div className="term-host" ref={hostRef} hidden={!visible} />;
}
