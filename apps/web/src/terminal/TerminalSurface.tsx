import { Plus, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
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
 *  can't set headers) and the session id for reconnect. Mirrors lib/api's base. */
function terminalWsUrl(sid: string): string {
  const httpBase = apiUrl("/ws/terminal");
  let base: string;
  if (/^https?:\/\//.test(httpBase)) {
    base = httpBase.replace(/^http/, "ws");
  } else {
    const { protocol, host } = window.location;
    base = `${protocol === "https:" ? "wss" : "ws"}://${host}${httpBase}`;
  }
  const params = new URLSearchParams();
  const key = getOperatorKey();
  if (key) params.set("key", key);
  if (sid) params.set("session", sid);
  const qs = params.toString();
  return qs ? `${base}?${qs}` : base;
}

// A terminal tab is identified by its server session id (sid) so a reload can
// reconnect to the same PTY and replay its scrollback (protopen-330). Tabs are
// persisted in localStorage; the sid survives the reload, the PTY survives on the
// server (until its idle TTL), so the terminal comes back as you left it.
type Tab = { sid: string; title: string };
const TABS_KEY = "protopen.terminal.tabs.v1";

function newSid(): string {
  return `s-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function loadTabs(): { tabs: Tab[]; currentSid: string } {
  try {
    const raw = window.localStorage.getItem(TABS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as { tabs?: Tab[]; currentSid?: string };
      const tabs = (parsed.tabs || []).filter((t) => t && t.sid);
      if (tabs.length) return { tabs, currentSid: parsed.currentSid || tabs[0].sid };
    }
  } catch {
    /* ignore corrupt/absent state */
  }
  const t = { sid: newSid(), title: "shell 1" };
  return { tabs: [t], currentSid: t.sid };
}

export function TerminalSurface({ active = true }: { active?: boolean }) {
  const initial = useRef(loadTabs());
  const [tabs, setTabs] = useState<Tab[]>(initial.current.tabs);
  const [currentSid, setCurrentSid] = useState(initial.current.currentSid);

  // Persist tabs + selection so a reload restores the same sessions.
  useEffect(() => {
    try {
      window.localStorage.setItem(TABS_KEY, JSON.stringify({ tabs, currentSid }));
    } catch {
      /* storage unavailable */
    }
  }, [tabs, currentSid]);

  function newTab() {
    const tab = { sid: newSid(), title: `shell ${tabs.length + 1}` };
    setTabs((prev) => [...prev, tab]);
    setCurrentSid(tab.sid);
  }

  function closeTab(sid: string) {
    setTabs((prev) => {
      const next = prev.filter((tab) => tab.sid !== sid);
      if (next.length === 0) {
        const fresh = { sid: newSid(), title: "shell 1" };
        setCurrentSid(fresh.sid);
        return [fresh];
      }
      if (sid === currentSid) setCurrentSid(next[next.length - 1].sid);
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
            <div className={`chat-tab ${tab.sid === currentSid ? "active" : ""}`} key={tab.sid}>
              <span className="session-dot idle" />
              <button
                type="button"
                role="tab"
                aria-selected={tab.sid === currentSid}
                className="chat-tab-label"
                onClick={() => setCurrentSid(tab.sid)}
              >
                {tab.title}
              </button>
              <button
                type="button"
                className="chat-tab-close"
                title="Close terminal"
                onClick={() => closeTab(tab.sid)}
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
          <TerminalPane key={tab.sid} sid={tab.sid} visible={active && tab.sid === currentSid} />
        ))}
      </div>
    </section>
  );
}

function TerminalPane({ sid, visible }: { sid: string; visible: boolean }) {
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

    // GPU renderer — lower render latency / smoother heavy output. Falls back to
    // the DOM renderer if WebGL is unavailable or the context is lost.
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      /* no WebGL — DOM renderer is fine */
    }

    const ws = new WebSocket(terminalWsUrl(sid));
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

    // Local convenience hotkeys (everything else passes through to the PTY).
    // Mac uses ⌘; other platforms use Ctrl (with Shift for copy/paste, since
    // Ctrl+C must stay SIGINT). Returning false consumes the key.
    const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown") return true;
      const mod = isMac ? e.metaKey : e.ctrlKey;
      const otherMod = isMac ? e.ctrlKey : e.metaKey;
      if (!mod || otherMod || e.altKey) return true; // not our combo → to PTY
      const send = (msg: object) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(msg));

      if (e.code === "KeyK" && !e.shiftKey) {
        // Clear: wipe the local view AND the server scrollback (so a reload
        // doesn't replay the cleared output).
        term.clear();
        send({ type: "clear" });
        return false;
      }
      if (e.code === "KeyC") {
        // ⌘C / Ctrl+Shift+C copies a selection; plain Ctrl+C falls through to SIGINT.
        const wantsCopy = isMac || e.shiftKey;
        if (wantsCopy) {
          if (term.hasSelection()) {
            void navigator.clipboard?.writeText(term.getSelection()).catch(() => {});
          }
          return false;
        }
        return true;
      }
      if (e.code === "KeyV" && (isMac || e.shiftKey)) {
        void navigator.clipboard
          ?.readText()
          .then((text) => {
            if (text) send({ type: "input", data: text });
          })
          .catch(() => {});
        return false;
      }
      if (e.code === "KeyA" && isMac && !e.shiftKey) {
        term.selectAll();
        return false;
      }
      return true;
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
