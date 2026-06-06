import { Loader2, MessageSquarePlus, Send, Square, TerminalSquare, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { api } from "../lib/api";
import { ConfirmDialog } from "../components/ConfirmDialog";
import type { ChatMessage, HitlPayload, SlashCommand } from "../lib/types";
import { chatStore, MAX_ACTIVE_SESSIONS, useChatState } from "./chat-store";
import { HitlForm } from "./HitlForm";
import { Markdown } from "./LazyMarkdown";
import { ToolCalls } from "./ToolCalls";

function messageId() {
  return `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function useSession(sessionId: string) {
  const state = useChatState();
  return state.sessions.find((session) => session.id === sessionId) || null;
}

export function ChatSurface({ onError }: { onError: (message: string) => void }) {
  const chat = useChatState();
  const currentSession = chat.sessions.find((session) => session.id === chat.currentSessionId) || null;
  const [editingId, setEditingId] = useState<string | null>(null);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const pendingDelete = pendingDeleteId
    ? chat.sessions.find((session) => session.id === pendingDeleteId) || null
    : null;

  useEffect(() => {
    if (!chat.currentSessionId && chat.sessions.length === 0) {
      chatStore.createSession();
    }
  }, [chat.currentSessionId, chat.sessions.length]);

  const atSessionCap = chat.sessions.length >= MAX_ACTIVE_SESSIONS;

  // One toolbar: a tab per session (status dot · title · close), then "+ New".
  // Double-click a tab to rename it inline. Replaces the old triple-stacked
  // header (title block + tab strip + per-slot title/id/status row).
  return (
    <section className="panel stage-panel chat-stage">
      <div className="chat-header" role="tablist" aria-label="Chat sessions">
        <div className="chat-session-tabs">
          {chat.sessions.map((session) => {
            const active = session.id === chat.currentSessionId;
            const status = chat.sessionStatusMap[session.id] || "idle";
            const editing = editingId === session.id;
            return (
              <div className={`chat-tab ${active ? "active" : ""}`} key={session.id}>
                <span className={`session-dot ${status}`} title={status} />
                {editing ? (
                  <input
                    className="chat-tab-rename"
                    autoFocus
                    value={session.title}
                    onChange={(event) => chatStore.renameSession(session.id, event.target.value)}
                    onBlur={() => setEditingId(null)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === "Escape") setEditingId(null);
                    }}
                    aria-label="Rename session"
                  />
                ) : (
                  <button
                    type="button"
                    role="tab"
                    aria-selected={active}
                    className="chat-tab-label"
                    title={`${session.title}\n${session.id}  (double-click to rename)`}
                    onClick={() => chatStore.switchSession(session.id)}
                    onDoubleClick={() => setEditingId(session.id)}
                  >
                    {session.title}
                  </button>
                )}
                <button
                  type="button"
                  className="chat-tab-close"
                  title="Delete session"
                  disabled={status === "streaming"}
                  onClick={() => setPendingDeleteId(session.id)}
                >
                  <X size={13} />
                </button>
              </div>
            );
          })}
        </div>
        <button
          className="chat-tab-new"
          type="button"
          onClick={() => chatStore.createSession()}
          disabled={atSessionCap}
          title={atSessionCap ? `Session limit reached (${MAX_ACTIVE_SESSIONS})` : "New session"}
        >
          <MessageSquarePlus size={15} />
          New
        </button>
      </div>

      <div className="chat-session-pool">
        {chat.activeSessions.map((sessionId) => (
          <ChatSessionSlot
            key={sessionId}
            sessionId={sessionId}
            visible={sessionId === currentSession?.id}
            onError={onError}
          />
        ))}
      </div>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete session?"
        message={
          pendingDelete
            ? `“${pendingDelete.title}” and its messages will be permanently removed. This can't be undone.`
            : undefined
        }
        confirmLabel="Delete session"
        onConfirm={() => {
          if (pendingDeleteId) chatStore.deleteSession(pendingDeleteId);
          setPendingDeleteId(null);
        }}
        onCancel={() => setPendingDeleteId(null)}
      />
    </section>
  );
}

function ChatSessionSlot({
  sessionId,
  visible,
  onError,
}: {
  sessionId: string;
  visible: boolean;
  onError: (message: string) => void;
}) {
  const session = useSession(sessionId);
  const chat = useChatState();
  const [draft, setDraft] = useState("");
  const [statusMessage, setStatusMessage] = useState("");
  const [taskId, setTaskId] = useState("");
  const [hitl, setHitl] = useState<HitlPayload | null>(null);
  // Bumped on each new HITL payload so <HitlForm> remounts with fresh field
  // state — a reused instance must not carry inputs from a prior request.
  const [hitlSeq, setHitlSeq] = useState(0);
  const abortRef = useRef<AbortController | null>(null);
  // The parked task id survives the turn's `finally` (which resets taskId state)
  // so Dismiss can cancel an input-required task on the backend, not just hide it.
  const hitlTaskRef = useRef<string>("");
  const listRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const status = chat.sessionStatusMap[sessionId] || "idle";

  // Slash-command autocomplete. Server-handled `/`-commands are fetched once;
  // the dropdown is active while typing "/name" (before a space).
  const [commands, setCommands] = useState<SlashCommand[]>([]);
  const [slashIndex, setSlashIndex] = useState(0);
  const [slashDismissed, setSlashDismissed] = useState(false);

  useEffect(() => {
    api
      .chatCommands()
      .then((r) => setCommands(r.commands))
      .catch(() => {});
  }, []);

  const slashQuery = useMemo(() => {
    if (slashDismissed || !draft.startsWith("/")) return null;
    const after = draft.slice(1);
    return after.includes(" ") ? null : after; // closes once a space is typed
  }, [draft, slashDismissed]);

  const slashMatches = useMemo(() => {
    if (slashQuery === null) return [];
    const q = slashQuery.toLowerCase();
    return commands.filter(
      (c) => !q || c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q),
    );
  }, [slashQuery, commands]);

  const slashActive = slashMatches.length > 0;
  const slashSel = slashActive ? Math.min(slashIndex, slashMatches.length - 1) : 0;

  function completeCommand(cmd: SlashCommand) {
    setDraft(`/${cmd.name} `);
    setSlashIndex(0);
    setSlashDismissed(true); // a space follows, so it would close anyway
    textareaRef.current?.focus();
  }

  useEffect(() => {
    if (!visible) return;
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [session?.messages, visible]);

  // Consume a prompt staged from another surface (e.g. "Ask agent" on the
  // Capabilities catalog). Only the visible slot takes it, and only once.
  // Append rather than overwrite so we don't discard text already in the composer.
  useEffect(() => {
    const staged = chat.pendingDraft;
    if (!visible || !staged) return;
    setDraft((current) => (current.trim() ? `${current}\n${staged}` : staged));
    chatStore.setPendingDraft(null);
    textareaRef.current?.focus();
  }, [visible, chat.pendingDraft]);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  // Self-heal an interrupted turn (reload / network blip / a stale tab): if the
  // last assistant message is stuck in `streaming` with no live controller,
  // reconcile it against the server's durable task (A2A GetTask) — finalize when
  // terminal, polling briefly if it's genuinely still running. Without this an
  // interrupted stream would spin forever even though the server completed the
  // turn while we were away.
  useEffect(() => {
    if (abortRef.current) return; // a live turn in this slot owns the stream
    const snap = chatStore.getSnapshot().sessions.find((s) => s.id === sessionId);
    const last = [...(snap?.messages || [])].reverse().find((m) => m.role === "assistant");
    if (!last || last.status !== "streaming" || !last.taskId || !last.id) return;

    const assistantId = last.id;
    const taskId = last.taskId;
    const TERMINAL = /completed|failed|canceled|cancelled/i;
    let cancelled = false;
    let polls = 0;
    const MAX_POLLS = 40; // ~2 min at 3s — then give up and leave it as-is

    function finalize(state: string, text: string) {
      const cur = chatStore.getSnapshot().sessions.find((s) => s.id === sessionId);
      if (!cur) return;
      const failed = /fail|cancel/i.test(state);
      chatStore.updateMessages(
        sessionId,
        cur.messages.map((m) => {
          if (m.id !== assistantId) return m;
          const toolCalls = m.toolCalls?.map((c) =>
            c.status === "running" ? { ...c, status: "done" as const } : c,
          );
          return { ...m, content: text || m.content, status: failed ? "error" : "done", toolCalls };
        }),
      );
      chatStore.setSessionStatus(sessionId, failed ? "error" : "idle");
    }

    async function tick() {
      if (cancelled) return;
      let res: { state: string; text: string };
      try {
        res = await api.getTask(taskId);
      } catch {
        return; // best-effort — leave the message as-is on a hard error
      }
      if (cancelled) return;
      if (!res.state || TERMINAL.test(res.state)) {
        // terminal, or the task is gone (un-stick rather than spin forever)
        finalize(res.state, res.text);
        return;
      }
      if (++polls < MAX_POLLS) window.setTimeout(() => void tick(), 3000);
    }
    void tick();
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const messages = session?.messages || [];

  const canSend = useMemo(() => Boolean(draft.trim()) && status !== "streaming", [draft, status]);

  async function send() {
    if (!session || !canSend) return;
    const content = draft.trim();
    setDraft("");
    void runTurn(content);
  }

  // Resume a paused (input-required) turn: the response rides as a follow-up
  // message on the same session — the backend (a2a_executor) sees the parked
  // input-required task on this context and resumes the agent with it. A form
  // response serializes to JSON; an approval sends "approved" / "denied".
  async function resumeHitl(response: Record<string, unknown> | string) {
    setHitl(null);
    void runTurn(typeof response === "string" ? response : JSON.stringify(response));
  }

  // Dismiss without answering: cancel the parked input-required task on the
  // backend (best-effort) so it doesn't linger and silently consume the next
  // message as its response, then clear the card.
  function dismissHitl() {
    const taskId = hitlTaskRef.current;
    hitlTaskRef.current = "";
    if (taskId) void api.cancelTask(taskId).catch(() => {});
    setHitl(null);
    if (session) chatStore.setHitlPending(session.id, false);
  }

  async function runTurn(content: string) {
    if (!session || !content) return;
    // Abort any still-in-flight stream before starting a new turn (e.g. a fast
    // HITL resume) so two SSE connections never interleave assistant messages.
    abortRef.current?.abort();
    setHitl(null);
    chatStore.setHitlPending(session.id, false);
    const userMessage: ChatMessage = {
      id: messageId(),
      role: "user",
      content,
      createdAt: Date.now(),
      status: "done",
    };
    const assistantId = messageId();
    const assistant: ChatMessage = {
      id: assistantId,
      role: "assistant",
      content: "",
      createdAt: Date.now(),
      status: "streaming",
    };

    setStatusMessage("submitted");
    const current = chatStore.getSnapshot().sessions.find((item) => item.id === session.id)?.messages || messages;
    chatStore.updateMessages(session.id, [...current, userMessage, assistant]);
    chatStore.setSessionStatus(session.id, "streaming");
    onError("");

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await api.streamChat(userMessage.content, session.id, {
        signal: controller.signal,
        onTaskId: (id) => {
          setTaskId(id);
          hitlTaskRef.current = id;
          // Persist the task id on the assistant message so a stuck `streaming`
          // turn can be reconciled against the server task after a reload.
          const cur = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
          if (cur) {
            chatStore.updateMessages(
              session.id,
              cur.messages.map((m) => (m.id === assistantId ? { ...m, taskId: id } : m)),
            );
          }
        },
        onStatus: setStatusMessage,
        onText: (text, append) => {
          const latest = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
          if (!latest) return;
          chatStore.updateMessages(
            session.id,
            latest.messages.map((message) =>
              message.id === assistantId
                ? {
                    ...message,
                    content: append ? `${message.content}${text}` : text,
                    status: "streaming",
                  }
                : message,
            ),
          );
        },
        onToolCall: (evt) => {
          const latest = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
          if (!latest) return;
          chatStore.updateMessages(
            session.id,
            latest.messages.map((message) => {
              if (message.id !== assistantId) return message;
              const calls = [...(message.toolCalls || [])];
              const idx = calls.findIndex((c) => c.id === evt.id);
              const now = Date.now();
              if (evt.phase === "start") {
                // A tool that starts while a `task` is still running is a child
                // of that subagent delegation — nest it. (Last open task wins,
                // so nested task() calls group correctly.)
                const openTask = [...calls]
                  .reverse()
                  .find((c) => c.name === "task" && c.status === "running" && c.id !== evt.id);
                const card = {
                  id: evt.id,
                  name: evt.name,
                  input: evt.input,
                  status: "running" as const,
                  startedAt: now,
                  parentId: openTask?.id,
                };
                if (idx >= 0) calls[idx] = { ...calls[idx], ...card };
                else calls.push(card);
              } else {
                // end — flip the matching card to done (or create one if the
                // start frame was missed). Stamp elapsed when we saw the start.
                const startedAt = idx >= 0 ? calls[idx].startedAt : undefined;
                const durationMs = startedAt !== undefined ? now - startedAt : undefined;
                if (idx >= 0) {
                  calls[idx] = { ...calls[idx], output: evt.output, status: "done", durationMs };
                } else {
                  calls.push({ id: evt.id, name: evt.name, output: evt.output, status: "done" });
                }
              }
              return { ...message, toolCalls: calls };
            }),
          );
        },
        onInputRequired: (payload) => {
          // The turn parked awaiting the operator. Surface the form/approval/
          // question; the stream closes here and the post-await block finalizes
          // the assistant placeholder, so the card renders without a stuck spinner.
          // (hitlTaskRef already holds this task's id, set by onTaskId.)
          setHitl(payload);
          setHitlSeq((n) => n + 1);
          chatStore.setHitlPending(session.id, true); // companion "waiting on you"
          setStatusMessage("input required");
        },
        onDone: () => {
          const latest = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
          if (!latest) return;
          chatStore.updateMessages(
            session.id,
            latest.messages.map((message) =>
              message.id === assistantId ? { ...message, status: "done" } : message,
            ),
          );
        },
      });
      // If the stream closed without a terminal frame, onDone never fired and
      // the placeholder is still "streaming" — finalize it so it doesn't persist
      // as a stuck spinner.
      const settled = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
      if (settled) {
        chatStore.updateMessages(
          session.id,
          settled.messages.map((message) =>
            message.id === assistantId && message.status === "streaming"
              ? { ...message, status: "done" }
              : message,
          ),
        );
      }
      chatStore.setSessionStatus(session.id, "idle");
      setStatusMessage("idle");
    } catch (exc) {
      if (controller.signal.aborted) {
        setStatusMessage("stopped");
        // Finalize the placeholder too — otherwise a stopped stream stays
        // "streaming" and renders a spinner that never resolves (keep any
        // partial content already streamed).
        const stopped = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
        if (stopped) {
          chatStore.updateMessages(
            session.id,
            stopped.messages.map((message) =>
              message.id === assistantId && message.status === "streaming"
                ? { ...message, status: "done" }
                : message,
            ),
          );
        }
      } else {
        const message = exc instanceof Error ? exc.message : String(exc);
        onError(message);
        setStatusMessage(message);
        chatStore.setSessionStatus(session.id, "error");
        const latest = chatStore.getSnapshot().sessions.find((item) => item.id === session.id);
        if (latest) {
          chatStore.updateMessages(
            session.id,
            latest.messages.map((item) =>
              item.id === assistantId ? { ...item, content: item.content || message, status: "error" } : item,
            ),
          );
        }
        return;
      }
      chatStore.setSessionStatus(session.id, "idle");
    } finally {
      abortRef.current = null;
      setTaskId("");
    }
  }

  async function stop() {
    if (taskId) {
      try {
        await api.cancelTask(taskId);
      } catch {
        // The local abort below still releases the UI even if the task already finished.
      }
    }
    abortRef.current?.abort();
    chatStore.setSessionStatus(sessionId, "idle");
    setStatusMessage("stopped");
  }

  if (!session) return null;

  return (
    <div className="chat-session-slot" hidden={!visible}>
      <div className="message-list" ref={listRef}>
        {messages.length === 0 ? (
          <div className="empty-state">
            <TerminalSquare size={18} />
            <span>No messages in this session.</span>
          </div>
        ) : (
          messages.map((message) => (
            <article className={`message message-${message.role}`} key={message.id || `${message.role}-${message.createdAt}`}>
              <div className="message-role">{message.role}</div>
              <div className="message-body">
                {message.toolCalls && message.toolCalls.length > 0 ? (
                  <ToolCalls calls={message.toolCalls} />
                ) : null}
                {message.content ? (
                  message.role === "assistant" ? (
                    <Markdown>{message.content}</Markdown>
                  ) : (
                    message.content
                  )
                ) : message.status === "streaming" && !(message.toolCalls && message.toolCalls.length) ? (
                  <Loader2 className="spin" size={15} />
                ) : null}
              </div>
            </article>
          ))
        )}
      </div>

      {hitl ? (
        <HitlForm
          key={hitlSeq}
          payload={hitl}
          busy={status === "streaming"}
          onSubmit={resumeHitl}
          onCancel={dismissHitl}
        />
      ) : null}

      <div className="composer-wrap">
        {slashActive ? (
          <div className="slash-menu" role="listbox">
            {slashMatches.map((cmd, index) => (
              <button
                type="button"
                key={cmd.name}
                role="option"
                aria-selected={index === slashSel}
                className={`slash-item${index === slashSel ? " active" : ""}`}
                onMouseEnter={() => setSlashIndex(index)}
                onClick={() => completeCommand(cmd)}
              >
                <span className="slash-name">/{cmd.name}</span>
                <span className="slash-desc">{cmd.usage || cmd.description}</span>
              </button>
            ))}
          </div>
        ) : null}
        <form
          className="composer"
          onSubmit={(event) => {
            event.preventDefault();
            void send();
          }}
        >
          <textarea
            ref={textareaRef}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setSlashDismissed(false); // re-open the menu when the input changes
            }}
            onKeyDown={(event) => {
              // Slash-command navigation takes priority while the menu is open.
              if (slashActive) {
                if (event.key === "ArrowDown") {
                  event.preventDefault();
                  setSlashIndex((i) => (i + 1) % slashMatches.length);
                  return;
                }
                if (event.key === "ArrowUp") {
                  event.preventDefault();
                  setSlashIndex((i) => (i - 1 + slashMatches.length) % slashMatches.length);
                  return;
                }
                if (event.key === "Enter" || event.key === "Tab") {
                  event.preventDefault();
                  completeCommand(slashMatches[slashSel]);
                  return;
                }
                if (event.key === "Escape") {
                  event.preventDefault();
                  setSlashDismissed(true);
                  return;
                }
              }
              // Enter sends; Cmd/Ctrl/Shift+Enter inserts a newline.
              if (event.key === "Enter" && !event.metaKey && !event.ctrlKey && !event.shiftKey) {
                event.preventDefault();
                void send();
              }
            }}
            placeholder="Message protoPen  (/ for commands · ⌘/Ctrl+Enter for newline)"
            rows={3}
          />
        {status === "streaming" ? (
          <div className="composer-actions">
            {statusMessage ? <span className="composer-status">{statusMessage}</span> : null}
            <button className="secondary-button" type="button" onClick={() => void stop()}>
              <Square size={15} />
              Stop
            </button>
          </div>
        ) : (
          <button className="primary-button" type="submit" disabled={!canSend}>
            <Send size={16} />
            Send
          </button>
        )}
        </form>
      </div>
    </div>
  );
}
