import { Activity, Boxes, MessageSquare, ScrollText, Target } from "lucide-react";
import type { ReactNode } from "react";

// Bottom thumb-nav for the handheld/Deck chat-first shell — replaces the far-left
// vertical rail (a poor thumb-reach pattern on a 7″ handheld). Drives the same
// `surface` state the desktop rail does, so every surface is reused untouched.
// "Chat" maps to the `home` surface (chat is the root there). System lives on a
// topbar gear; Terminal is desktop-only for now.
// See docs/plans/2026-07-22-chat-first-deck-ui.md (P0).

type Item = { id: string; label: string; icon: ReactNode };

// Surface order — also what the gamepad's bumpers cycle through (P3), hence
// exported rather than kept private to the nav.
export const NAV_SURFACES = ["home", "engagement", "findings", "activity", "capabilities"];

const ITEMS: Item[] = [
  { id: "home", label: "Chat", icon: <MessageSquare size={22} /> },
  { id: "engagement", label: "Engage", icon: <Target size={22} /> },
  { id: "findings", label: "Findings", icon: <ScrollText size={22} /> },
  { id: "activity", label: "Activity", icon: <Activity size={22} /> },
  { id: "capabilities", label: "Tools", icon: <Boxes size={22} /> },
];

export function BottomNav({
  surface,
  onSelect,
  activityUnread = 0,
  chatStreaming = false,
  driveActive = false,
}: {
  surface: string;
  onSelect: (surface: string) => void;
  activityUnread?: number;
  chatStreaming?: boolean;
  // A goal is driving somewhere — including headless, with nothing streaming
  // into this browser. Worth a standing marker on Chat: the companion is working
  // even when the screen is idle (P2).
  driveActive?: boolean;
}) {
  return (
    <nav className="thumbnav" aria-label="Primary">
      {ITEMS.map((item) => {
        const active = surface === item.id;
        // A turn streaming into chat while you're on another surface earns a dot on
        // Chat — as does an active drive, which may be running with nothing streaming.
        const dot = item.id === "home" && (chatStreaming || driveActive) && surface !== "home";
        const badge = item.id === "activity" && activityUnread > 0 ? activityUnread : 0;
        return (
          <button
            key={item.id}
            type="button"
            className={`nav-item ${active ? "active" : ""}`}
            aria-current={active ? "page" : undefined}
            onClick={() => onSelect(item.id)}
          >
            <span className="nav-icon">
              {item.icon}
              {dot ? (
                <span className={`nav-dot ${!chatStreaming && driveActive ? "drive" : ""}`} aria-hidden="true" />
              ) : null}
              {badge ? <span className="nav-badge">{badge > 9 ? "9+" : badge}</span> : null}
            </span>
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}
