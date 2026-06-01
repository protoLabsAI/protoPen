import { useState } from "react";
import type { ReactNode } from "react";

// Lightweight custom popover shown on hover/focus of its trigger (a styled
// replacement for native title tooltips — richer content, themed). Anchored to
// the trigger; `placement` controls which way it opens.
export function HoverPopover({
  children,
  content,
  placement = "bottom-end",
  label,
}: {
  children: ReactNode;
  content: ReactNode;
  placement?: "bottom-end" | "bottom-start" | "bottom-center" | "top-end";
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="popover-anchor"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open ? (
        <div className={`popover popover-${placement}`} role="tooltip" aria-label={label}>
          {content}
        </div>
      ) : null}
    </div>
  );
}
