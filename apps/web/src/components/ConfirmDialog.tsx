import { AlertTriangle } from "lucide-react";
import { useEffect, useRef } from "react";

// Custom confirmation dialog (replaces window.confirm). For destructive actions
// it defaults focus to Cancel and only binds Escape — Enter never auto-confirms —
// so an accidental keypress can't carry out the action.
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Delete",
  cancelLabel = "Cancel",
  tone = "danger",
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "danger" | "default";
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    cancelRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  return (
    // mouseDown on the backdrop cancels; stopPropagation on the card keeps a
    // click that starts inside the card from dismissing it.
    <div className="confirm-overlay" role="dialog" aria-modal="true" aria-label={title} onMouseDown={onCancel}>
      <div className="confirm-card" onMouseDown={(event) => event.stopPropagation()}>
        <div className="confirm-head">
          {tone === "danger" ? <AlertTriangle size={18} className="confirm-icon-danger" /> : null}
          <h2>{title}</h2>
        </div>
        {message ? <p className="confirm-message">{message}</p> : null}
        <div className="confirm-actions">
          <button ref={cancelRef} className="secondary-button" type="button" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            className={`primary-button${tone === "danger" ? " danger" : ""}`}
            type="button"
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
