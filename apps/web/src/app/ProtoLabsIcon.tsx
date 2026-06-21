/**
 * The protoLabs.studio bot mark, from protoContent's brand assets
 * (docs/assets/brand/protolabs-icon{,-outline}.svg). Rendered as a crisp inline
 * SVG (vs a static <img>) so the loading screens can take the console's green
 * accent (var(--accent)) rather than a hardcoded brand color.
 *
 * Per brand rules the mark itself is never deformed; only the icon background
 * may be recolored.
 *
 * - `flat` (default): green-accent rounded square + white robot — the app/brand
 *   icon at moderate sizes.
 * - `outline`: face-only green-accent strokes on transparent — for inline-with-
 *   text / no-compete contexts (what the launch splash + boot gate use).
 * - `white`: white robot, no background — for dark chrome (e.g. a title bar).
 */
export function ProtoLabsIcon({
  size = 64,
  variant = "flat",
  className,
  decorative = false,
}: {
  size?: number;
  variant?: "flat" | "outline" | "white";
  className?: string;
  /** When true the SVG is hidden from a11y (the labelled container carries the
   *  name) — avoids a redundant nested "protoLabs.studio" announcement. */
  decorative?: boolean;
}) {
  const robotStroke = variant === "outline" ? "var(--accent)" : "#ffffff";
  const a11y = decorative
    ? { "aria-hidden": true as const }
    : { role: "img", "aria-label": "protoLabs.studio" };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 256 256"
      className={className}
      {...a11y}
    >
      {variant === "flat" && (
        <rect x="16" y="16" width="224" height="224" rx="56" fill="var(--accent)" />
      )}
      <g
        transform="translate(224, 32) scale(-8, 8)"
        fill="none"
        stroke={robotStroke}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 8V4H8" />
        <rect width="16" height="12" x="4" y="8" rx="2" />
        <path d="M2 14h2" />
        <path d="M20 14h2" />
        <path d="M15 13v2" />
        <path d="M9 13v2" />
      </g>
    </svg>
  );
}
