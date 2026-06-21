/**
 * The protoPen alien mark — an inline SVG (vs a static <img>) so the loading
 * screens render a crisp vector and can recolor it to the app's lavender chrome
 * accent (#9b87f2) rather than the brand-default violet (#7c3aed), which is
 * muddy on the dark background. Alien head from Phosphor Icons (MIT).
 *
 * - `flat` (default): lavender rounded square + white alien — the app/brand
 *   icon at moderate sizes.
 * - `outline`: alien strokes on transparent — for inline-with-text / no-compete
 *   contexts (what the launch splash + boot gate use).
 * - `white`: white alien, no background — for dark chrome (e.g. a title bar).
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
   *  name) — avoids a redundant nested "protoPen" announcement. */
  decorative?: boolean;
}) {
  const markStroke = variant === "outline" ? "#9b87f2" : "#ffffff";
  const a11y = decorative
    ? { "aria-hidden": true as const }
    : { role: "img", "aria-label": "protoPen" };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 256 256"
      className={className}
      {...a11y}
    >
      {variant === "flat" && (
        <rect x="16" y="16" width="224" height="224" rx="56" fill="#9b87f2" />
      )}
      <g
        fill="none"
        stroke={markStroke}
        strokeWidth={16}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M216,112c0,48.6-56,120-88,120S40,160.6,40,112a88,88,0,0,1,176,0Z" />
        <path
          d="M80,104h0a32,32,0,0,1,32,32v0a8,8,0,0,1-8,8h0a32,32,0,0,1-32-32v0a8,8,0,0,1,8-8Z"
          transform="translate(184 248) rotate(-180)"
        />
        <path d="M176,104h0a8,8,0,0,1,8,8v0a32,32,0,0,1-32,32h0a8,8,0,0,1-8-8v0a32,32,0,0,1,32-32Z" />
        <line x1="112" y1="184" x2="144" y2="184" />
      </g>
    </svg>
  );
}
