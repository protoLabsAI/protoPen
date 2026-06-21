// protoLabs.studio VitePress theme — extends the default theme and maps
// VitePress's --vp-* variables to the @protolabsai/design brand tokens, so the
// docs site stays brand-consistent from one source (no per-repo color drift).
// Pair with `appearance: "force-dark"` in config.mts.
import theme from "@protolabsai/vitepress-theme";
import "./custom.css"; // green brand override (after the theme — see custom.css)

export default theme;
