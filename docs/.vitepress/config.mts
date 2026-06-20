import { defineConfig } from "vitepress";

// Base path + canonical URL are env-overridable so the same docs build serves
// two homes: GitHub Pages at /protoPen/ (default) and, folded into the marketing
// bundle by marketing-deploy.yml, pen.protolabs.studio/docs/ (DOCS_BASE=/docs/).
const BASE = process.env.DOCS_BASE || "/protoPen/";
const SITE_URL = process.env.DOCS_SITE_URL || "https://protolabsai.github.io/protoPen/";
const OG_IMAGE = `${SITE_URL}og-image.png`;
const TITLE = "protoPen — Autonomous Security Research & Pen-Testing Agent";
const DESCRIPTION =
  "Autonomous pen-testing & AI research agent — Steam Deck + RF hardware";

export default defineConfig({
  title: "protoPen",
  description: DESCRIPTION,
  base: BASE,

  // Dark, brand-first ground — the @protolabsai/vitepress-theme (docs/.vitepress/
  // theme) is dark-first like the marketing site; this pins it and drops the
  // light/dark toggle.
  appearance: "force-dark",

  // Internal working docs — kept in the repo for reference, NOT published to the
  // docs site. Plans/specs/research/superpowers are planning + design artifacts,
  // not user-facing documentation.
  srcExclude: [
    "plans/**",
    "specs/**",
    "research/**",
    "superpowers/**",
  ],

  head: [
    ["link", { rel: "icon", href: `${BASE}favicon.svg` }],
    // Open Graph + Twitter card — absolute image URL so social scrapers resolve it.
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: TITLE }],
    ["meta", { property: "og:description", content: DESCRIPTION }],
    ["meta", { property: "og:image", content: OG_IMAGE }],
    ["meta", { property: "og:url", content: SITE_URL }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:title", content: TITLE }],
    ["meta", { name: "twitter:description", content: DESCRIPTION }],
    ["meta", { name: "twitter:image", content: OG_IMAGE }],
  ],

  themeConfig: {
    logo: "/favicon.svg",

    nav: [
      { text: "Tutorials", link: "/tutorials/" },
      { text: "Guides", link: "/guides/" },
      { text: "Reference", link: "/reference/" },
      { text: "Explanation", link: "/explanation/" },
    ],

    // Fleet docs standard: Diátaxis at the top level (Tutorials / Guides /
    // Reference / Explanation), then a consistent DOMAIN taxonomy within each
    // section (reused names: Getting started · Engagements & operations ·
    // Autonomy & control · Knowledge & intelligence · Interfaces & protocols ·
    // Tools & extension · Platform & configuration).
    sidebar: {
      "/tutorials/": [
        { text: "Tutorials", items: [{ text: "Overview", link: "/tutorials/" }] },
        {
          text: "Getting started",
          items: [{ text: "Steam Deck Setup", link: "/tutorials/steam-deck-setup" }],
        },
        {
          text: "Engagements & operations",
          items: [{ text: "First Engagement", link: "/tutorials/first-engagement" }],
        },
      ],

      "/guides/": [
        { text: "Guides", items: [{ text: "Overview", link: "/guides/" }] },
        {
          text: "Autonomy & control",
          items: [{ text: "Scheduler", link: "/guides/scheduler" }],
        },
        {
          text: "Interfaces & protocols",
          items: [
            { text: "Operator Console", link: "/guides/operator-console" },
            { text: "A2A Integration", link: "/guides/a2a-integration" },
            { text: "Discord Integration", link: "/guides/discord-integration" },
          ],
        },
        {
          text: "Platform & configuration",
          items: [{ text: "Deploy Updates", link: "/guides/deploy-updates" }],
        },
      ],

      "/reference/": [
        { text: "Reference", items: [{ text: "Overview", link: "/reference/" }] },
        {
          text: "Autonomy & control",
          items: [
            { text: "Goals (Autonomy)", link: "/reference/goals" },
            { text: "Playbooks", link: "/reference/playbooks" },
          ],
        },
        {
          text: "Engagements & operations",
          items: [{ text: "Engagement Modes", link: "/reference/engagement-modes" }],
        },
        {
          text: "Knowledge & intelligence",
          items: [{ text: "Target Intel Schema", link: "/reference/target-intel" }],
        },
        {
          text: "Interfaces & protocols",
          items: [
            { text: "API Endpoints", link: "/reference/api-endpoints" },
            { text: "Chat Commands", link: "/reference/chat-commands" },
            { text: "Integrated Terminal", link: "/reference/terminal" },
          ],
        },
        {
          text: "Tools & extension",
          items: [
            { text: "Tools", link: "/reference/tools" },
            { text: "Adding a Tool", link: "/reference/adding-a-tool" },
          ],
        },
        {
          text: "Platform & configuration",
          items: [
            { text: "Configuration", link: "/reference/configuration" },
            { text: "Environment Variables", link: "/reference/environment-variables" },
          ],
        },
      ],

      "/explanation/": [
        { text: "Explanation", items: [{ text: "Overview", link: "/explanation/" }] },
        {
          text: "Autonomy & control",
          items: [
            { text: "Autonomy & Self-Driving", link: "/explanation/autonomy" },
            { text: "The Control Stack", link: "/explanation/control-stack" },
          ],
        },
        {
          text: "Knowledge & intelligence",
          items: [
            { text: "Knowledge Search", link: "/explanation/knowledge-search" },
            { text: "Auto-Ingestion Pipeline", link: "/explanation/auto-ingestion" },
          ],
        },
        {
          text: "Engagements & operations",
          items: [{ text: "Security Model", link: "/explanation/security-model" }],
        },
        {
          text: "Platform & configuration",
          items: [{ text: "Architecture", link: "/explanation/architecture" }],
        },
      ],
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/protoLabsAI/protoPen" },
    ],

    search: {
      provider: "local",
    },

    footer: {
      message: "Part of the protoLabs autonomous development studio.",
      copyright: "© 2026 protoLabs.studio",
    },
  },
});
