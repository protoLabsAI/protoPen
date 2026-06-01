import { defineConfig } from "vitepress";

export default defineConfig({
  title: "protoPen",
  description:
    "Autonomous pen-testing & AI research agent — Steam Deck + RF hardware",
  base: "/protoPen/",

  head: [["link", { rel: "icon", href: "/protoPen/favicon.svg" }]],

  themeConfig: {
    logo: "/favicon.svg",

    nav: [
      { text: "Tutorials", link: "/tutorials/" },
      { text: "Guides", link: "/guides/" },
      { text: "Reference", link: "/reference/" },
      { text: "Explanation", link: "/explanation/" },
    ],

    sidebar: {
      "/tutorials/": [
        {
          text: "Tutorials",
          items: [
            { text: "Getting Started", link: "/tutorials/" },
            { text: "Steam Deck Setup", link: "/tutorials/steam-deck-setup" },
            {
              text: "First Engagement",
              link: "/tutorials/first-engagement",
            },
          ],
        },
      ],

      "/guides/": [
        {
          text: "How-To Guides",
          items: [
            { text: "Overview", link: "/guides/" },
            { text: "Operator Console", link: "/guides/operator-console" },
            { text: "Scheduler", link: "/guides/scheduler" },
            { text: "Deploy Updates", link: "/guides/deploy-updates" },
            { text: "A2A Integration", link: "/guides/a2a-integration" },
            { text: "Lab Mode", link: "/guides/lab-mode" },
            {
              text: "Rabbit Hole (MCP)",
              link: "/guides/rabbit-hole-mcp",
            },
          ],
        },
      ],

      "/reference/": [
        {
          text: "Reference",
          items: [
            { text: "Overview", link: "/reference/" },
            { text: "API Endpoints", link: "/reference/api-endpoints" },
            { text: "Chat Commands", link: "/reference/chat-commands" },
            { text: "Tools", link: "/reference/tools" },
            { text: "Playbooks", link: "/reference/playbooks" },
            { text: "Target Intel Schema", link: "/reference/target-intel" },
            {
              text: "Engagement Modes",
              link: "/reference/engagement-modes",
            },
            {
              text: "Environment Variables",
              link: "/reference/environment-variables",
            },
            { text: "Configuration", link: "/reference/configuration" },
          ],
        },
      ],

      "/explanation/": [
        {
          text: "Explanation",
          items: [
            { text: "Overview", link: "/explanation/" },
            { text: "Architecture", link: "/explanation/architecture" },
            { text: "The Control Stack", link: "/explanation/control-stack" },
            {
              text: "Knowledge Search",
              link: "/explanation/knowledge-search",
            },
            {
              text: "Auto-Ingestion Pipeline",
              link: "/explanation/auto-ingestion",
            },
            { text: "Security Model", link: "/explanation/security-model" },
          ],
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
