// @ts-check
import { defineConfig } from "astro/config";

// Marketing site for protoPen / pwndeck. Served at pen.protolabs.studio, with the
// VitePress docs folded in at /docs by the marketing-deploy workflow.
export default defineConfig({
  site: "https://pen.protolabs.studio",
  output: "static",
});
