import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, new URL("../..", import.meta.url).pathname, "PROTOPEN_");
  const apiBase = env.PROTOPEN_API_BASE || "http://127.0.0.1:7870";

  return {
    base: "/app/",
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": apiBase,
        "/a2a": apiBase,
        "/v1": apiBase,
      },
    },
  };
});
