import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  // Prefix "PROTO" loads both PROTOPEN_* (current) and PROTOAGENT_* (legacy).
  const env = loadEnv(mode, new URL("../..", import.meta.url).pathname, "PROTO");
  const apiBase = env.PROTOPEN_API_BASE || env.PROTOAGENT_API_BASE || "http://127.0.0.1:7870";

  return {
    base: "/app/",
    plugins: [react()],
    build: {
      rollupOptions: {
        output: {
          // Split the React runtime into its own long-lived vendor chunk. The
          // package-boundary regex avoids matching react-markdown / sibling
          // packages so the lazily-loaded markdown chunk stays separate.
          manualChunks(id) {
            if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
              return "react-vendor";
            }
          },
        },
      },
    },
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
