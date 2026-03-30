import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

/**
 * vite.config.js — Oxbuild Compliance Agent
 * ==========================================
 * Works for both:
 *   Browser:  npm run dev     → http://localhost:5173
 *   Electron: npm run app:dev → Electron window loads from Vite dev server
 *   Build:    npm run build   → dist/ folder Electron loads in production
 *
 * base: "./" is REQUIRED for Electron.
 * Electron loads dist/index.html from the file system (not a server),
 * so all JS/CSS asset paths must be relative, not absolute (/assets/...).
 *
 * CHANGES FROM ORIGINAL:
 *   - Removed "recharts" from manualChunks — it is not in package.json
 *     dependencies. Having it there caused Rollup to warn/error on build.
 *     Add it back + `npm install recharts` if you need charting later.
 */
export default defineConfig({
  plugins: [
    react({
      // Automatic JSX runtime — React 17+ behaviour.
      // You don't need `import React from 'react'` in every file.
      jsxRuntime: "automatic",
    }),
  ],

  resolve: {
    alias: {
      // Lets you write `import X from "@/components/X"` instead of
      // relative paths like `../../components/X`.
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // Relative base = assets work from file:// (Electron) AND http:// (browser)
  base: "./",

  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // Proxy /api/* requests to the FastAPI backend during development.
      // In production, Electron talks directly to localhost:8000.
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          // Split vendor bundles for better caching.
          // Only list packages that are actually in dependencies.
          "vendor-react":  ["react", "react-dom"],
          "vendor-lucide": ["lucide-react"],
          // "vendor-recharts": ["recharts"],  ← add back if you install recharts
        },
      },
    },
  },
});