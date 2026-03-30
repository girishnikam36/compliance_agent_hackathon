/** @type {import('tailwindcss').Config} */

/**
 * tailwind.config.js — Oxbuild Compliance Agent
 * ================================================
 * CRITICAL FIX: package.json has "type": "module" which makes every .js
 * file in this project run as an ES Module. That means require() does NOT
 * exist here. The previous version used require("@tailwindcss/typography")
 * which crashed Tailwind's config loader silently — Tailwind would start,
 * read this file, hit the require(), throw a ReferenceError internally,
 * and fall back to generating ZERO utility classes. This is why the entire
 * layout was broken: bg-zinc-950, flex, grid, rounded-xl etc. never applied.
 *
 * Rule: In a "type":"module" project, tailwind.config.js must use only
 * ES Module syntax. Either:
 *   A) import plugins at the top (used here), or
 *   B) rename the file to tailwind.config.cjs and use module.exports = {}
 *
 * App.jsx uses no prose or form-* plugin classes, so the plugins are
 * removed entirely. Add them back with ESM imports if needed later.
 */

export default {
  // ── Dark mode ─────────────────────────────────────────────────────────────
  // "class" strategy: dark mode activates when <html class="dark"> is set.
  // index.html already has class="dark" on the <html> tag statically,
  // so the app is always dark without any JavaScript toggle needed.
  darkMode: "class",

  // ── Content paths — tells Tailwind which files to scan for class names ────
  // Tailwind v3 uses JIT (Just-In-Time) compilation by default.
  // It reads every file listed here, finds every Tailwind class name used,
  // and generates ONLY those classes in the final CSS output.
  // If a file is missing from this list, classes in that file won't work.
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],

  theme: {
    // ── Font families ──────────────────────────────────────────────────────
    // Override the default font stacks so Tailwind's font-mono and font-sans
    // classes use our terminal fonts.
    fontFamily: {
      mono: [
        "Geist Mono",
        "JetBrains Mono",
        "Cascadia Code",
        "ui-monospace",
        "Fira Code",
        "monospace",
      ],
      sans: [
        "Geist",
        "Geist Mono",
        "system-ui",
        "sans-serif",
      ],
    },

    extend: {
      // ── Custom animations used in App.jsx ─────────────────────────────────
      // These power the phase step indicators (animate-ping),
      // the loading spinner, and the fade-in list stagger.
      keyframes: {
        "caret-blink": {
          "0%, 100%": { opacity: "1" },
          "50%":       { opacity: "0" },
        },
        "fade-up": {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "spin-cw": {
          from: { transform: "rotate(0deg)"   },
          to:   { transform: "rotate(360deg)" },
        },
        "glow-pulse": {
          "0%, 100%": { boxShadow: "0 0 8px rgba(74,222,128,0.2)"  },
          "50%":       { boxShadow: "0 0 20px rgba(74,222,128,0.4)" },
        },
      },

      animation: {
        "caret-blink": "caret-blink 1.1s step-end infinite",
        "fade-up":     "fade-up 0.3s ease both",
        "spin-fast":   "spin-cw 0.6s linear infinite",
        "spin-slow":   "spin-cw 2s linear infinite",
        "glow-pulse":  "glow-pulse 2.5s ease infinite",
      },

      // ── Custom box shadows used in App.jsx ────────────────────────────────
      boxShadow: {
        "glow-green":    "0 0 0 1px rgba(74,222,128,0.25), 0 0 16px rgba(74,222,128,0.12)",
        "glow-critical": "0 0 0 1px rgba(248,113,113,0.25), 0 0 16px rgba(248,113,113,0.10)",
        "focus-ring":    "0 0 0 2px rgba(74,222,128,0.50)",
      },
    },
  },

  // ── Plugins ───────────────────────────────────────────────────────────────
  // Empty array — no plugins needed.
  // If you add @tailwindcss/typography later, use ESM import:
  //
  //   import typography from "@tailwindcss/typography";
  //   ...
  //   plugins: [typography],
  //
  // DO NOT use require() — it will break silently in "type":"module" projects.
  plugins: [],
};