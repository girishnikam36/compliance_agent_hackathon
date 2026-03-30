/**
 * postcss.config.js — Oxbuild Compliance Agent
 * ==============================================
 * This file MUST exist for Vite to run PostCSS plugins on your CSS files.
 * Without it, @tailwind directives in index.css are silently ignored and
 * no utility classes are generated.
 *
 * WHY THIS FILE WAS MISSING (and why the CDN workaround was used):
 * The project uses "type": "module" in package.json. PostCSS historically
 * loaded its config via CommonJS require(). In older setups this caused
 * a conflict. However, Vite 4+ ships its own PostCSS loader that handles
 * both ESM and CJS postcss.config files correctly — so this just works.
 *
 * The two plugins:
 *   tailwindcss  — reads tailwind.config.js, scans content files,
 *                  generates utility classes from @tailwind directives
 *   autoprefixer — adds vendor prefixes (-webkit-, -moz-, etc.)
 *                  to CSS properties that need them for cross-browser support
 *
 * Vite automatically picks up this file and runs PostCSS on every
 * .css file imported in your project (including index.css).
 */
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};