/**
 * src/main.jsx — React Entry Point
 * ==================================
 * Three jobs:
 *   1. Import global CSS (Tailwind + custom styles)
 *   2. Import the root App component
 *   3. Mount App into <div id="root"> from index.html
 *
 * NOTE ON REACT IMPORT:
 * vite.config.js uses jsxRuntime: "automatic" which means Vite/Babel
 * automatically injects the React JSX transform into every file that uses
 * JSX syntax. You do NOT need `import React from "react"` anymore.
 * In React 17+ the automatic runtime handles <StrictMode>, <App />, etc.
 * Adding `import React` causes a lint warning ("value never read") because
 * it's genuinely never used when the automatic runtime is active.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./index.css";
import App from "./App.jsx";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
);