/**
 * electron/preload.cjs
 * =====================
 * The PRELOAD SCRIPT runs in a special in-between environment:
 *   - It has access to Node.js APIs (like `require`)
 *   - It also has access to browser APIs (like `window`, `document`)
 *   - But it is ISOLATED from the React app's JavaScript context
 *
 * Think of it as a secure messenger between your React UI and Electron.
 *
 * HOW IT WORKS:
 *   1. This script runs before your React app loads
 *   2. It uses contextBridge.exposeInMainWorld() to safely inject
 *      specific values/functions into the window object
 *   3. Your React code can then call window.electronAPI.platform etc.
 *   4. NO Node.js APIs leak into the React context — only what you
 *      explicitly expose here is accessible
 *
 * ADDING YOUR OWN APIS:
 * To let React call something in Electron (e.g. open a file dialog),
 * you would add it here as an exposed function.
 *
 * Example (not active — just showing the pattern):
 *   ipcRenderer.invoke("open-file-dialog") → triggers main.cjs handler
 */

"use strict";

const { contextBridge, ipcRenderer } = require("electron");

// ─────────────────────────────────────────────────────────────────────────────
// Expose safe APIs to the React renderer (window.electronAPI)
// ─────────────────────────────────────────────────────────────────────────────

contextBridge.exposeInMainWorld("electronAPI", {
  // ── Platform info ──────────────────────────────────────────────────────────
  // Lets React know it's running inside Electron and on which OS.
  // Usage in React: window.electronAPI.platform → "darwin" | "win32" | "linux"
  platform: process.platform,

  // Operating system: "darwin" (macOS), "win32" (Windows), "linux"
  isElectron: true,

  // ── Version info ───────────────────────────────────────────────────────────
  versions: {
    electron: process.versions.electron,
    node:     process.versions.node,
    chrome:   process.versions.chrome,
  },

  // ── App info ───────────────────────────────────────────────────────────────
  // To get the app version: window.electronAPI.getAppVersion()
  getAppVersion: () => ipcRenderer.invoke("get-app-version"),

  // ── Window controls (for custom title bars) ────────────────────────────────
  // If you build a custom title bar in React, wire these up.
  // Usage: window.electronAPI.minimizeWindow()
  minimizeWindow: () => ipcRenderer.send("window-minimize"),
  maximizeWindow: () => ipcRenderer.send("window-maximize"),
  closeWindow:    () => ipcRenderer.send("window-close"),
});

// ─────────────────────────────────────────────────────────────────────────────
// Console log so you can see the preload ran in DevTools
// ─────────────────────────────────────────────────────────────────────────────
console.log(
  "[Oxbuild] Preload executed | platform:",
  process.platform,
  "| electron:",
  process.versions.electron
);
