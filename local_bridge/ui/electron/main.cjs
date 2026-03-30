/**
 * electron/main.cjs
 * ==================
 * Electron MAIN PROCESS — this is the "backend" side of Electron.
 * It runs in Node.js and is responsible for:
 *
 *   1. Creating the native OS window (BrowserWindow)
 *   2. Loading your React app into that window
 *      → In development: loads http://localhost:5173 (Vite dev server)
 *      → In production:  loads dist/index.html from the built files
 *   3. Handling OS-level things (menus, tray, file system, notifications)
 *   4. Keeping macOS app alive when all windows are closed (standard Mac UX)
 *
 * WHY .cjs EXTENSION?
 * package.json has "type": "module" (needed for Vite/ESM).
 * Electron's main process uses CommonJS (require/module.exports).
 * The .cjs extension forces Node to treat THIS file as CommonJS,
 * even though the rest of the project uses ESM. No conflict.
 *
 * THIS FILE IS NEVER SENT TO THE BROWSER.
 * It runs only on your computer, in the Electron process.
 */

"use strict";

const { app, BrowserWindow, shell, Menu, nativeTheme } = require("electron");
const path = require("path");

// ─────────────────────────────────────────────────────────────────────────────
// Environment detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * app.isPackaged is true ONLY when the app has been built into a distributable
 * (e.g. .exe, .dmg, .AppImage) with electron-builder.
 * During development (`npm run app:dev`), it is always false.
 */
const IS_DEV = !app.isPackaged;

/**
 * The URL Electron loads in development.
 * Must match the port in vite.config.js → server.port
 */
const VITE_DEV_SERVER_URL = "http://localhost:5173";

// ─────────────────────────────────────────────────────────────────────────────
// Force dark mode at the OS level
// ─────────────────────────────────────────────────────────────────────────────
nativeTheme.themeSource = "dark";

// ─────────────────────────────────────────────────────────────────────────────
// Window creation
// ─────────────────────────────────────────────────────────────────────────────

/** @type {BrowserWindow | null} */
let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    // ── Window dimensions ──────────────────────────────────────────────────
    width:     1440,
    height:    900,
    minWidth:  960,
    minHeight: 640,

    // ── Appearance ────────────────────────────────────────────────────────
    // Match zinc-950 exactly so there's no white flash before React loads
    backgroundColor: "#09090b",

    // On macOS: hides the title bar but keeps the traffic-light buttons,
    // giving a clean modern look. On Windows/Linux: uses the default title bar.
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",

    // App title shown in the title bar on Windows and in the Dock on macOS
    title: "Oxbuild Compliance Agent",

    // ── Performance: don't show until fully loaded ─────────────────────────
    // Without this, you'd see the window appear blank for a split second.
    show: false,

    // ── Security settings ─────────────────────────────────────────────────
    webPreferences: {
      // preload.cjs runs in the renderer but has access to Node APIs.
      // It's the safe bridge between your React code and Electron.
      preload: path.join(__dirname, "preload.cjs"),

      // contextIsolation: MUST be true for security.
      // Keeps the preload script's Node environment separate from the
      // React app's browser environment. Prevents XSS from escaping to Node.
      contextIsolation: true,

      // nodeIntegration: MUST be false for security.
      // Prevents your React code from directly calling require() and
      // accessing the file system or other Node APIs.
      nodeIntegration: false,

      // Disable web security ONLY in development for the Vite proxy to work.
      // In production this is always true (secure).
      webSecurity: !IS_DEV,
    },
  });

  // ── Load the app ──────────────────────────────────────────────────────────

  if (IS_DEV) {
    // Development: load from the Vite dev server running at localhost:5173
    // This gives you Hot Module Replacement (instant UI updates on save)
    mainWindow.loadURL(VITE_DEV_SERVER_URL);

    // Open Chrome DevTools automatically in development
    // You can also open it manually: View → Toggle Developer Tools
    mainWindow.webContents.openDevTools({ mode: "right" });
  } else {
    // Production: load the built index.html file from the dist folder
    // path.join(__dirname, "../dist/index.html") resolves to:
    // local_bridge/ui/dist/index.html — the output of `npm run build`
    mainWindow.loadFile(path.join(__dirname, "../dist/index.html"));
  }

  // ── Show window only once it's fully loaded ───────────────────────────────
  mainWindow.once("ready-to-show", () => {
    mainWindow.show();

    // On macOS, focus the window after showing it
    if (process.platform === "darwin") {
      app.focus({ steal: true });
    }
  });

  // ── Handle external links ─────────────────────────────────────────────────
  // Any link that would open a new window (e.g. target="_blank")
  // opens in the user's default browser instead of a new Electron window.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Only open external URLs in the browser, not local app URLs
    if (url.startsWith("http") && !url.startsWith(VITE_DEV_SERVER_URL)) {
      shell.openExternal(url);
    }
    // Always deny opening new Electron windows
    return { action: "deny" };
  });

  // Cleanup reference when window is closed
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Native application menu (minimal — hides irrelevant items)
// ─────────────────────────────────────────────────────────────────────────────

function buildMenu() {
  const isMac = process.platform === "darwin";

  const template = [
    // macOS app menu (the one with the app name)
    ...(isMac
      ? [
          {
            label: app.name,
            submenu: [
              { role: "about" },
              { type: "separator" },
              { role: "services" },
              { type: "separator" },
              { role: "hide" },
              { role: "hideOthers" },
              { role: "unhide" },
              { type: "separator" },
              { role: "quit" },
            ],
          },
        ]
      : []),

    // File menu
    {
      label: "File",
      submenu: [isMac ? { role: "close" } : { role: "quit" }],
    },

    // Edit menu (enables copy/paste keyboard shortcuts)
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },

    // View menu
    {
      label: "View",
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        // Show DevTools only in development
        ...(IS_DEV ? [{ role: "toggleDevTools" }] : []),
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },

    // Window menu
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        ...(isMac
          ? [
              { type: "separator" },
              { role: "front" },
              { type: "separator" },
              { role: "window" },
            ]
          : [{ role: "close" }]),
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// ─────────────────────────────────────────────────────────────────────────────
// App lifecycle events
// ─────────────────────────────────────────────────────────────────────────────

/**
 * app.whenReady() fires when Electron has finished initialising
 * and is ready to create browser windows.
 * You must NOT create BrowserWindow before this event.
 */
app.whenReady().then(() => {
  buildMenu();
  createWindow();

  // macOS: re-create window when dock icon is clicked and no windows exist
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

/**
 * Quit the app when all windows are closed.
 * EXCEPTION: macOS convention is to keep the app running (in the Dock)
 * even when all windows are closed, until the user explicitly quits.
 * The 'activate' event above handles re-opening the window on macOS.
 */
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Security: block navigation away from the app
// ─────────────────────────────────────────────────────────────────────────────

app.on("web-contents-created", (_, contents) => {
  // Prevent navigating to arbitrary URLs (protects against XSS attacks
  // that try to redirect the window to an external malicious page)
  contents.on("will-navigate", (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    const allowedOrigins = ["http://localhost:5173", "file://"];
    const isAllowed = allowedOrigins.some(
      (origin) =>
        parsedUrl.origin === origin || navigationUrl.startsWith(origin)
    );
    if (!isAllowed) {
      event.preventDefault();
    }
  });
});
