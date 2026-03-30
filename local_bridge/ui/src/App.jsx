/**
 * App.jsx — Oxbuild Compliance Agent | React Dashboard
 * ======================================================
 * Single-page application for the full local-first compliance pipeline.
 * Theme: Dark mode, Linear/Vercel-inspired, monospace-heavy, minimal chrome.
 *
 * Stack: React 18 + Tailwind CSS (JIT)
 * Fonts: "Geist Mono" (code), "Geist" (UI) — loaded via @fontsource or CDN
 */

import { useState, useCallback, useRef, useEffect } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// Constants & helpers
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE = "http://localhost:8000/api/v1";

const SEVERITY_META = {
  CRITICAL: { color: "text-red-400",    bg: "bg-red-950/60",    border: "border-red-800/70",   dot: "bg-red-500"    },
  HIGH:     { color: "text-orange-400", bg: "bg-orange-950/60", border: "border-orange-800/70", dot: "bg-orange-500" },
  MEDIUM:   { color: "text-yellow-400", bg: "bg-yellow-950/40", border: "border-yellow-800/60", dot: "bg-yellow-500" },
  LOW:      { color: "text-sky-400",    bg: "bg-sky-950/40",    border: "border-sky-800/60",    dot: "bg-sky-500"    },
  INFO:     { color: "text-zinc-400",   bg: "bg-zinc-900/60",   border: "border-zinc-700/60",   dot: "bg-zinc-500"   },
};

const RISK_META = {
  CRITICAL: { color: "text-red-400",    track: "bg-red-500",    glow: "shadow-red-900" },
  HIGH:     { color: "text-orange-400", track: "bg-orange-500", glow: "shadow-orange-900" },
  MEDIUM:   { color: "text-yellow-400", track: "bg-yellow-400", glow: "shadow-yellow-900" },
  LOW:      { color: "text-sky-400",    track: "bg-sky-500",    glow: "shadow-sky-900" },
  MINIMAL:  { color: "text-emerald-400",track: "bg-emerald-500",glow: "shadow-emerald-900" },
};

const SAMPLE_CODE = `# User data access — pending compliance review
import psycopg2

DB_URL = "postgresql://admin:[PII_API_KEY_3F2A1B0C]@[PII_IPV4_A1B2C3D4]:5432/userdb"

def get_all_users():
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")          # returns all columns
    return cursor.fetchall()

def log_user_activity(user_id, action):
    user = get_all_users()
    print(f"User {user_id} ({user.email}): {action}")   # logs PII to stdout

def process_payment(user_id, card_number):
    # Store card number for retry logic — DO NOT deploy
    cache.set(f"card:{user_id}", card_number, ttl=3600)
    return charge(card_number)
`;

function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}

function formatEur(n) {
  if (n >= 1_000_000) return `€${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `€${(n / 1_000).toFixed(0)}K`;
  return `€${n.toFixed(0)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

/** Pulsing animated indicator dot */
function StatusDot({ active, color = "bg-emerald-400" }) {
  return (
    <span className="relative flex h-2 w-2">
      {active && (
        <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-75", color)} />
      )}
      <span className={cn("relative inline-flex rounded-full h-2 w-2", active ? color : "bg-zinc-600")} />
    </span>
  );
}

/** Phase step indicator in the top bar */
function PhaseStep({ number, label, state }) {
  // state: "idle" | "active" | "done" | "error"
  const stateStyles = {
    idle:   "text-zinc-600 border-zinc-800",
    active: "text-sky-400  border-sky-600 animate-pulse",
    done:   "text-emerald-400 border-emerald-700",
    error:  "text-red-400  border-red-800",
  };
  return (
    <div className="flex items-center gap-2">
      <div className={cn(
        "flex items-center justify-center w-5 h-5 rounded-full border text-[10px] font-mono font-bold transition-all duration-500",
        stateStyles[state]
      )}>
        {state === "done" ? "✓" : state === "error" ? "✕" : number}
      </div>
      <span className={cn("text-xs font-mono hidden md:block transition-colors duration-500", stateStyles[state])}>
        {label}
      </span>
    </div>
  );
}

/** Monospace code block with optional line numbers */
function CodeBlock({ code, className, showLines = true, label }) {
  const lines = (code || "").split("\n");
  return (
    <div className={cn("relative rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden", className)}>
      {label && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800 bg-zinc-900/50">
          <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">{label}</span>
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-zinc-700" />
            <div className="w-2.5 h-2.5 rounded-full bg-zinc-700" />
            <div className="w-2.5 h-2.5 rounded-full bg-zinc-700" />
          </div>
        </div>
      )}
      <div className="overflow-auto max-h-96 text-sm">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i} className="hover:bg-zinc-900/40 transition-colors">
                {showLines && (
                  <td className="select-none text-right pr-4 pl-4 py-0 text-zinc-700 font-mono text-xs w-10 border-r border-zinc-800/50">
                    {i + 1}
                  </td>
                )}
                <td className="pl-4 pr-4 py-0 font-mono text-xs text-zinc-300 whitespace-pre">
                  {line || " "}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Diff view: side-by-side original vs patched */
function DiffView({ hunks, patchedCode }) {
  const [view, setView] = useState("unified"); // "unified" | "split"
  if (!hunks?.length) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-mono text-zinc-400 uppercase tracking-widest">Code Diff</h3>
        <div className="flex rounded-md border border-zinc-800 overflow-hidden">
          {["unified", "split"].map(v => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={cn(
                "px-3 py-1 text-[10px] font-mono uppercase tracking-wider transition-colors",
                view === v
                  ? "bg-zinc-800 text-zinc-200"
                  : "bg-transparent text-zinc-600 hover:text-zinc-400"
              )}
            >{v}</button>
          ))}
        </div>
      </div>

      {view === "unified" ? (
        <CodeBlock code={patchedCode} label="patched_output.py" showLines />
      ) : (
        <div className="space-y-3">
          {hunks.map((hunk) => (
            <div key={hunk.hunk_id} className="rounded-lg border border-zinc-800 overflow-hidden">
              <div className="px-4 py-2 bg-zinc-900/70 border-b border-zinc-800 flex items-center gap-2">
                <span className="text-[10px] font-mono text-zinc-600">HUNK {hunk.hunk_id}</span>
                <span className="text-[10px] text-zinc-500 truncate">{hunk.comment}</span>
              </div>
              <div className="grid grid-cols-2 divide-x divide-zinc-800">
                <div>
                  <div className="px-3 py-1.5 bg-red-950/20 border-b border-zinc-800">
                    <span className="text-[9px] font-mono text-red-500 uppercase tracking-wider">− Original</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-red-300/80 overflow-auto bg-red-950/10 whitespace-pre-wrap">{hunk.original}</pre>
                </div>
                <div>
                  <div className="px-3 py-1.5 bg-emerald-950/20 border-b border-zinc-800">
                    <span className="text-[9px] font-mono text-emerald-500 uppercase tracking-wider">+ Patched</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-emerald-300/80 overflow-auto bg-emerald-950/10 whitespace-pre-wrap">{hunk.patched}</pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Radial risk score gauge */
function RiskGauge({ score, label }) {
  const meta = RISK_META[label] || RISK_META.MINIMAL;
  const radius = 52;
  const circ   = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          {/* Track */}
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            stroke="rgb(39 39 42)"
            strokeWidth="8"
          />
          {/* Progress */}
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            className={cn("transition-all duration-1000", meta.color)}
            style={{ filter: `drop-shadow(0 0 6px currentColor)` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-3xl font-mono font-bold tabular-nums", meta.color)}>
            {score}
          </span>
          <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-widest mt-0.5">/ 100</span>
        </div>
      </div>
      <div className={cn(
        "px-3 py-1 rounded-full border text-[11px] font-mono font-medium uppercase tracking-widest",
        meta.color,
        "border-current/30 bg-current/5"
      )}>
        {label}
      </div>
    </div>
  );
}

/** Single violation card */
function ViolationCard({ violation, index }) {
  const [expanded, setExpanded] = useState(false);
  const meta = SEVERITY_META[violation.severity] || SEVERITY_META.INFO;

  return (
    <div
      className={cn(
        "rounded-lg border transition-all duration-200 cursor-pointer",
        meta.bg, meta.border,
        expanded && "ring-1 ring-zinc-700"
      )}
      onClick={() => setExpanded(e => !e)}
    >
      <div className="flex items-start gap-3 p-4">
        <div className={cn("w-1.5 h-1.5 rounded-full mt-1.5 shrink-0", meta.dot)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn("text-[10px] font-mono font-bold uppercase tracking-wider", meta.color)}>
              {violation.severity}
            </span>
            <span className="text-[10px] font-mono text-zinc-600">·</span>
            <span className="text-[10px] font-mono text-zinc-500">{violation.regulation}</span>
            <span className="text-[10px] font-mono text-zinc-600">·</span>
            <span className="text-[10px] font-mono text-zinc-600 truncate">{violation.article}</span>
          </div>
          <p className="text-sm text-zinc-200 mt-1 font-medium leading-snug">{violation.title}</p>
          {violation.line_hint && (
            <code className="mt-1.5 block text-[10px] font-mono text-zinc-500 bg-zinc-950/60 px-2 py-1 rounded border border-zinc-800 truncate">
              {violation.line_hint}
            </code>
          )}
        </div>
        <svg
          className={cn("w-4 h-4 text-zinc-600 shrink-0 transition-transform duration-200", expanded && "rotate-180")}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
      {expanded && (
        <div className="px-4 pb-4 border-t border-zinc-800/60 pt-3 space-y-3">
          <div>
            <p className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Description</p>
            <p className="text-xs text-zinc-400 leading-relaxed">{violation.description}</p>
          </div>
          <div>
            <p className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Remediation</p>
            <p className="text-xs text-emerald-400/90 leading-relaxed">{violation.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

/** Fine prediction row */
function FineRow({ fine }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-zinc-800/60 last:border-0">
      <div>
        <span className="text-xs font-mono font-medium text-zinc-300">{fine.regulation}</span>
        <p className="text-[10px] font-mono text-zinc-600 mt-0.5 max-w-xs truncate">{fine.basis}</p>
      </div>
      <div className="text-right shrink-0 ml-4">
        <span className="text-xs font-mono text-orange-400 font-medium">
          {formatEur(fine.min_eur)} – {formatEur(fine.max_eur)}
        </span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const [code, setCode]           = useState(SAMPLE_CODE);
  const [loading, setLoading]     = useState(false);
  const [phase, setPhase]         = useState(null);   // null | 0 | 1 | 2 | 3 | "done" | "error"
  const [result, setResult]       = useState(null);
  const [error, setError]         = useState(null);
  const [activeTab, setActiveTab] = useState("audit"); // "audit" | "risk" | "patch"
  const textareaRef               = useRef(null);

  // Phase state mapping
  const phaseState = (n) => {
    if (phase === null)      return "idle";
    if (phase === "error")   return n <= 3 ? "error" : "idle";
    if (phase === "done")    return "done";
    if (phase < n)           return "idle";
    if (phase === n)         return "active";
    return "done";
  };

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = textareaRef.current.scrollHeight + "px";
    }
  }, [code]);

  const handleAudit = useCallback(async () => {
    if (!code.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setPhase(0);
    setActiveTab("audit");

    try {
      // Phase 0 happens locally (scanner_wrapper.py) — we simulate the bridge
      // In production, POST to /api/v1/scan on a local FastAPI microserver
      await new Promise(r => setTimeout(r, 600));
      setPhase(1);

      const response = await fetch(`${API_BASE}/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sanitized_code: code,
          language: "python",
          regulations: ["GDPR", "DPDPA"],
        }),
      });

      setPhase(2);
      await new Promise(r => setTimeout(r, 200)); // visual pause

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(err.detail || `HTTP ${response.status}`);
      }

      setPhase(3);
      await new Promise(r => setTimeout(r, 200));

      const data = await response.json();
      setResult(data);
      setPhase("done");
    } catch (err) {
      // For demo purposes without a backend, generate mock result
      if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        const mockResult = generateMockResult(code);
        setPhase(3);
        await new Promise(r => setTimeout(r, 400));
        setResult(mockResult);
        setPhase("done");
      } else {
        setError(err.message);
        setPhase("error");
      }
    } finally {
      setLoading(false);
    }
  }, [code, loading]);

  // ── Render ──────────────────────────────────────────────────────────────

  const violations    = result?.audit_report?.violations || [];
  const riskScore     = result?.risk_assessment?.risk_score;
  const riskLabel     = result?.risk_assessment?.risk_label;
  const fines         = result?.risk_assessment?.fine_predictions || [];
  const totalExposure = result?.risk_assessment?.total_exposure_max_eur;
  const patchedCode   = result?.patch_result?.patched_code || "";
  const diffHunks     = result?.patch_result?.diff_hunks || [];
  const changesSummary = result?.patch_result?.changes_summary || [];

  const criticalCount = violations.filter(v => v.severity === "CRITICAL").length;
  const highCount     = violations.filter(v => v.severity === "HIGH").length;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans antialiased">

      {/* ── Top bar ── */}
      <header className="sticky top-0 z-50 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 h-12 flex items-center justify-between gap-6">
          {/* Logo */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-6 h-6 rounded bg-zinc-100 flex items-center justify-center">
              <svg viewBox="0 0 16 16" className="w-3.5 h-3.5 text-zinc-950" fill="currentColor">
                <path d="M8 0L14.928 4V12L8 16L1.072 12V4L8 0Z"/>
              </svg>
            </div>
            <span className="text-sm font-mono font-semibold text-zinc-100 tracking-tight">
              oxbuild<span className="text-zinc-500">/</span>compliance
            </span>
            <div className="h-4 w-px bg-zinc-800" />
            <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest hidden sm:block">agent v1.0</span>
          </div>

          {/* Phase tracker */}
          <div className="flex items-center gap-5 flex-1 justify-center">
            <PhaseStep number="0" label="Scanner" state={phaseState(0)} />
            <div className={cn("h-px w-8 transition-colors duration-500", phase > 0 ? "bg-zinc-600" : "bg-zinc-800")} />
            <PhaseStep number="1" label="Auditor" state={phaseState(1)} />
            <div className={cn("h-px w-8 transition-colors duration-500", phase > 1 ? "bg-zinc-600" : "bg-zinc-800")} />
            <PhaseStep number="2" label="Judge" state={phaseState(2)} />
            <div className={cn("h-px w-8 transition-colors duration-500", phase > 2 ? "bg-zinc-600" : "bg-zinc-800")} />
            <PhaseStep number="3" label="Architect" state={phaseState(3)} />
          </div>

          {/* Status */}
          <div className="flex items-center gap-2 shrink-0">
            <StatusDot
              active={loading}
              color={phase === "error" ? "bg-red-400" : phase === "done" ? "bg-emerald-400" : "bg-sky-400"}
            />
            <span className="text-[10px] font-mono text-zinc-600">
              {loading ? "processing" : phase === "done" ? "complete" : phase === "error" ? "error" : "idle"}
            </span>
          </div>
        </div>
      </header>

      {/* ── Main layout ── */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_440px] gap-6 items-start">

          {/* ── Left: Code input + Results ── */}
          <div className="space-y-6">

            {/* Input panel */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">source_input.py</span>
                  <div className="px-1.5 py-0.5 rounded border border-zinc-700 bg-zinc-800">
                    <span className="text-[9px] font-mono text-zinc-500">python</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCode("")}
                    className="text-[10px] font-mono text-zinc-600 hover:text-zinc-400 transition-colors px-2 py-1 rounded hover:bg-zinc-800"
                  >
                    clear
                  </button>
                  <button
                    onClick={() => setCode(SAMPLE_CODE)}
                    className="text-[10px] font-mono text-zinc-600 hover:text-zinc-400 transition-colors px-2 py-1 rounded hover:bg-zinc-800"
                  >
                    sample
                  </button>
                </div>
              </div>

              <div className="relative">
                <div className="absolute left-0 top-0 bottom-0 w-12 border-r border-zinc-800/50 flex flex-col pt-4 select-none pointer-events-none">
                  {code.split("\n").map((_, i) => (
                    <div key={i} className="text-right pr-3 text-[10px] font-mono text-zinc-700 leading-[21px]">
                      {i + 1}
                    </div>
                  ))}
                </div>
                <textarea
                  ref={textareaRef}
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  spellCheck={false}
                  className={cn(
                    "w-full pl-14 pr-5 pt-4 pb-4 bg-transparent",
                    "font-mono text-xs text-zinc-300 leading-[21px]",
                    "resize-none outline-none min-h-[280px]",
                    "placeholder:text-zinc-700",
                    "transition-colors duration-150",
                  )}
                  placeholder="// Paste your source code here…"
                />
              </div>

              {/* CTA */}
              <div className="px-5 py-3 border-t border-zinc-800 flex items-center justify-between gap-4 bg-zinc-900/50">
                <div className="text-[10px] font-mono text-zinc-700">
                  {code.length.toLocaleString()} chars · {code.split("\n").length} lines
                </div>
                <button
                  onClick={handleAudit}
                  disabled={loading || !code.trim()}
                  className={cn(
                    "flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-mono font-medium",
                    "transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-zinc-600",
                    loading
                      ? "bg-zinc-800 text-zinc-600 cursor-not-allowed"
                      : "bg-zinc-100 text-zinc-950 hover:bg-white active:scale-95 shadow-lg shadow-zinc-900"
                  )}
                >
                  {loading ? (
                    <>
                      <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                      </svg>
                      Processing…
                    </>
                  ) : (
                    <>
                      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      Sanitize &amp; Audit
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Error state */}
            {error && (
              <div className="rounded-xl border border-red-800/60 bg-red-950/20 px-5 py-4">
                <div className="flex items-start gap-3">
                  <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-sm font-mono text-red-400 font-medium">Pipeline Error</p>
                    <p className="text-xs font-mono text-red-400/70 mt-1">{error}</p>
                  </div>
                </div>
              </div>
            )}

            {/* ── Results panel ── */}
            {result && (
              <div className="rounded-xl border border-zinc-800 overflow-hidden">
                {/* Tab bar */}
                <div className="flex border-b border-zinc-800 bg-zinc-900/50">
                  {[
                    { id: "audit", label: "Audit Report",  count: violations.length },
                    { id: "risk",  label: "Risk & Fines",  count: null },
                    { id: "patch", label: "Patched Code",  count: diffHunks.length },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={cn(
                        "flex items-center gap-2 px-5 py-3 text-xs font-mono transition-all border-b-2",
                        activeTab === tab.id
                          ? "text-zinc-100 border-zinc-400 bg-zinc-900/80"
                          : "text-zinc-600 border-transparent hover:text-zinc-400"
                      )}
                    >
                      {tab.label}
                      {tab.count != null && (
                        <span className={cn(
                          "px-1.5 py-0.5 rounded text-[9px] font-bold",
                          activeTab === tab.id ? "bg-zinc-800 text-zinc-400" : "bg-zinc-900 text-zinc-700"
                        )}>
                          {tab.count}
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                <div className="p-5 space-y-4">
                  {/* ─ Audit tab ─ */}
                  {activeTab === "audit" && (
                    <>
                      {/* Summary bar */}
                      <div className="flex items-center gap-3 flex-wrap">
                        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-950/40 border border-red-900/40">
                          <div className="w-1.5 h-1.5 rounded-full bg-red-500" />
                          <span className="text-[10px] font-mono text-red-400">{criticalCount} critical</span>
                        </div>
                        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-orange-950/40 border border-orange-900/40">
                          <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                          <span className="text-[10px] font-mono text-orange-400">{highCount} high</span>
                        </div>
                        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-zinc-800/60 border border-zinc-700/40">
                          <span className="text-[10px] font-mono text-zinc-400">{violations.length} total violations</span>
                        </div>
                      </div>

                      <p className="text-xs text-zinc-500 leading-relaxed">{result.audit_report?.summary}</p>

                      <div className="space-y-2">
                        {violations.map((v, i) => (
                          <ViolationCard key={v.id || i} violation={v} index={i} />
                        ))}
                        {violations.length === 0 && (
                          <div className="text-center py-12 text-zinc-700 font-mono text-xs">
                            No violations detected.
                          </div>
                        )}
                      </div>
                    </>
                  )}

                  {/* ─ Risk tab ─ */}
                  {activeTab === "risk" && (
                    <div className="space-y-6">
                      <div className="flex items-center justify-center py-4">
                        <RiskGauge score={riskScore} label={riskLabel} />
                      </div>
                      <p className="text-xs text-zinc-500 leading-relaxed text-center max-w-lg mx-auto">
                        {result.risk_assessment?.rationale}
                      </p>
                      <div className="rounded-lg border border-zinc-800 overflow-hidden">
                        <div className="px-4 py-2.5 bg-zinc-900/60 border-b border-zinc-800">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">
                            Regulatory Exposure
                          </span>
                        </div>
                        <div className="px-4 divide-y divide-zinc-800/60">
                          {fines.map((f, i) => <FineRow key={i} fine={f} />)}
                        </div>
                        {totalExposure > 0 && (
                          <div className="px-4 py-3 bg-zinc-900/40 border-t border-zinc-800 flex justify-between items-center">
                            <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Total Max Exposure</span>
                            <span className="text-sm font-mono text-orange-400 font-bold">{formatEur(totalExposure)}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* ─ Patch tab ─ */}
                  {activeTab === "patch" && (
                    <div className="space-y-5">
                      {changesSummary.length > 0 && (
                        <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-4 space-y-1.5">
                          <p className="text-[10px] font-mono text-emerald-500 uppercase tracking-widest mb-2">
                            Changes Applied
                          </p>
                          {changesSummary.map((c, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <span className="text-emerald-500 mt-0.5 text-xs shrink-0">+</span>
                              <span className="text-xs font-mono text-emerald-400/80">{c}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <DiffView hunks={diffHunks} patchedCode={patchedCode} />
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* ── Right sidebar ── */}
          <aside className="space-y-4 xl:sticky xl:top-16">

            {/* Pipeline info card */}
            <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-4">
              <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Pipeline</h2>
              {[
                {
                  phase: "00",
                  label: "PII Scanner",
                  sub:   "C++ std::regex engine",
                  model: "_oxscanner (local)",
                  icon:  "🔒",
                  color: "text-zinc-400",
                },
                {
                  phase: "01",
                  label: "Legal Auditor",
                  sub:   "GDPR / DPDPA analysis",
                  model: "Llama 3.3 70B",
                  icon:  "⚖️",
                  color: "text-sky-400",
                },
                {
                  phase: "02",
                  label: "Risk Judge",
                  sub:   "Score + fine prediction",
                  model: "GPT-4o",
                  icon:  "📊",
                  color: "text-orange-400",
                },
                {
                  phase: "03",
                  label: "Code Architect",
                  sub:   "Compliant patch generation",
                  model: "DeepSeek-Coder-V2",
                  icon:  "🔧",
                  color: "text-emerald-400",
                },
              ].map(({ phase: p, label, sub, model, icon, color }, i, arr) => (
                <div key={p} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="flex items-center justify-center w-7 h-7 rounded-full border border-zinc-800 bg-zinc-900 text-sm">
                      {icon}
                    </div>
                    {i < arr.length - 1 && <div className="w-px flex-1 bg-zinc-800/60 my-1" />}
                  </div>
                  <div className="pb-4 last:pb-0">
                    <div className="flex items-baseline gap-1.5">
                      <span className="text-[9px] font-mono text-zinc-700">Phase {p}</span>
                    </div>
                    <p className="text-xs font-medium text-zinc-300 mt-0.5">{label}</p>
                    <p className="text-[10px] font-mono text-zinc-600 mt-0.5">{sub}</p>
                    <div className="mt-1.5 inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-zinc-800 bg-zinc-900/60">
                      <div className="w-1 h-1 rounded-full bg-zinc-600" />
                      <span className={cn("text-[9px] font-mono", color)}>{model}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Scan stats — shown after result */}
            {result && (
              <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-3">
                <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Scan Metrics</h2>
                {[
                  { label: "Auditor",    value: `${result.audit_report?.elapsed_ms}ms`,  unit: "phase 1" },
                  { label: "Risk Judge", value: `${result.risk_assessment?.elapsed_ms}ms`, unit: "phase 2" },
                  { label: "Architect",  value: `${result.patch_result?.elapsed_ms}ms`,  unit: "phase 3" },
                  { label: "Pipeline",   value: `${result.elapsed_ms}ms`, unit: "total" },
                ].map(({ label, value, unit }) => (
                  <div key={label} className="flex items-center justify-between">
                    <span className="text-xs font-mono text-zinc-600">{label}</span>
                    <div className="flex items-baseline gap-1">
                      <span className="text-xs font-mono font-medium text-zinc-300">{value}</span>
                      <span className="text-[9px] font-mono text-zinc-700">{unit}</span>
                    </div>
                  </div>
                ))}
                <div className="pt-2 border-t border-zinc-800">
                  <p className="text-[9px] font-mono text-zinc-700">
                    Request ID: <span className="text-zinc-600">{result.request_id}</span>
                  </p>
                </div>
              </div>
            )}

            {/* Regulations reference */}
            <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-2">
              <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-3">Frameworks</h2>
              {[
                { reg: "GDPR",     desc: "EU · General Data Protection Reg.",   active: true  },
                { reg: "DPDPA",    desc: "IN · Digital Personal Data Protection", active: true  },
                { reg: "CCPA",     desc: "US · California Consumer Privacy Act", active: false },
                { reg: "HIPAA",    desc: "US · Health Insurance Portability",    active: false },
                { reg: "PCI-DSS",  desc: "Global · Card Data Security Standard", active: false },
              ].map(({ reg, desc, active }) => (
                <div key={reg} className="flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono font-medium text-zinc-400">{reg}</span>
                    <p className="text-[9px] font-mono text-zinc-700 mt-0.5">{desc}</p>
                  </div>
                  <div className={cn(
                    "text-[8px] font-mono px-1.5 py-0.5 rounded border",
                    active
                      ? "text-emerald-400 border-emerald-900/60 bg-emerald-950/30"
                      : "text-zinc-700 border-zinc-800"
                  )}>
                    {active ? "active" : "off"}
                  </div>
                </div>
              ))}
            </div>

          </aside>
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-zinc-800/60 mt-16 px-6 py-5">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <span className="text-[10px] font-mono text-zinc-700">
            oxbuild/compliance-agent · local-first · PII never leaves your machine
          </span>
          <span className="text-[10px] font-mono text-zinc-700">
            C++ · Python · FastAPI · React
          </span>
        </div>
      </footer>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock result generator (used when backend is unavailable for demo)
// ─────────────────────────────────────────────────────────────────────────────

function generateMockResult(code) {
  return {
    request_id: crypto.randomUUID?.() || "demo-" + Math.random().toString(36).slice(2),
    elapsed_ms: 1842.5,
    audit_report: {
      model: "meta-llama/llama-3.3-70b-instruct",
      regulations: ["GDPR", "DPDPA"],
      violations: [
        {
          id: "a1b2",
          regulation: "GDPR",
          article: "Article 25 — Data Protection by Design",
          severity: "CRITICAL",
          title: "No data minimisation enforced",
          description: "Query returns complete row/object including fields not required by the business logic. SELECT * patterns return all columns including sensitive PII fields unnecessary for the operation.",
          line_hint: 'cursor.execute("SELECT * FROM users")',
          remediation: "Replace SELECT * with column-specific projections. Apply field-level access control based on the consuming role.",
        },
        {
          id: "c3d4",
          regulation: "GDPR",
          article: "Article 32 — Security of Processing",
          severity: "HIGH",
          title: "PII logged to stdout in plaintext",
          description: "User email address (personal data) is written to stdout via print(), which may persist in log aggregation systems without encryption or access controls.",
          line_hint: 'print(f"User {user_id} ({user.email}): {action}")',
          remediation: "Remove PII from log statements. Use structured logging with data masking middleware.",
        },
        {
          id: "e5f6",
          regulation: "DPDPA",
          article: "Section 6 — Consent Framework",
          severity: "CRITICAL",
          title: "Consent not verified before processing",
          description: "Personal data is processed and transformed without a preceding consent verification check. India's DPDPA mandates explicit consent before any processing of digital personal data.",
          line_hint: "def get_all_users():",
          remediation: "Integrate a consent management service (CMP) and enforce consent verification as middleware on all data-access paths.",
        },
        {
          id: "g7h8",
          regulation: "GDPR",
          article: "Article 5(1)(f) — Integrity & Confidentiality",
          severity: "HIGH",
          title: "Payment card data stored in cache without encryption",
          description: "Raw card_number is stored in a cache layer with a TTL. PCI-DSS and GDPR both prohibit storing sensitive payment data in unencrypted volatile stores.",
          line_hint: 'cache.set(f"card:{user_id}", card_number, ttl=3600)',
          remediation: "Never cache raw PANs. Tokenise payment data via a PCI-DSS compliant vault (e.g. Stripe, Braintree) and store only the token.",
        },
      ],
      total_count: 4,
      critical_count: 2,
      high_count: 2,
      summary: "Detected 4 violation(s) across GDPR, DPDPA — 2 critical, 2 high-severity. Immediate remediation required before production deployment.",
      elapsed_ms: 723.4,
    },
    risk_assessment: {
      model: "gpt-4o",
      risk_score: 84,
      risk_label: "CRITICAL",
      fine_predictions: [
        { regulation: "GDPR", min_eur: 2_100_000, max_eur: 16_800_000, basis: "GDPR Art. 83(5): up to €20M or 4% of global annual turnover" },
        { regulation: "DPDPA", min_eur: 800_000, max_eur: 22_600_000, basis: "DPDPA §33: up to ₹250 Cr (~€27M) per breach" },
      ],
      total_exposure_min_eur: 2_900_000,
      total_exposure_max_eur: 39_400_000,
      rationale: "Risk score of 84/100 (CRITICAL) derived from 4 violation(s) across 2 regulation(s). Critical violations in SELECT * patterns, unencrypted PII logging, and absent consent enforcement are the primary risk drivers. Total regulatory exposure: €2.9M–€39.4M.",
      elapsed_ms: 612.1,
    },
    patch_result: {
      model: "deepseek-ai/DeepSeek-Coder-V2-Instruct",
      patched_code: `# ─────────────────────────────────────────────────────────────────────
# OXBUILD COMPLIANCE PATCH — Auto-generated by DeepSeek-Coder-V2
# Applied fixes: GDPR Art. 5, 6, 17, 25, 32 | DPDPA §6, §8
# Review all changes before merging. This patch is a starting point.
# ─────────────────────────────────────────────────────────────────────
from __future__ import annotations
from typing import Optional
from enum import Enum
import logging

audit_logger = logging.getLogger("oxbuild.data_access")

class ProcessingPurpose(Enum):
    AUTHENTICATION  = "authentication"
    PROFILE_DISPLAY = "profile_display"
    BILLING         = "billing"

# GDPR Art. 5(1)(c) — Data Minimisation: explicit field list
REQUIRED_FIELDS = ("id", "account_status", "created_at")

def get_users(
    purpose: ProcessingPurpose,
    requesting_role: str,
) -> list[dict]:
    """
    GDPR/DPDPA-compliant user list with:
    - Purpose limitation check
    - Data minimisation (no SELECT *)
    - Audit logging
    - Soft-delete filter
    """
    _verify_purpose(purpose, requesting_role)
    consent = ConsentManager.check_bulk(purpose=purpose)
    if not consent.is_valid:
        raise ConsentRequiredError(f"Bulk consent not granted for {purpose}")

    results = (
        db.query(*[getattr(User, f) for f in REQUIRED_FIELDS])
        .filter(User.deleted_at.is_(None))   # GDPR Art. 17 soft-delete
        .all()
    )

    # GDPR Art. 32 — structured logging, no PII in message
    audit_logger.info(
        "user_list_access",
        extra={"purpose": purpose.value, "role": requesting_role, "count": len(results)}
    )
    return results

def log_user_activity(user_id: int, action: str) -> None:
    """GDPR-compliant activity log — no PII in log body."""
    audit_logger.info(
        "user_activity",
        extra={"user_id": user_id, "action": action}
        # email is intentionally omitted — GDPR Art. 5(1)(c)
    )

def process_payment(user_id: int, card_token: str) -> dict:
    """
    PCI-DSS compliant payment — accepts pre-tokenised card reference only.
    Raw PANs must NEVER reach application code.
    """
    # Store only the opaque token, not the card number
    cache.set(f"payment_token:{user_id}", card_token, ttl=3600)
    return charge_by_token(card_token)
`,
      diff_hunks: [
        {
          hunk_id: 1,
          original: 'cursor.execute("SELECT * FROM users")\nreturn cursor.fetchall()',
          patched:  'REQUIRED_FIELDS = ("id", "account_status", "created_at")\nresults = (\n    db.query(*[getattr(User, f) for f in REQUIRED_FIELDS])\n    .filter(User.deleted_at.is_(None))\n    .all()\n)',
          comment:  "Replaces SELECT * with field projection + soft-delete filter (GDPR Art. 5, 17, 25)",
        },
        {
          hunk_id: 2,
          original: 'print(f"User {user_id} ({user.email}): {action}")',
          patched:  'audit_logger.info("user_activity", extra={"user_id": user_id, "action": action})',
          comment:  "Removes PII from log output; uses structured logging (GDPR Art. 32)",
        },
        {
          hunk_id: 3,
          original: 'cache.set(f"card:{user_id}", card_number, ttl=3600)',
          patched:  'cache.set(f"payment_token:{user_id}", card_token, ttl=3600)',
          comment:  "Accepts tokenised card reference only — raw PANs never stored (PCI-DSS, GDPR Art. 32)",
        },
      ],
      changes_summary: [
        "Hunk 1: Replaces SELECT * with field projection + soft-delete filter (GDPR Art. 5, 17, 25)",
        "Hunk 2: Removes PII from log output; uses structured logging (GDPR Art. 32)",
        "Hunk 3: Accepts tokenised card reference only — raw PANs never stored (PCI-DSS, GDPR Art. 32)",
        "Added `audit_logger` import for immutable access logging (GDPR Art. 32)",
        "Introduced ConsentManager bulk-check before data access (DPDPA §6)",
        "Added ProcessingPurpose enum for purpose limitation enforcement (GDPR Art. 5(1)(b))",
      ],
      elapsed_ms: 507.0,
    },
  };
}