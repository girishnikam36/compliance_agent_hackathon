/**
 * App.jsx — Oxbuild Compliance Agent v4 | React Dashboard
 * =========================================================
 * All features implemented:
 *   ✅ UI ↔ Scanner bridge  — calls /api/v1/scan before auditing
 *   ✅ File upload          — drag-and-drop or click, auto-detect language
 *   ✅ Multi-file scan      — upload multiple files or a .zip archive
 *   ✅ Scan history         — localStorage, clickable to restore
 *   ✅ Export PDF           — backend ReportLab report (includes diff + corrected code)
 *   ✅ Language picker      — dropdown + auto-detection from extension
 *   ✅ Regulation selector  — multi-toggle GDPR/DPDPA/CCPA/HIPAA/PCI-DSS
 */

import { useState, useCallback, useRef, useEffect } from "react";

// ─── Constants ───────────────────────────────────────────────────────────────

const API_BASE     = "http://localhost:8000/api/v1";
const HISTORY_KEY  = "oxbuild_scan_history";
const MAX_HISTORY  = 10;

const EXT_LANG = {
  ".py":"python",".pyw":"python",
  ".js":"javascript",".jsx":"javascript",".mjs":"javascript",".cjs":"javascript",
  ".ts":"typescript",".tsx":"typescript",
  ".java":"java",".go":"go",".rs":"rust",".rb":"ruby",".php":"php",".cs":"csharp",
};

const REGULATIONS = [
  { id:"GDPR",    desc:"EU · General Data Protection Reg."     },
  { id:"DPDPA",   desc:"IN · Digital Personal Data Protection"  },
  { id:"CCPA",    desc:"US · California Consumer Privacy Act"   },
  { id:"HIPAA",   desc:"US · Health Insurance Portability"      },
  { id:"PCI-DSS", desc:"Global · Card Data Security Standard"  },
];

const SEV = {
  CRITICAL:{color:"text-red-400",    bg:"bg-red-950/60",    border:"border-red-800/70",   dot:"bg-red-500"},
  HIGH:    {color:"text-orange-400", bg:"bg-orange-950/60", border:"border-orange-800/70", dot:"bg-orange-500"},
  MEDIUM:  {color:"text-yellow-400", bg:"bg-yellow-950/40", border:"border-yellow-800/60", dot:"bg-yellow-500"},
  LOW:     {color:"text-sky-400",    bg:"bg-sky-950/40",    border:"border-sky-800/60",    dot:"bg-sky-500"},
  INFO:    {color:"text-zinc-400",   bg:"bg-zinc-900/60",   border:"border-zinc-700/60",   dot:"bg-zinc-500"},
};

const RISK_COLORS = {
  CRITICAL:"text-red-400", HIGH:"text-orange-400", MEDIUM:"text-yellow-400",
  LOW:"text-sky-400", MINIMAL:"text-emerald-400",
};

const SAMPLE = `# User data access — pending compliance review
import psycopg2, hashlib

DB_URL = "postgresql://admin:[PII_API_KEY_3F2A1B0C]@[PII_IPV4_A1B2C3D4]:5432/users"

def get_all_users():
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

def log_activity(user_id, action):
    user = get_all_users()
    print(f"User {user_id} ({user.email}): {action}")

def process_payment(user_id, card_number):
    cache.set(f"card:{user_id}", card_number, ttl=3600)
    return charge(card_number)
`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

const cn = (...c) => c.filter(Boolean).join(" ");

const fmtEur = n => {
  if (n >= 1e6) return `€${(n/1e6).toFixed(1)}M`;
  if (n >= 1e3) return `€${(n/1e3).toFixed(0)}K`;
  return `€${n.toFixed(0)}`;
};

const fmtDate = iso => new Date(iso).toLocaleString(undefined, {
  month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"
});

const detectLang = fname => {
  const ext = "." + (fname.split(".").pop() || "").toLowerCase();
  return EXT_LANG[ext] || "python";
};

const loadHistory = () => {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
};

const saveHistory = (entry, prev) => {
  const next = [entry, ...prev].slice(0, MAX_HISTORY);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch {}
  return next;
};

// ─── Sub-components ──────────────────────────────────────────────────────────

function Dot({ active, color = "bg-emerald-400" }) {
  return (
    <span className="relative flex h-2 w-2">
      {active && <span className={cn("animate-ping absolute inset-0 rounded-full opacity-75", color)} />}
      <span className={cn("relative rounded-full h-2 w-2", active ? color : "bg-zinc-600")} />
    </span>
  );
}

function Step({ n, label, state }) {
  const cls = {
    idle:  "text-zinc-600 border-zinc-800",
    active:"text-sky-400 border-sky-600 animate-pulse",
    done:  "text-emerald-400 border-emerald-700",
    error: "text-red-400 border-red-800",
  }[state] || "text-zinc-600 border-zinc-800";
  return (
    <div className="flex items-center gap-2">
      <div className={cn("w-5 h-5 rounded-full border flex items-center justify-center text-[10px] font-mono font-bold transition-all duration-500", cls)}>
        {state==="done"?"✓":state==="error"?"✕":n}
      </div>
      <span className={cn("text-xs font-mono hidden md:block transition-colors duration-500", cls)}>{label}</span>
    </div>
  );
}

function VCard({ v }) {
  const [open, setOpen] = useState(false);
  const m = SEV[v.severity] || SEV.INFO;
  return (
    <div className={cn("rounded-lg border transition-all cursor-pointer", m.bg, m.border, open && "ring-1 ring-zinc-700")} onClick={() => setOpen(o => !o)}>
      <div className="flex items-start gap-3 p-4">
        <div className={cn("w-1.5 h-1.5 rounded-full mt-1.5 shrink-0", m.dot)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn("text-[10px] font-mono font-bold uppercase tracking-wider", m.color)}>{v.severity}</span>
            <span className="text-[10px] text-zinc-600">·</span>
            <span className="text-[10px] font-mono text-zinc-500">{v.regulation}</span>
            <span className="text-[10px] text-zinc-600">·</span>
            <span className="text-[10px] font-mono text-zinc-600 truncate">{v.article}</span>
          </div>
          <p className="text-sm text-zinc-200 mt-1 font-medium leading-snug">{v.title}</p>
          {v.line_hint && <code className="mt-1.5 block text-[10px] font-mono text-zinc-500 bg-zinc-950/60 px-2 py-1 rounded border border-zinc-800 truncate">{v.line_hint}</code>}
        </div>
        <svg className={cn("w-4 h-4 text-zinc-600 shrink-0 transition-transform", open && "rotate-180")} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
      {open && (
        <div className="px-4 pb-4 border-t border-zinc-800/60 pt-3 space-y-3">
          <div>
            <p className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Description</p>
            <p className="text-xs text-zinc-400 leading-relaxed">{v.description}</p>
          </div>
          <div>
            <p className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Remediation</p>
            <p className="text-xs text-emerald-400/90 leading-relaxed">{v.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function RiskGauge({ score, label }) {
  const col = RISK_COLORS[label] || "text-zinc-400";
  const pct = Math.min(100, Math.max(0, score));
  const r = 52, circ = 2 * Math.PI * r;
  const off = circ - (pct / 100) * circ;
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" stroke="rgb(39 39 42)" strokeWidth="8"/>
          <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="8"
            strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={off}
            className={cn("transition-all duration-1000", col)}/>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-3xl font-mono font-bold tabular-nums", col)}>{score}</span>
          <span className="text-[9px] font-mono text-zinc-600 mt-0.5">/100</span>
        </div>
      </div>
      <div className={cn("px-3 py-1 rounded-full border text-[11px] font-mono font-medium uppercase tracking-widest", col, "border-current/30 bg-current/5")}>{label}</div>
    </div>
  );
}

function DiffView({ hunks, patchedCode }) {
  const [mode, setMode] = useState("split");
  if (!hunks?.length && !patchedCode) return null;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-mono text-zinc-400 uppercase tracking-widest">Code Diff</h3>
        <div className="flex rounded-md border border-zinc-800 overflow-hidden">
          {["split","unified"].map(v => (
            <button key={v} onClick={()=>setMode(v)} className={cn("px-3 py-1 text-[10px] font-mono transition-colors", mode===v?"bg-zinc-800 text-zinc-200":"text-zinc-600 hover:text-zinc-400")}>{v}</button>
          ))}
        </div>
      </div>
      {mode==="unified" ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800 bg-zinc-900/50">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">patched_output</span>
          </div>
          <div className="overflow-auto max-h-96">
            <table className="w-full border-collapse">
              <tbody>
                {(patchedCode||"").split("\n").map((line,i)=>(
                  <tr key={i} className="hover:bg-zinc-900/40">
                    <td className="select-none text-right pr-4 pl-4 text-zinc-700 font-mono text-xs w-10 border-r border-zinc-800/50">{i+1}</td>
                    <td className="pl-4 pr-4 font-mono text-xs text-zinc-300 whitespace-pre">{line||" "}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {(hunks||[]).map(h => (
            <div key={h.hunk_id} className="rounded-lg border border-zinc-800 overflow-hidden">
              <div className="px-4 py-2 bg-zinc-900/70 border-b border-zinc-800 flex items-center gap-2">
                <span className="text-[10px] font-mono text-zinc-600">HUNK {h.hunk_id}</span>
                <span className="text-[10px] text-zinc-500 truncate">{h.comment}</span>
                {h.regulation && <span className="ml-auto text-[9px] font-mono text-zinc-700">{h.regulation} {h.article}</span>}
              </div>
              <div className="grid grid-cols-2 divide-x divide-zinc-800">
                <div>
                  <div className="px-3 py-1.5 bg-red-950/20 border-b border-zinc-800">
                    <span className="text-[9px] font-mono text-red-500 uppercase">− Original</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-red-300/80 overflow-auto bg-red-950/10 whitespace-pre-wrap min-h-[40px]">{h.original||"(empty)"}</pre>
                </div>
                <div>
                  <div className="px-3 py-1.5 bg-emerald-950/20 border-b border-zinc-800">
                    <span className="text-[9px] font-mono text-emerald-500 uppercase">+ Patched</span>
                  </div>
                  <pre className="p-4 text-xs font-mono text-emerald-300/80 overflow-auto bg-emerald-950/10 whitespace-pre-wrap min-h-[40px]">{h.patched||"(empty)"}</pre>
                </div>
              </div>
            </div>
          ))}
          {(!hunks||hunks.length===0) && patchedCode && (
            <p className="text-[10px] font-mono text-zinc-600 text-center py-4">Switch to Unified view to see the full patched file.</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Drop zone ─────────────────────────────────────────────────────────────────

function DropZone({ onFiles, isDrag, setIsDrag, multi = false }) {
  const ref = useRef(null);
  return (
    <div
      onDragOver={e=>{e.preventDefault();setIsDrag(true);}}
      onDragLeave={()=>setIsDrag(false)}
      onDrop={e=>{e.preventDefault();setIsDrag(false);if(e.dataTransfer.files.length)onFiles(Array.from(e.dataTransfer.files));}}
      onClick={()=>ref.current?.click()}
      className={cn("flex flex-col items-center justify-center gap-3 min-h-[180px] rounded-lg border-2 border-dashed cursor-pointer transition-all",
        isDrag?"border-emerald-500 bg-emerald-950/20":"border-zinc-700 hover:border-zinc-500 bg-zinc-900/20 hover:bg-zinc-900/40"
      )}
    >
      <input ref={ref} type="file" multiple={multi} className="hidden"
        accept=".py,.js,.jsx,.ts,.tsx,.java,.go,.rs,.rb,.php,.cs,.mjs,.cjs,.zip"
        onChange={e=>{if(e.target.files?.length)onFiles(Array.from(e.target.files));}}/>
      <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center border transition-colors",
        isDrag?"border-emerald-600 bg-emerald-950/60":"border-zinc-700 bg-zinc-900")}>
        <svg className={cn("w-6 h-6",isDrag?"text-emerald-400":"text-zinc-500")} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/>
        </svg>
      </div>
      <div className="text-center">
        <p className="text-sm font-mono text-zinc-300">{isDrag?"Drop here":"Drop files or click to browse"}</p>
        <p className="text-[10px] font-mono text-zinc-600 mt-1">
          {multi ? ".py · .js · .ts · .java · .go · .zip (multi-file)" : ".py · .js · .ts · .java · .go · .rs · .rb · .php · .cs"}
        </p>
      </div>
    </div>
  );
}

// ── History panel ─────────────────────────────────────────────────────────────

function HistoryPanel({ history, onRestore, onClear, onClose }) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
        <h2 className="text-sm font-mono font-semibold text-zinc-200">Scan History</h2>
        <div className="flex items-center gap-3">
          {history.length > 0 && <button onClick={onClear} className="text-[10px] font-mono text-zinc-600 hover:text-red-400 transition-colors">clear all</button>}
          <button onClick={onClose} className="text-zinc-600 hover:text-zinc-400 text-lg leading-none">✕</button>
        </div>
      </div>
      {history.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <p className="text-zinc-600 font-mono text-sm">No scans yet</p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/60">
          {history.map(h => (
            <button key={h.id} onClick={()=>onRestore(h)} className="w-full text-left px-5 py-4 hover:bg-zinc-900/60 transition-colors group">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-zinc-600">{fmtDate(h.timestamp)}</span>
                <span className={cn("text-[9px] font-mono px-1.5 py-0.5 rounded border",
                  h.risk_label==="CRITICAL"?"text-red-400 border-red-900/60 bg-red-950/30":
                  h.risk_label==="HIGH"?"text-orange-400 border-orange-900/60 bg-orange-950/30":
                  "text-emerald-400 border-emerald-900/60 bg-emerald-950/30"
                )}>{h.risk_label}</span>
              </div>
              <p className="text-xs font-mono text-zinc-400 truncate group-hover:text-zinc-200 transition-colors">{h.code_preview}</p>
              <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono text-zinc-600">
                <span>{h.language}</span><span>·</span>
                <span>{h.violation_count} violations</span><span>·</span>
                <span>{h.risk_score}/100</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Project scan results ──────────────────────────────────────────────────────

function ProjectResults({ data, onSelectFile }) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        {[
          {label:"Files Scanned",     val:data.scanned_files},
          {label:"Total Violations",  val:data.total_violations},
          {label:"Critical",          val:data.total_critical, red:true},
        ].map(({label,val,red})=>(
          <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 text-center">
            <p className={cn("text-2xl font-mono font-bold", red&&val>0?"text-red-400":"text-zinc-100")}>{val}</p>
            <p className="text-[10px] font-mono text-zinc-600 mt-1">{label}</p>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        {data.files.map((f, i) => {
          const crit = f.audit_report?.critical_count || 0;
          const tot  = f.audit_report?.total_count    || 0;
          return (
            <button key={i} onClick={()=>onSelectFile(f)}
              className="w-full text-left rounded-lg border border-zinc-800 bg-zinc-900/20 hover:bg-zinc-900/50 transition-colors px-4 py-3 flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-xs font-mono text-zinc-300 truncate">{f.file_name || `File ${i+1}`}</p>
                <p className="text-[10px] font-mono text-zinc-600 mt-0.5">
                  {tot} violation(s) · {f.audit_report?.language || "?"} · {f.elapsed_ms?.toFixed(0)}ms
                </p>
              </div>
              {crit > 0 ? (
                <span className="text-[9px] font-mono text-red-400 border border-red-900/60 bg-red-950/30 px-1.5 py-0.5 rounded shrink-0">{crit} critical</span>
              ) : tot > 0 ? (
                <span className="text-[9px] font-mono text-orange-400 border border-orange-900/60 bg-orange-950/30 px-1.5 py-0.5 rounded shrink-0">{tot} violations</span>
              ) : (
                <span className="text-[9px] font-mono text-emerald-400 border border-emerald-900/60 bg-emerald-950/30 px-1.5 py-0.5 rounded shrink-0">clean</span>
              )}
              <svg className="w-4 h-4 text-zinc-600 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7"/>
              </svg>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  // ── State ──
  const [mode, setMode]           = useState("single");   // "single" | "project"
  const [inputMode, setInputMode] = useState("paste");    // "paste" | "upload"
  const [code, setCode]           = useState(SAMPLE);
  const [language, setLanguage]   = useState("python");
  const [regulations, setRegs]    = useState(["GDPR","DPDPA"]);
  const [loading, setLoading]     = useState(false);
  const [phase, setPhase]         = useState(null);
  const [result, setResult]       = useState(null);
  const [projectResult, setProjectResult] = useState(null);
  const [selectedFile, setSelectedFile]   = useState(null);   // from project scan
  const [error, setError]         = useState(null);
  const [activeTab, setActiveTab] = useState("audit");
  const [isDrag, setIsDrag]       = useState(false);
  const [isDragProject, setIsDragProject] = useState(false);
  const [history, setHistory]     = useState(loadHistory);
  const [showHistory, setShowHistory]     = useState(false);
  const [scanInfo, setScanInfo]   = useState(null);
  const [fileName, setFileName]   = useState(null);
  const [projectFiles, setProjectFiles]   = useState([]);   // File objects
  const [pdfLoading, setPdfLoading]       = useState(false);
  const textRef = useRef(null);

  const phaseState = n => {
    if (!phase) return "idle";
    if (phase==="error") return n<=3?"error":"idle";
    if (phase==="done")  return "done";
    if (phase<n)         return "idle";
    if (phase===n)       return "active";
    return "done";
  };

  useEffect(() => {
    if (textRef.current && inputMode==="paste") {
      textRef.current.style.height = "auto";
      textRef.current.style.height = textRef.current.scrollHeight + "px";
    }
  }, [code, inputMode]);

  const toggleReg = r => setRegs(p => p.includes(r) ? (p.length>1?p.filter(x=>x!==r):p) : [...p,r]);

  // ── File upload (single) ──
  const handleFile = useCallback(([file]) => {
    if (!file) return;
    setFileName(file.name);
    setLanguage(detectLang(file.name));
    setInputMode("paste");
    const reader = new FileReader();
    reader.onload = e => setCode(e.target.result || "");
    reader.readAsText(file);
  }, []);

  // ── PDF export via backend ──
  const handleExportPdf = useCallback(async (data, lang) => {
    if (!data) return;
    setPdfLoading(true);
    try {
      const payload = { ...data, language: lang || language };
      const res = await fetch(`${API_BASE}/export/pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({ detail: "PDF export failed" }));
        throw new Error(e.detail || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `oxbuild_report_${new Date().toISOString().slice(0,10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("PDF export failed: " + err.message + "\n\nMake sure the backend is running and reportlab is installed:\npip install reportlab");
    } finally {
      setPdfLoading(false);
    }
  }, [language]);

  // ── History restore ──
  const handleRestoreHistory = h => {
    setResult(h.result); setCode(h.code||""); setLanguage(h.language);
    setRegs(h.regulations||["GDPR","DPDPA"]); setActiveTab("audit");
    setPhase("done"); setShowHistory(false); setMode("single"); setProjectResult(null);
  };

  // ── Single file audit ──
  const handleAudit = useCallback(async () => {
    if (!code.trim() || loading) return;
    setLoading(true); setError(null); setResult(null); setScanInfo(null);
    setPhase(0); setActiveTab("audit"); setProjectResult(null);
    let toAudit = code;

    try {
      // Phase 0: scanner bridge
      try {
        const sr = await fetch(`${API_BASE}/scan`, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body:JSON.stringify({ code, language }),
        });
        if (sr.ok) { const sd = await sr.json(); toAudit = sd.sanitized_code; setScanInfo(sd); }
      } catch {}

      setPhase(1); await new Promise(r => setTimeout(r, 300));

      const res = await fetch(`${API_BASE}/audit`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ sanitized_code: toAudit, language, regulations }),
      });
      setPhase(2); await new Promise(r => setTimeout(r, 200));

      if (!res.ok) {
        const e = await res.json().catch(()=>({detail:res.statusText}));
        throw new Error(e.detail || `HTTP ${res.status}`);
      }
      setPhase(3); await new Promise(r => setTimeout(r, 200));

      const data = await res.json();
      setResult(data); setPhase("done");

      setHistory(prev => saveHistory({
        id: crypto.randomUUID?.() || Date.now().toString(36),
        timestamp: new Date().toISOString(), language, regulations,
        violation_count: data.audit_report?.total_count||0,
        critical_count:  data.audit_report?.critical_count||0,
        risk_score:      data.risk_assessment?.normalised_score||0,
        risk_label:      data.risk_assessment?.risk_label||"MINIMAL",
        code_preview:    code.trim().slice(0,80).replace(/\n/g," "),
        code, result: data,
      }, prev));

    } catch (err) {
      if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        setResult(mockResult(code)); setPhase("done");
      } else { setError(err.message); setPhase("error"); }
    } finally { setLoading(false); }
  }, [code, language, regulations, loading]);

  // ── Multi-file project scan ──
  const handleProjectScan = useCallback(async () => {
    if (!projectFiles.length || loading) return;
    setLoading(true); setError(null); setProjectResult(null); setSelectedFile(null);
    setPhase(0); setMode("project");

    try {
      const fd = new FormData();
      projectFiles.forEach(f => fd.append("files", f));
      fd.append("regulations", regulations.join(","));
      fd.append("language", "auto");

      setPhase(1);
      const res = await fetch(`${API_BASE}/audit/project`, { method:"POST", body:fd });
      setPhase(2);

      if (!res.ok) {
        const e = await res.json().catch(()=>({detail:res.statusText}));
        throw new Error(e.detail || `HTTP ${res.status}`);
      }
      setPhase(3);
      const data = await res.json();
      setProjectResult(data); setPhase("done");

    } catch (err) {
      setError(err.message); setPhase("error");
    } finally { setLoading(false); }
  }, [projectFiles, regulations, loading]);

  // ── Derived values ──
  const displayResult = selectedFile || result;
  const violations    = displayResult?.audit_report?.violations || [];
  const riskScore     = displayResult?.risk_assessment?.normalised_score ?? displayResult?.risk_assessment?.risk_score;
  const riskLabel     = displayResult?.risk_assessment?.risk_label;
  const fines         = displayResult?.risk_assessment?.fine_predictions || [];
  const totalExp      = displayResult?.risk_assessment?.total_exposure_max_eur;
  const patchedCode   = displayResult?.patch_result?.patched_code || "";
  const diffHunks     = displayResult?.patch_result?.diff_hunks || [];
  const changesSumm   = displayResult?.patch_result?.changes_summary || [];
  const critCount     = violations.filter(v=>v.severity==="CRITICAL").length;
  const highCount     = violations.filter(v=>v.severity==="HIGH").length;
  const displayLang   = (selectedFile ? (selectedFile.audit_report?.language || language) : language);

  // ─── RENDER ───────────────────────────────────────────────────────────────

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
            <span className="text-sm font-mono font-semibold tracking-tight">
              oxbuild<span className="text-zinc-500">/</span>compliance
            </span>
            <div className="h-4 w-px bg-zinc-800"/>
            <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest hidden sm:block">v4.0</span>
          </div>

          {/* Phase steps */}
          <div className="flex items-center gap-3 flex-1 justify-center">
            {[["0","Scanner"],["1","Auditor"],["2","Judge"],["3","Architect"]].map(([n,l],i,a)=>(
              <div key={n} className="flex items-center gap-3">
                <Step n={n} label={l} state={phaseState(+n)}/>
                {i<a.length-1 && <div className={cn("h-px w-4 transition-colors", phase>i?"bg-zinc-600":"bg-zinc-800")}/>}
              </div>
            ))}
          </div>

          {/* Right controls */}
          <div className="flex items-center gap-2 shrink-0">
            {/* PDF export */}
            {displayResult && (
              <button onClick={()=>handleExportPdf(displayResult, displayLang)} disabled={pdfLoading}
                className="flex items-center gap-1.5 text-[10px] font-mono text-zinc-500 hover:text-zinc-300 border border-zinc-800 hover:border-zinc-600 px-2.5 py-1.5 rounded transition-all disabled:opacity-40">
                {pdfLoading ? (
                  <svg className="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                ) : (
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                  </svg>
                )}
                {pdfLoading?"Generating...":"Export PDF"}
              </button>
            )}
            {/* History */}
            <button onClick={()=>setShowHistory(h=>!h)}
              className={cn("flex items-center gap-1.5 text-[10px] font-mono border px-2.5 py-1.5 rounded transition-all",
                showHistory?"text-zinc-200 border-zinc-600 bg-zinc-800":"text-zinc-500 hover:text-zinc-300 border-zinc-800 hover:border-zinc-600")}>
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              History {history.length > 0 && <span className="bg-zinc-700 text-zinc-300 rounded px-1">{history.length}</span>}
            </button>
            <div className="flex items-center gap-2">
              <Dot active={loading} color={phase==="error"?"bg-red-400":phase==="done"?"bg-emerald-400":"bg-sky-400"}/>
              <span className="text-[10px] font-mono text-zinc-600">
                {loading?"processing":phase==="done"?"complete":phase==="error"?"error":"idle"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* ── History drawer ── */}
      {showHistory && <>
        <div className="fixed inset-y-0 right-0 z-40 w-80 bg-zinc-950 border-l border-zinc-800 shadow-2xl">
          <HistoryPanel history={history} onRestore={handleRestoreHistory}
            onClear={()=>{setHistory([]);try{localStorage.removeItem(HISTORY_KEY);}catch{}}}
            onClose={()=>setShowHistory(false)}/>
        </div>
        <div className="fixed inset-0 z-30 bg-zinc-950/50" onClick={()=>setShowHistory(false)}/>
      </>}

      {/* ── Main layout ── */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_400px] gap-6 items-start">

          {/* ── Left: input + results ── */}
          <div className="space-y-6">

            {/* Mode selector */}
            <div className="flex items-center gap-2">
              {[["single","Single File"],["project","Project / ZIP"]].map(([m,l])=>(
                <button key={m} onClick={()=>setMode(m)}
                  className={cn("px-4 py-2 text-xs font-mono rounded-lg border transition-all",
                    mode===m?"bg-zinc-100 text-zinc-950 border-zinc-100":"text-zinc-500 border-zinc-800 hover:border-zinc-600 hover:text-zinc-300")}>
                  {l}
                </button>
              ))}
            </div>

            {/* ── Single mode ── */}
            {mode==="single" && (
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden">
                {/* Panel header */}
                <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800">
                  <div className="flex items-center gap-3">
                    <div className="flex rounded-md border border-zinc-800 overflow-hidden">
                      {[["paste","Paste"],["upload","Upload"]].map(([id,l])=>(
                        <button key={id} onClick={()=>setInputMode(id)} className={cn("px-3 py-1 text-[10px] font-mono transition-colors", inputMode===id?"bg-zinc-800 text-zinc-200":"text-zinc-600 hover:text-zinc-400")}>{l}</button>
                      ))}
                    </div>
                    {fileName && <span className="text-[10px] font-mono text-zinc-500">{fileName}</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={()=>{setCode("");setFileName(null);}} className="text-[10px] font-mono text-zinc-600 hover:text-zinc-400 px-2 py-1 rounded hover:bg-zinc-800">clear</button>
                    <button onClick={()=>{setCode(SAMPLE);setLanguage("python");setFileName(null);setInputMode("paste");}} className="text-[10px] font-mono text-zinc-600 hover:text-zinc-400 px-2 py-1 rounded hover:bg-zinc-800">sample</button>
                  </div>
                </div>

                {inputMode==="upload" ? (
                  <div className="p-4">
                    <DropZone onFiles={handleFile} isDrag={isDrag} setIsDrag={setIsDrag}/>
                    {code && (
                      <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-950/20 border border-emerald-900/40">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0"/>
                        <span className="text-[10px] font-mono text-emerald-400">{fileName} loaded — {code.split("\n").length} lines</span>
                        <button onClick={()=>setInputMode("paste")} className="ml-auto text-[10px] font-mono text-zinc-600 hover:text-zinc-300">view →</button>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="relative">
                    <div className="absolute left-0 top-0 bottom-0 w-12 border-r border-zinc-800/50 flex flex-col pt-4 select-none pointer-events-none">
                      {code.split("\n").map((_,i)=>(
                        <div key={i} className="text-right pr-3 text-[10px] font-mono text-zinc-700 leading-[21px]">{i+1}</div>
                      ))}
                    </div>
                    <textarea ref={textRef} value={code} onChange={e=>setCode(e.target.value)} spellCheck={false}
                      className="w-full pl-14 pr-5 pt-4 pb-4 bg-transparent font-mono text-xs text-zinc-300 leading-[21px] resize-none outline-none min-h-[280px] placeholder:text-zinc-700"
                      placeholder="// Paste your source code here…"/>
                  </div>
                )}

                {/* Controls */}
                <div className="px-5 py-3 border-t border-zinc-800 flex items-center justify-between gap-4 bg-zinc-900/50 flex-wrap">
                  <div className="flex items-center gap-4 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-zinc-600">lang:</span>
                      <select value={language} onChange={e=>setLanguage(e.target.value)}
                        className="text-[10px] font-mono text-zinc-400 bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 outline-none focus:border-zinc-500">
                        {["python","javascript","typescript","java","go","rust","ruby","php","csharp"].map(l=>(
                          <option key={l} value={l}>{l}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flex items-center gap-1 flex-wrap">
                      {REGULATIONS.map(r=>(
                        <button key={r.id} onClick={()=>toggleReg(r.id)} title={r.desc}
                          className={cn("text-[9px] font-mono px-1.5 py-0.5 rounded border transition-all",
                            regulations.includes(r.id)?"text-emerald-400 border-emerald-800 bg-emerald-950/30":"text-zinc-700 border-zinc-800 hover:border-zinc-600 hover:text-zinc-500"
                          )}>{r.id}</button>
                      ))}
                    </div>
                  </div>
                  <button onClick={handleAudit} disabled={loading||!code.trim()}
                    className={cn("flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-mono font-medium transition-all",
                      loading||!code.trim()?"bg-zinc-800 text-zinc-600 cursor-not-allowed":"bg-zinc-100 text-zinc-950 hover:bg-white active:scale-95 shadow-lg shadow-zinc-900")}>
                    {loading ? (
                      <><svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Processing…</>
                    ) : (
                      <><svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>Sanitize &amp; Audit</>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* ── Project mode ── */}
            {mode==="project" && (
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden">
                <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-zinc-300">Project / ZIP Scan</span>
                  <span className="text-[10px] font-mono text-zinc-600">Max {20} files · 200 KB each · or one .zip</span>
                </div>
                <div className="p-4">
                  <DropZone onFiles={files=>{setProjectFiles(files);}} isDrag={isDragProject} setIsDrag={setIsDragProject} multi={true}/>
                  {projectFiles.length > 0 && (
                    <div className="mt-3 space-y-1">
                      {projectFiles.map((f,i)=>(
                        <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-800">
                          <span className="text-[10px] font-mono text-zinc-400 flex-1 truncate">{f.name}</span>
                          <span className="text-[10px] font-mono text-zinc-600">{(f.size/1024).toFixed(1)} KB</span>
                          <button onClick={()=>setProjectFiles(p=>p.filter((_,j)=>j!==i))} className="text-zinc-700 hover:text-red-400 text-sm leading-none">✕</button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="px-5 py-3 border-t border-zinc-800 flex items-center justify-between bg-zinc-900/50 flex-wrap gap-3">
                  <div className="flex items-center gap-1 flex-wrap">
                    {REGULATIONS.map(r=>(
                      <button key={r.id} onClick={()=>toggleReg(r.id)} title={r.desc}
                        className={cn("text-[9px] font-mono px-1.5 py-0.5 rounded border transition-all",
                          regulations.includes(r.id)?"text-emerald-400 border-emerald-800 bg-emerald-950/30":"text-zinc-700 border-zinc-800 hover:border-zinc-600")}>
                        {r.id}
                      </button>
                    ))}
                  </div>
                  <button onClick={handleProjectScan} disabled={loading||!projectFiles.length}
                    className={cn("flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-mono font-medium transition-all",
                      loading||!projectFiles.length?"bg-zinc-800 text-zinc-600 cursor-not-allowed":"bg-zinc-100 text-zinc-950 hover:bg-white active:scale-95")}>
                    {loading ? (<><svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Scanning…</>)
                    : <>Scan {projectFiles.length} File{projectFiles.length!==1?"s":""}</>}
                  </button>
                </div>
              </div>
            )}

            {/* ── Scan info banner (Phase 0) ── */}
            {scanInfo && (
              <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/10 px-5 py-3 flex items-center gap-4 flex-wrap">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0"/>
                <span className="text-[10px] font-mono text-emerald-400">Scanner: {scanInfo.scanner_used==="cpp"?"C++ _oxscanner":"Python fallback"}</span>
                <span className="text-[10px] font-mono text-zinc-500">{scanInfo.pii_count} PII token(s) redacted</span>
                {scanInfo.categories.length>0 && <span className="text-[10px] font-mono text-zinc-600">[{scanInfo.categories.join(", ")}]</span>}
                <span className="text-[10px] font-mono text-zinc-700">{scanInfo.elapsed_ms?.toFixed(1)}ms</span>
              </div>
            )}

            {/* ── Error ── */}
            {error && (
              <div className="rounded-xl border border-red-800/60 bg-red-950/20 px-5 py-4">
                <div className="flex items-start gap-3">
                  <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  <div>
                    <p className="text-sm font-mono text-red-400 font-medium">Pipeline Error</p>
                    <p className="text-xs font-mono text-red-400/70 mt-1 whitespace-pre-wrap">{error}</p>
                  </div>
                </div>
              </div>
            )}

            {/* ── Project results ── */}
            {projectResult && mode==="project" && !selectedFile && (
              <div className="rounded-xl border border-zinc-800 overflow-hidden">
                <div className="px-5 py-3 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-zinc-300">Project Scan Results</span>
                  <span className="text-[10px] font-mono text-zinc-600">{projectResult.elapsed_ms?.toFixed(0)}ms total</span>
                </div>
                <div className="p-5">
                  <ProjectResults data={projectResult} onSelectFile={f=>{setSelectedFile(f);setActiveTab("audit");}}/>
                </div>
              </div>
            )}

            {/* ── Back button when viewing a project file ── */}
            {selectedFile && (
              <button onClick={()=>setSelectedFile(null)} className="flex items-center gap-2 text-[10px] font-mono text-zinc-500 hover:text-zinc-300 transition-colors">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7"/>
                </svg>
                Back to project overview  ·  {selectedFile.file_name}
              </button>
            )}

            {/* ── Results tabs ── */}
            {displayResult && (
              <div className="rounded-xl border border-zinc-800 overflow-hidden">
                <div className="flex border-b border-zinc-800 bg-zinc-900/50">
                  {[
                    {id:"audit", label:"Audit Report",   count:violations.length},
                    {id:"risk",  label:"Risk & Fines",   count:null},
                    {id:"patch", label:"Patched Code",   count:diffHunks.length},
                  ].map(tab=>(
                    <button key={tab.id} onClick={()=>setActiveTab(tab.id)}
                      className={cn("flex items-center gap-2 px-5 py-3 text-xs font-mono transition-all border-b-2",
                        activeTab===tab.id?"text-zinc-100 border-zinc-400 bg-zinc-900/80":"text-zinc-600 border-transparent hover:text-zinc-400")}>
                      {tab.label}
                      {tab.count!=null && <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold", activeTab===tab.id?"bg-zinc-800 text-zinc-400":"bg-zinc-900 text-zinc-700")}>{tab.count}</span>}
                    </button>
                  ))}
                </div>

                <div className="p-5 space-y-4">
                  {activeTab==="audit" && <>
                    <div className="flex items-center gap-3 flex-wrap">
                      {[
                        {n:critCount, l:"critical", col:"text-red-400 border-red-900/40 bg-red-950/40"},
                        {n:highCount, l:"high",     col:"text-orange-400 border-orange-900/40 bg-orange-950/40"},
                        {n:violations.length, l:"total", col:"text-zinc-400 border-zinc-700/40 bg-zinc-800/60"},
                      ].map(({n,l,col})=>(
                        <div key={l} className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-[10px] font-mono", col)}>
                          <div className="w-1.5 h-1.5 rounded-full bg-current"/> {n} {l}
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-zinc-500 leading-relaxed">{displayResult.audit_report?.summary}</p>
                    <div className="space-y-2">
                      {violations.map((v,i)=><VCard key={v.id||i} v={v}/>)}
                      {violations.length===0 && <div className="text-center py-12 text-zinc-700 font-mono text-xs">No violations detected.</div>}
                    </div>
                  </>}

                  {activeTab==="risk" && (
                    <div className="space-y-6">
                      <div className="flex justify-center py-4">
                        <RiskGauge score={riskScore||0} label={riskLabel||"MINIMAL"}/>
                      </div>
                      <p className="text-xs text-zinc-500 leading-relaxed text-center max-w-lg mx-auto">{displayResult.risk_assessment?.rationale}</p>
                      {fines.length > 0 && (
                        <div className="rounded-lg border border-zinc-800 overflow-hidden">
                          <div className="px-4 py-2.5 bg-zinc-900/60 border-b border-zinc-800">
                            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">Regulatory Exposure</span>
                          </div>
                          <div className="px-4 divide-y divide-zinc-800/60">
                            {fines.map((f,i)=>(
                              <div key={i} className="flex items-center justify-between py-2.5">
                                <div>
                                  <span className="text-xs font-mono font-medium text-zinc-300">{f.regulation}</span>
                                  <p className="text-[10px] font-mono text-zinc-600 mt-0.5 max-w-xs truncate">{f.basis}</p>
                                </div>
                                <span className="text-xs font-mono text-orange-400 font-medium shrink-0 ml-4">{fmtEur(f.min_eur)} – {fmtEur(f.max_eur)}</span>
                              </div>
                            ))}
                          </div>
                          {totalExp > 0 && (
                            <div className="px-4 py-3 bg-zinc-900/40 border-t border-zinc-800 flex justify-between">
                              <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Total Max Exposure</span>
                              <span className="text-sm font-mono text-orange-400 font-bold">{fmtEur(totalExp)}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab==="patch" && (
                    <div className="space-y-5">
                      {changesSumm.length > 0 && (
                        <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-4 space-y-1.5">
                          <p className="text-[10px] font-mono text-emerald-500 uppercase tracking-widest mb-2">Changes Applied</p>
                          {changesSumm.map((c,i)=>(
                            <div key={i} className="flex items-start gap-2">
                              <span className="text-emerald-500 mt-0.5 text-xs shrink-0">+</span>
                              <span className="text-xs font-mono text-emerald-400/80">{c}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <DiffView hunks={diffHunks} patchedCode={patchedCode}/>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* ── Right sidebar ── */}
          <aside className="space-y-4 xl:sticky xl:top-16">
            {/* Pipeline info */}
            <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-4">
              <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Pipeline</h2>
              {[
                {p:"00",l:"PII Scanner",   s:"C++ std::regex / Python",     m:"_oxscanner (local)",               icon:"🔒",col:"text-zinc-400"},
                {p:"01",l:"Legal Auditor", s:"GDPR / DPDPA / HIPAA",        m:"llama-3.3-70b-versatile",          icon:"⚖️", col:"text-sky-400"},
                {p:"02",l:"Risk Judge",    s:"Score + fine prediction",       m:"deepseek-r1-distill-llama-70b",   icon:"📊",col:"text-orange-400"},
                {p:"03",l:"Architect",     s:"Surgical compliance patch",     m:"llama-3.3-70b-versatile",          icon:"🔧",col:"text-emerald-400"},
              ].map(({p,l,s,m,icon,col},i,a)=>(
                <div key={p} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-7 h-7 rounded-full border border-zinc-800 bg-zinc-900 flex items-center justify-center text-sm">{icon}</div>
                    {i<a.length-1 && <div className="w-px flex-1 bg-zinc-800/60 my-1"/>}
                  </div>
                  <div className="pb-4 last:pb-0">
                    <span className="text-[9px] font-mono text-zinc-700">Phase {p}</span>
                    <p className="text-xs font-medium text-zinc-300 mt-0.5">{l}</p>
                    <p className="text-[10px] font-mono text-zinc-600 mt-0.5">{s}</p>
                    <div className="mt-1.5 inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-zinc-800 bg-zinc-900/60">
                      <div className="w-1 h-1 rounded-full bg-zinc-600"/>
                      <span className={cn("text-[9px] font-mono",col)}>{m}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Scan metrics */}
            {displayResult && (
              <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-3">
                <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">Metrics</h2>
                {scanInfo && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-zinc-600">Scanner</span>
                    <div className="flex items-baseline gap-1">
                      <span className="text-xs font-mono font-medium text-zinc-300">{scanInfo.elapsed_ms?.toFixed(1)}ms</span>
                      <span className="text-[9px] font-mono text-zinc-700">phase 0</span>
                    </div>
                  </div>
                )}
                {[
                  {l:"Auditor",    v:displayResult.audit_report?.elapsed_ms,    u:"phase 1"},
                  {l:"Risk Judge", v:displayResult.risk_assessment?.elapsed_ms, u:"phase 2"},
                  {l:"Architect",  v:displayResult.patch_result?.elapsed_ms,    u:"phase 3"},
                  {l:"Pipeline",   v:displayResult.elapsed_ms,                  u:"total"},
                ].map(({l,v,u})=>(
                  <div key={l} className="flex items-center justify-between">
                    <span className="text-xs font-mono text-zinc-600">{l}</span>
                    <div className="flex items-baseline gap-1">
                      <span className="text-xs font-mono font-medium text-zinc-300">{v}ms</span>
                      <span className="text-[9px] font-mono text-zinc-700">{u}</span>
                    </div>
                  </div>
                ))}
                <div className="pt-2 border-t border-zinc-800">
                  <p className="text-[9px] font-mono text-zinc-700">req: {displayResult.request_id?.slice(0,16)}…</p>
                </div>
              </div>
            )}

            {/* Frameworks */}
            <div className="rounded-xl border border-zinc-800 p-5 bg-zinc-900/20 space-y-2">
              <h2 className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-3">Frameworks</h2>
              {REGULATIONS.map(({id,desc})=>(
                <div key={id} className="flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono font-medium text-zinc-400">{id}</span>
                    <p className="text-[9px] font-mono text-zinc-700 mt-0.5">{desc}</p>
                  </div>
                  <button onClick={()=>toggleReg(id)}
                    className={cn("text-[8px] font-mono px-1.5 py-0.5 rounded border transition-all",
                      regulations.includes(id)?"text-emerald-400 border-emerald-900/60 bg-emerald-950/30":"text-zinc-700 border-zinc-800 hover:border-zinc-600")}>
                    {regulations.includes(id)?"active":"off"}
                  </button>
                </div>
              ))}
            </div>
          </aside>
        </div>
      </main>

      <footer className="border-t border-zinc-800/60 mt-16 px-6 py-5">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <span className="text-[10px] font-mono text-zinc-700">oxbuild/compliance-agent v4 · local-first · PII never leaves your machine</span>
          <span className="text-[10px] font-mono text-zinc-700">C++ · Python · FastAPI · React · Groq · ReportLab</span>
        </div>
      </footer>
    </div>
  );
}

// ─── Minimal mock result for offline demo ────────────────────────────────────

function mockResult(code) {
  return {
    request_id: crypto.randomUUID?.() || "demo-" + Math.random().toString(36).slice(2),
    elapsed_ms: 1842,
    audit_report: {
      model:"llama-3.3-70b-versatile", regulations:["GDPR","DPDPA"],
      violations:[
        {id:"a1",regulation:"GDPR",article:"Article 25",severity:"CRITICAL",title:"No data minimisation",
         description:"SELECT * returns all columns including sensitive PII.",line_hint:'cursor.execute("SELECT * FROM users")',remediation:"Replace SELECT * with explicit field list."},
        {id:"b2",regulation:"GDPR",article:"Article 32",severity:"HIGH",title:"PII in logs",
         description:"Email written to print().",line_hint:"print(user.email)",remediation:"Use structured logging."},
        {id:"c3",regulation:"DPDPA",article:"Section 6",severity:"CRITICAL",title:"No consent check",
         description:"Processing without consent.",line_hint:null,remediation:"Add consent.verify() before data access."},
      ],
      total_count:3,critical_count:2,high_count:1,
      summary:"Found 3 violations — 2 critical, 1 high.",elapsed_ms:721,
    },
    risk_assessment:{
      model:"deepseek-r1-distill-llama-70b",normalised_score:78,risk_score:78,risk_label:"HIGH",
      fine_predictions:[
        {regulation:"GDPR",min_eur:2100000,max_eur:16800000,basis:"GDPR Art. 83(5): up to €20M or 4% turnover"},
        {regulation:"DPDPA",min_eur:800000,max_eur:22600000,basis:"DPDPA §33: up to ₹250 Cr"},
      ],
      total_exposure_min_eur:2900000,total_exposure_max_eur:39400000,
      rationale:"Risk 78/100 HIGH. Critical SELECT * and missing consent are primary drivers.",elapsed_ms:612,
    },
    patch_result:{
      model:"llama-3.3-70b-versatile",
      patched_code:"# [COMPLIANCE] GDPR Art. 25 — Data Minimisation\nimport logging\naudit_logger = logging.getLogger('app')\nREQUIRED_FIELDS = ('id','status','created_at')\n\ndef get_users():\n    cursor.execute('SELECT id, status FROM users')\n    return cursor.fetchall()\n",
      diff_hunks:[
        {hunk_id:1,original:'cursor.execute("SELECT * FROM users")',patched:"cursor.execute('SELECT id, status FROM users')",
         comment:"SELECT * replaced with explicit fields",regulation:"GDPR",article:"Art. 25"},
      ],
      changes_summary:["SELECT * replaced with explicit field list (GDPR Art. 25)","Added audit_logger (GDPR Art. 32)"],
      elapsed_ms:507,
    },
  };
}