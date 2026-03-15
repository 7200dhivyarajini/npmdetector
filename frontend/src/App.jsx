import { useState, useEffect } from "react";
import {
  Shield, Activity, Upload, History, Settings,
  ChevronRight, Radio, Bug
} from "lucide-react";
import { SignedIn, SignedOut, UserButton, RedirectToSignIn, useAuth } from "@clerk/clerk-react";
import { Routes, Route, Navigate } from "react-router-dom";

// Import components from split files
import FileScannerPage from "./FileScanner";
import { DashboardPage, RemediationPage, VaultPage, SettingsPage, loadHistory, saveHistory, loadSettings } from "./DashboardComponents";

// Shared theme constants
const T = {
  bg: "#020617",
  surface: "rgba(255,255,255,0.022)",
  border: "rgba(255,255,255,0.065)",
  text: "#e2e8f0",
  textMuted: "rgba(255,255,255,0.35)",
  textDim: "rgba(255,255,255,0.18)",
  indigo: "#6366f1",
  indigoLo: "rgba(99,102,241,0.12)",
  violet: "#8b5cf6",
  red: "#ef4444",
  redLo: "rgba(239,68,68,0.10)",
  green: "#10b981",
  greenLo: "rgba(16,185,129,0.10)",
};

/* ─── Dashboard View Component (contains main app UI) ─────────────────── */
function DashboardView() {
  const [page, setPage] = useState("dashboard");
  const [history, setHistory] = useState([]);
  const [settings, setSettings] = useState(loadSettings());
  const [lastResult, setLastResult] = useState(null);
  const [remTarget, setRemTarget] = useState(null);

  useEffect(() => { setHistory(loadHistory()); }, []);

  const handleScanComplete = (data) => {
    const next = [data, ...history].slice(0, 60);
    setHistory(next); saveHistory(next);
    setLastResult(data);
    setPage("remediate");
  };

  const handleVaultSelect = (item) => { setRemTarget(item); setPage("remediate"); };
  const clearVault = () => { setHistory([]); saveHistory([]); };

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: Activity },
    { id: "scanner", label: "File Scanner", icon: Upload },
    { id: "vault", label: "Scan Vault", icon: History },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  const renderPage = () => {
    switch (page) {
      case "dashboard": return <DashboardPage history={history} />;
      case "scanner": return <FileScannerPage onScanComplete={handleScanComplete} settings={settings} />;
      case "remediate": return <RemediationPage result={remTarget || lastResult || { filename: "example.zip", risk_score: 0, verdict: "UNKNOWN" }} onBack={() => { setPage(remTarget ? "vault" : "scanner"); setRemTarget(null); }} />;
      case "vault": return <VaultPage history={history} onSelect={handleVaultSelect} onClear={clearVault} />;
      case "settings": return <SettingsPage settings={settings} onChange={setSettings} />;
      default: return null;
    }
  };

  return (
    <>
      <style>{`
        * { box-sizing:border-box; margin:0; padding:0; }
        body { background:${T.bg}; font-family:'Segoe UI', system-ui, sans-serif; }
        @keyframes slideUp { from { opacity:0; transform:translateY(14px); } to { opacity:1; transform:translateY(0); } }
        @keyframes slideInRight { from { opacity:0; transform:translateX(12px); } to { opacity:1; transform:translateX(0); } }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
        @keyframes ripple { 0% { transform:scale(0.7); opacity:0.6; } 100% { transform:scale(2.4); opacity:0; } }
        @keyframes glowPulse { 0%,100% { box-shadow:0 0 30px rgba(99,102,241,0.4); } 50% { box-shadow:0 0 60px rgba(99,102,241,0.7); } }
        .glass-card { background:${T.surface}; border:1px solid ${T.border}; border-radius:12px; backdrop-filter:blur(10px); }
        .nav-btn:hover { background:rgba(255,255,255,0.05) !important; }
        ::-webkit-scrollbar { width:4px; height:4px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.08); border-radius:2px; }
      `}</style>
      <div style={{ display: "flex", height: "100vh", width: "100%", background: T.bg, overflow: "hidden" }}>
        <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: `radial-gradient(ellipse 55% 45% at 8% 0%, rgba(99,102,241,0.055) 0%, transparent 55%), radial-gradient(ellipse 35% 35% at 92% 98%, rgba(139,92,246,0.04) 0%, transparent 55%)`, backgroundSize: "100% 100%, 100% 100%" }} />
        <div style={{ width: 210, background: "rgba(255,255,255,0.016)", borderRight: `1px solid ${T.border}`, display: "flex", flexDirection: "column", padding: "18px 10px", zIndex: 10, flexShrink: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "6px 8px", marginBottom: 24 }}>
            <div style={{ width: 32, height: 32, borderRadius: 9, background: `linear-gradient(135deg,${T.indigo},${T.violet})`, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 0 16px rgba(99,102,241,0.4)", flexShrink: 0 }}><Shield size={16} color="white" /></div>
            <div><div style={{ fontSize: 13, fontWeight: 700, color: T.text, letterSpacing: 0.3 }}>Sentinel</div><div style={{ fontSize: 9, color: T.textDim, letterSpacing: 2, fontFamily: "monospace" }}>ANALYSIS SUITE</div></div>
          </div>
          <div style={{ fontSize: 9, color: T.textDim, letterSpacing: 3, fontFamily: "monospace", padding: "0 8px", marginBottom: 6 }}>NAVIGATION</div>
          {navItems.map(({ id, label, icon: Icon }) => {
            const active = page === id || (page === "remediate" && id === "scanner");
            return (
              <button key={id} className="nav-btn" onClick={() => { setRemTarget(null); setPage(id); }} style={{ width: "100%", padding: "9px 10px", borderRadius: 8, border: "none", background: active ? "rgba(99,102,241,0.14)" : "transparent", color: active ? "#a5b4fc" : T.textMuted, display: "flex", alignItems: "center", gap: 9, cursor: "pointer", fontSize: 13, fontWeight: active ? 600 : 400, textAlign: "left", transition: "all 0.14s", marginBottom: 2, boxShadow: active ? "inset 0 0 0 1px rgba(99,102,241,0.28)" : "none" }}>
                <Icon size={14} />{label}{id === "vault" && history.length > 0 && <span style={{ marginLeft: "auto", fontSize: 10, padding: "1px 6px", borderRadius: 10, background: "rgba(99,102,241,0.18)", color: "#818cf8", fontFamily: "monospace" }}>{history.length}</span>}
              </button>
            );
          })}
          {(lastResult || remTarget) && (
            <><div style={{ height: 1, background: T.border, margin: "12px 0" }} />
            <div style={{ fontSize: 9, color: T.textDim, letterSpacing: 3, fontFamily: "monospace", padding: "0 8px", marginBottom: 6 }}>ACTIVE SESSION</div>
            <button className="nav-btn" onClick={() => setPage("remediate")} style={{ width: "100%", padding: "9px 10px", borderRadius: 8, border: "none", background: page === "remediate" ? "rgba(239,68,68,0.12)" : "transparent", color: page === "remediate" ? "#fca5a5" : T.textMuted, display: "flex", alignItems: "center", gap: 9, cursor: "pointer", fontSize: 13, textAlign: "left", transition: "all 0.14s", boxShadow: page === "remediate" ? "inset 0 0 0 1px rgba(239,68,68,0.25)" : "none" }}><Bug size={14} /> Remediation<span style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: T.red, boxShadow: `0 0 6px ${T.red}`, animation: "pulse 2s infinite" }} /></button></>
          )}
          <div style={{ flex: 1 }} />
          <div style={{ padding: "12px 10px", background: "rgba(16,185,129,0.06)", borderRadius: 8, border: `1px solid rgba(16,185,129,0.12)` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 3 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: T.green, boxShadow: `0 0 6px ${T.green}`, animation: "pulse 2s infinite" }} /><span style={{ fontSize: 10, color: "#34d399", fontFamily: "monospace", letterSpacing: 1 }}>ENGINE ONLINE</span></div>
            <div style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace" }}>Sentinel v4.2 · Ready</div>
          </div>
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", zIndex: 1 }}>
          <div style={{ height: 48, borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", padding: "0 24px", gap: 14, background: "rgba(2,6,23,0.7)", backdropFilter: "blur(20px)", flexShrink: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: T.textDim }}><span>Sentinel</span><ChevronRight size={10} /><span style={{ color: T.textMuted }}>{navItems.find(n => n.id === page || (page === "remediate" && n.id === "scanner"))?.label ?? "Remediation"}</span></div>
            <div style={{ flex: 1 }} />
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}><Radio size={10} color={T.green} /><span style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace" }}>LIVE</span></div>
            <div style={{ width: 1, height: 14, background: T.border }} />
            <div style={{ fontSize: 10, color: T.textDim, fontFamily: "'Courier New',monospace" }}>{new Date().toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" })}</div>
            <div style={{ marginLeft: 16 }}><UserButton afterSignOutUrl="/" /></div>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: "24px 28px" }}>{renderPage()}</div>
        </div>
      </div>
    </>
  );
}

/* ─── RootContent - Contains all Clerk hooks and routing logic ──────── */
function RootContent() {
  const { isLoaded, isSignedIn } = useAuth();

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      localStorage.removeItem("msuite_history");
      localStorage.removeItem("msuite_settings");
    }
  }, [isLoaded, isSignedIn]);

  if (!isLoaded) {
    return <div style={{ color: 'white' }}>Loading System...</div>;
  }

  return (
    <Routes>
      <Route
        path="/"
        element={
          isSignedIn ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <RedirectToSignIn />
          )
        }
      />
      <Route
        path="/dashboard"
        element={
          <SignedIn>
            <DashboardView />
          </SignedIn>
        }
      />
      <Route
        path="*"
        element={
          isSignedIn ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <RedirectToSignIn />
          )
        }
      />
    </Routes>
  );
}

/* ─── Main App Component - Contains ClerkProvider and Routes ─ */
export default function MalwareRemediationSuite() {
  return <RootContent />;
}
