import { useState, useEffect } from "react";
import { Shield, ShieldAlert, ShieldCheck, Activity, FileSearch, ChevronRight, Cpu, Lock, History, Settings, Package, Binary, Globe, MonitorCheck, Server, FolderOpen, Bell, Radio, Circle, Bug, FileJson } from "lucide-react";

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
  amber: "#f59e0b", 
  amberLo: "rgba(245,158,11,0.10)", 
  blue: "#3b82f6", 
  blueLo: "rgba(59,130,246,0.10)" 
};

function loadHistory() { 
  try { return JSON.parse(localStorage.getItem("msuite_history") || "[]"); } 
  catch { return []; } 
}

function saveHistory(data) { 
  try { localStorage.setItem("msuite_history", JSON.stringify(data)); } 
  catch {} 
}

function loadSettings() { 
  try { 
    return JSON.parse(localStorage.getItem("msuite_settings") || "null") || { 
      heuristic: true, 
      deepPattern: true, 
      deobfuscation: 2, 
      endpoint: "http://localhost:8000", 
      sensitivity: 7, 
      safePaths: ["/usr/local/bin", "C:\\Windows\\System32"], 
      trustedCerts: ["DigiCert Global Root G2"], 
      soundAlert: false, 
      desktopAlert: true 
    }; 
  } catch { return {}; } 
}

function saveSettings(s) { 
  try { localStorage.setItem("msuite_settings", JSON.stringify(s)); } 
  catch {} 
}

function GlassCard({ children, style = {} }) { 
  return <div className="glass-card" style={style}>{children}</div>; 
}

function Toggle({ value, onChange, size = 36 }) { 
  return (
    <button 
      onClick={() => onChange(!value)} 
      style={{ 
        width: size + 16, 
        height: size * 0.6, 
        borderRadius: size, 
        background: value ? T.indigo : "rgba(255,255,255,0.1)", 
        border: "none", 
        cursor: "pointer", 
        position: "relative", 
        transition: "background 0.25s", 
        flexShrink: 0, 
        boxShadow: value ? `0 0 10px rgba(99,102,241,0.4)` : "none" 
      }}
    >
      <div style={{ 
        width: size * 0.5, 
        height: size * 0.5, 
        borderRadius: "50%", 
        background: "white", 
        position: "absolute", 
        top: "50%", 
        transform: "translateY(-50%)", 
        left: value ? `calc(100% - ${size * 0.5 + 3}px)` : 3, 
        transition: "left 0.25s" 
      }} 
      />
    </button>
  ); 
}

function SectionLabel({ children }) { 
  return (
    <div style={{ fontSize: 10, color: T.textDim, letterSpacing: 3, fontFamily: "monospace", marginBottom: 14 }}>
      {children}
    </div>
  ); 
}

function PageHeader({ icon: Icon, title, subtitle, children }) { 
  return (
    <div style={{ marginBottom: 24, display: "flex", alignItems: "flex-start", justifyContent: "space-between", animation: "slideUp 0.4s both" }}>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <Icon size={14} color={T.indigo} />
          <span style={{ fontSize: 10, color: T.textMuted, letterSpacing: 3, fontFamily: "monospace" }}>{title.toUpperCase()}</span>
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: T.text }}>{title}</h1>
        {subtitle && <p style={{ fontSize: 12, color: T.textMuted, marginTop: 3 }}>{subtitle}</p>}
      </div>
      {children}
    </div>
  ); 
}

function exportForensicReport(results) {
  const forensicData = { 
    report_metadata: { 
      filename: results.filename, 
      timestamp: results.timestamp || new Date().toISOString(), 
      scan_method: results.scan_method || 'unknown', 
      tool_version: 'Sentinel v4.3' 
    }, 
    verdict: { 
      final_verdict: results.verdict, 
      risk_score: results.risk_score, 
      primary_intent: results.primary_intent || 'Unknown',
      ml_prediction: results.ml_verdict || results.ml_prediction || null,
      ml_confidence: results.ml_confidence !== undefined ? results.ml_confidence : null,
      ml_probability: results.ml_probability !== undefined ? results.ml_probability : null
    }, 
    findings: (results.raw_matches || []).map(match => ({ 
      filename: match.filename, 
      line_number: match.line_number, 
      pattern_found: match.pattern || match.matched_text, 
      calculated_risk: match.weight || (match.category === 'CODE_EXECUTION' ? 1.0 : 0.5), 
      behavioral_category: match.category || match.intent || 'UNKNOWN' 
    })), 
    ai_behavioral_scores: results.ai_behavioral_scores || null,
    ml_final_verdict: results.ml_verdict || null,
    ml_confidence_score: results.ml_confidence || null,
    raw_patterns: results.raw_patterns || [],
    ai_analysis: results.ai_summary ? { 
      file_system_score: results.file_system_score, 
      network_stealth_score: results.network_stealth_score, 
      obfuscation_detected: results.obfuscation_detected, 
      behavioral_summary: results.ai_summary 
    } : null,
    executive_summary: results.executive_summary || null,
    is_ai_verified: results.is_ai_verified || false,
    ai_confidence: results.ai_confidence || null
  };
  const blob = new Blob([JSON.stringify(forensicData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'Sentinel_Forensic_Analysis.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function DashboardPage({ history }) {
  const total = history.length;
  const threats = history.filter(h => (Number(h?.risk_score) || 0) >= 7).length;
  const clean = history.filter(h => (Number(h?.risk_score) || 0) < 4).length;
  const avgScore = total ? (history.reduce((a, b) => a + (Number(b?.risk_score) || 0), 0) / total).toFixed(1) : "—";
  const cards = [
    { icon: FileSearch, label: "Total Scans", value: total, color: T.indigo, sub: "All time" }, 
    { icon: ShieldAlert, label: "Threats Found", value: threats, color: T.red, sub: "Risk ≥ 7.0" }, 
    { icon: ShieldCheck, label: "Clean Files", value: clean, color: T.green, sub: "Risk < 4.0" }, 
    { icon: Activity, label: "Avg Risk Score", value: avgScore, color: T.amber, sub: "Out of 10.0" }
  ];
  const recentFive = history.slice(0, 5);
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={Activity} title="Dashboard" subtitle="Security posture summary" />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14, marginBottom: 22 }}>
        {cards.map(({ icon: Icon, label, value, color, sub }, i) => (
          <GlassCard key={i} style={{ padding: "20px 22px", animation: `slideUp 0.4s ${i * 0.07}s both` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <SectionLabel>{label}</SectionLabel>
                <div style={{ fontSize: 30, fontWeight: 700, color, fontFamily: "'Courier New', monospace" }}>{value}</div>
                <div style={{ fontSize: 11, color: T.textMuted, marginTop: 3 }}>{sub}</div>
              </div>
              <div style={{ width: 38, height: 38, borderRadius: 10, background: `${color}15`, border: `1px solid ${color}30`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon size={17} color={color} />
              </div>
            </div>
          </GlassCard>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <GlassCard style={{ padding: 22 }}>
          <SectionLabel>SYSTEM SAFETY GUARDRAILS</SectionLabel>
          {[
            { icon: MonitorCheck, label: "Static Analysis Mode", val: "ACTIVE", col: T.green }, 
            { icon: Shield, label: "Host System", val: "PROTECTED", col: T.green }, 
            { icon: Lock, label: "Sandbox Isolation", val: "ENABLED", col: T.green }, 
            { icon: Server, label: "Network Egress Control", val: "ENFORCED", col: T.amber }
          ].map(({ icon: Icon, label, val, col }, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: `1px solid ${T.border}` }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `${col}12`, border: `1px solid ${col}25`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <Icon size={14} color={col} />
              </div>
              <span style={{ flex: 1, fontSize: 13, color: T.text }}>{label}</span>
              <span style={{ fontSize: 11, fontFamily: "monospace", color: col, letterSpacing: 1, fontWeight: 700 }}>{val}</span>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: col, boxShadow: `0 0 6px ${col}`, flexShrink: 0 }} />
            </div>
          ))}
        </GlassCard>
        <GlassCard style={{ padding: 22 }}>
          <SectionLabel>RECENT SCAN ACTIVITY</SectionLabel>
          {recentFive.length === 0 ? (
            <div style={{ color: T.textMuted, fontSize: 13, textAlign: "center", paddingTop: 20 }}>
              No scans recorded yet. Go to File Scanner.
            </div>
          ) : (
            recentFive.map((item, i) => { 
              const score = Number(item?.risk_score) || 0; 
              const col = score >= 7 ? T.red : score >= 4 ? T.amber : T.green; 
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 0", borderBottom: `1px solid ${T.border}` }}>
                  <Circle size={5} fill={col} color={col} />
                  <span style={{ flex: 1, fontSize: 12, color: T.text, fontFamily: "'Courier New', monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {item?.filename || "unknown.zip"}
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: col, fontFamily: "monospace" }}>{score.toFixed(1)}</span>
                </div>
              ); 
            })
          )}
        </GlassCard>
      </div>
    </div>
  );
}

export function RemediationPage({ result, onBack }) {
  // Safely handle null/undefined result
  if (!result) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: T.textMuted }}>
        No scan result available
      </div>
    );
  }

  const score = Number(result?.risk_score) || 0;
  const col = score >= 7 ? T.red : score >= 4 ? T.amber : T.green;
  
  const getVerdictBadge = () => { 
    if (result?.verdict === "MALICIOUS") return { col: T.red, bg: T.redLo, label: "MALICIOUS" }; 
    if (result?.verdict === "SUSPICIOUS") return { col: T.amber, bg: T.amberLo, label: "SUSPICIOUS" }; 
    if (result?.verdict === "SIMULATION") return { col: T.blue, bg: T.blueLo, label: "SIMULATION" }; 
    return { col: T.green, bg: T.greenLo, label: "BENIGN" }; 
  };
  
  const verdictStyle = getVerdictBadge();
  const isAIScan = result?.scan_method === "ai-behavioral" || result?.ai_summary;
  const isAIJudged = result?.is_ai_judged === true || result?.is_ai_verified === true;
  const aiConfidence = result?.ai_confidence !== undefined ? result.ai_confidence : null;
  
  const getPrimaryIntent = () => { 
    if (result?.primary_intent) return result.primary_intent; 
    if (score >= 7.0) return 'Potential Ransomware/Malware'; 
    if (score >= 5.0) return 'Suspicious Behavior'; 
    if (score >= 3.0) return 'Low Risk / Utility'; 
    return 'Safe Developer Utility'; 
  };
  
  const mlVerdict = result?.ml_verdict || result?.ml_prediction;
  const mlConfidence = result?.ml_confidence !== undefined ? result.ml_confidence : null;
  const mlProbability = result?.ml_probability !== undefined ? result.ml_probability : null;
  const aiScores = result?.ai_behavioral_scores;
  
  // Get findings from either findings or raw_matches
  const findings = result?.findings || result?.raw_matches || [];
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      {/* Header with badges */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <button 
          onClick={onBack} 
          style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${T.border}`, borderRadius: 7, padding: "5px 12px", color: T.textMuted, cursor: "pointer", fontSize: 12, fontFamily: "monospace" }}
        >
          ← Back
        </button>
        <ChevronRight size={12} color={T.textDim} />
        <span style={{ fontFamily: "'Courier New',monospace", fontSize: 12, color: T.textMuted }}>{result?.filename || "Unknown file"}</span>
        <div style={{ flex: 1 }} />
        
        {/* Verdict Badge */}
        <div style={{ padding: "6px 14px", borderRadius: 8, background: verdictStyle.bg, border: `1px solid ${verdictStyle.col}30` }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: verdictStyle.col, fontFamily: "monospace" }}>{verdictStyle.label}</span>
        </div>
        
        {/* AI Analysis Badge */}
        {isAIScan && (
          <div style={{ padding: "4px 10px", borderRadius: 6, background: T.indigoLo, border: `1px solid ${T.indigo}30` }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: T.indigo, fontFamily: "monospace" }}>AI ANALYSIS</span>
          </div>
        )}
        
        {/* AI Context Verified Badge */}
        {isAIJudged && (
          <div style={{ padding: "4px 10px", borderRadius: 6, background: T.greenLo, border: `1px solid ${T.green}30` }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: T.green, fontFamily: "monospace" }}>
              AI CONTEXT VERIFIED
            </span>
          </div>
        )}
        
        {/* ML Prediction Badge */}
        {mlVerdict && (
          <div style={{ padding: "4px 10px", borderRadius: 6, background: T.violet + "20", border: `1px solid ${T.violet}40` }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: T.violet, fontFamily: "monospace" }}>ML PREDICTION</span>
          </div>
        )}
        
        <button 
          onClick={() => exportForensicReport(result)} 
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 7, background: T.indigoLo, border: `1px solid rgba(99,102,241,0.3)`, color: "#a5b4fc", cursor: "pointer", fontSize: 12, fontFamily: "monospace" }}
        >
          <FileJson size={14} /> Download Forensic Report
        </button>
      </div>
      
      {/* Status Bar */}
      <GlassCard style={{ padding: "14px 20px", marginBottom: 18, display: "flex", alignItems: "center", gap: 20, borderColor: `${T.green}30`, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: T.green, boxShadow: `0 0 8px ${T.green}`, animation: "pulse 2s infinite" }} />
          <span style={{ fontSize: 11, color: T.green, fontFamily: "monospace", letterSpacing: 1 }}>Static Analysis Mode: ACTIVE</span>
        </div>
        <div style={{ width: 1, height: 16, background: T.border }} />
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Shield size={12} color={T.green} />
          <span style={{ fontSize: 11, color: T.green, fontFamily: "monospace", letterSpacing: 1 }}>Host System: PROTECTED</span>
        </div>
        <div style={{ width: 1, height: 16, background: T.border }} />
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Lock size={12} color={T.amber} />
          <span style={{ fontSize: 11, color: T.amber, fontFamily: "monospace", letterSpacing: 1 }}>Sandbox: ISOLATED</span>
        </div>
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace" }}>Risk Score: {score.toFixed(1)}/10</span>
      </GlassCard>
      
      {/* Stats Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 18 }}>
        {[
          { label: "Risk Score", value: score.toFixed(1), color: col }, 
          { label: "Density", value: Number(result?.density || 0).toFixed(2), color: T.indigo }, 
          { label: "Total Files", value: result?.total_files || 0, color: T.textMuted }, 
          { label: "Findings", value: findings.length, color: T.amber }
        ].map(({ label, value, color }, i) => (
          <GlassCard key={i} style={{ padding: 16, textAlign: "center" }}>
            <div style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace", letterSpacing: 1, marginBottom: 6 }}>{label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color, fontFamily: "'Courier New',monospace" }}>{value}</div>
          </GlassCard>
        ))}
      </div>
      
      {/* ML Prediction Card */}
      {mlVerdict && (
        <GlassCard style={{ padding: 16, marginBottom: 18, background: T.violet + "08", borderColor: T.violet + "30" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace", letterSpacing: 1, marginBottom: 4 }}>ML PREDICTION</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: mlVerdict === "MALICIOUS" ? T.red : mlVerdict === "SUSPICIOUS" ? T.amber : T.green, fontFamily: "'Courier New',monospace" }}>
                {mlVerdict}
              </div>
            </div>
            <div style={{ width: 1, height: 40, background: T.border }} />
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace", letterSpacing: 1, marginBottom: 4 }}>CONFIDENCE</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: T.violet, fontFamily: "'Courier New',monospace" }}>
                {mlConfidence !== null ? `${mlConfidence}%` : (mlProbability !== null ? `${(mlProbability * 100).toFixed(1)}%` : '—')}
              </div>
            </div>
          </div>
          
          {/* AI Behavioral Scores */}
          {aiScores && (
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${T.border}` }}>
              <div style={{ fontSize: 10, color: T.textDim, fontFamily: "monospace", letterSpacing: 1, marginBottom: 10 }}>AI BEHAVIORAL SCORES</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 8 }}>
                {[
                  { label: "Persistence", score: aiScores.persistence || 0 }, 
                  { label: "Obfuscation", score: aiScores.obfuscation || 0 }, 
                  { label: "Exfiltration", score: aiScores.exfiltration || 0 }, 
                  { label: "Destruction", score: aiScores.destruction || 0 }, 
                  { label: "Injection", score: aiScores.injection || 0 }
                ].map(({ label, score }, i) => (
                  <div key={i} style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 4 }}>{label}</div>
                    <div style={{ height: 4, background: T.border, borderRadius: 2, overflow: "hidden" }}>
                      <div style={{ height: "100%", background: score > 0.5 ? T.red : T.green, width: `${Math.min((score || 0) * 100, 100)}%` }} />
                    </div>
                    <div style={{ fontSize: 10, color: T.text, fontFamily: "monospace", marginTop: 2 }}>{(score || 0).toFixed(2)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </GlassCard>
      )}
      
      {/* Executive Summary */}
      {(result?.reasoning || result?.ai_summary) && (
        <GlassCard style={{ padding: 20, marginBottom: 18 }}>
          <SectionLabel>EXECUTIVE SUMMARY - {getPrimaryIntent()}</SectionLabel>
          {result?.reasoning && (
            <p style={{ fontSize: 13, color: T.textMuted, lineHeight: 1.7 }}>{result.reasoning}</p>
          )}
          {result?.ai_summary && (
            <div style={{ marginTop: result?.reasoning ? 12 : 0, padding: 12, background: T.indigoLo, borderRadius: 8 }}>
              <div style={{ fontSize: 11, color: T.indigo, fontFamily: "monospace", marginBottom: 6 }}>AI BEHAVIORAL ANALYSIS</div>
              <p style={{ fontSize: 12, color: T.text, lineHeight: 1.6 }}>{result.ai_summary}</p>
            </div>
          )}
        </GlassCard>
      )}
      
      {/* Forensic Matches - FIXED THE ERROR HERE */}
      {findings.length > 0 && (
        <GlassCard style={{ overflow: "hidden" }}>
          <div style={{ padding: "12px 18px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 8 }}>
            <Bug size={13} color={T.indigo} />
            <span style={{ fontSize: 11, color: T.textMuted, letterSpacing: 2, fontFamily: "monospace" }}>FORENSIC MATCHES</span>
            <span style={{ marginLeft: "auto", fontSize: 10, color: T.indigo, fontFamily: "monospace" }}>{findings.length} matches</span>
          </div>
          <div style={{ maxHeight: 300, overflow: "auto" }}>
            <div style={{ display: "grid", gridTemplateColumns: "60px 1fr 80px 100px", padding: "8px 18px", borderBottom: `1px solid ${T.border}`, fontSize: 9, color: T.textDim, letterSpacing: 2, fontFamily: "monospace" }}>
              <span>LINE</span>
              <span>FILE</span>
              <span>CATEGORY</span>
              <span>PATTERN</span>
            </div>
            {findings.slice(0, 50).map((match, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "60px 1fr 80px 100px", padding: "8px 18px", borderBottom: `1px solid rgba(255,255,255,0.03)`, fontSize: 11, alignItems: "center" }}>
                <span style={{ fontFamily: "monospace", color: T.textMuted }}>{match.line_number || "-"}</span>
                <span style={{ fontFamily: "'Courier New',monospace", color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{match.filename || "unknown"}</span>
                <span style={{ color: match.category === "DANGEROUS_APIS" || match.behavioral_category === "HIGH_RISK" ? T.red : 
                                 match.category === "NETWORK_EXFIL" || match.behavioral_category === "MEDIUM_RISK" ? T.amber : T.textMuted, fontSize: 10 }}>
                  {match.category || match.behavioral_category || "UNKNOWN"}
                </span>
                <span style={{ color: T.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {match.pattern_found || match.matched_text || match.pattern || ""}
                </span>
              </div>
            ))}
          </div>
        </GlassCard>
      )}
      
      {/* No findings message */}
      {findings.length === 0 && (
        <GlassCard style={{ padding: 30, textAlign: "center" }}>
          <ShieldCheck size={30} color={T.green} style={{ marginBottom: 10 }} />
          <div style={{ color: T.textMuted, fontSize: 13 }}>
            No suspicious patterns detected in this file.
          </div>
        </GlassCard>
      )}
    </div>
  );
}

export function VaultPage({ history, onSelect, onClear }) {
  const [filter, setFilter] = useState("all");
  
  const filtered = filter === "all" 
    ? history 
    : history.filter(h => { 
        const s = Number(h?.risk_score) || 0; 
        return filter === "malicious" ? s >= 7 : filter === "suspicious" ? s >= 4 && s < 7 : s < 4; 
      });
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={History} title="Scan Vault" subtitle="Persistent history of all analyzed packages">
        {history.length > 0 && (
          <button 
            onClick={onClear} 
            style={{ padding: "6px 14px", borderRadius: 7, background: T.redLo, border: `1px solid rgba(239,68,68,0.2)`, color: "rgba(239,68,68,0.7)", fontSize: 12, cursor: "pointer" }}
          >
            Clear Vault
          </button>
        )}
      </PageHeader>
      
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          ["all", "All"], 
          ["malicious", "Malicious"], 
          ["suspicious", "Suspicious"], 
          ["benign", "Benign"]
        ].map(([id, label]) => (
          <button 
            key={id} 
            onClick={() => setFilter(id)} 
            style={{ 
              padding: "5px 14px", 
              borderRadius: 7, 
              border: `1px solid ${filter === id ? "rgba(99,102,241,0.5)" : T.border}`, 
              background: filter === id ? T.indigoLo : "transparent", 
              color: filter === id ? "#a5b4fc" : T.textMuted, 
              fontSize: 12, 
              cursor: "pointer", 
              fontFamily: "monospace", 
              transition: "all 0.15s" 
            }}
          >
            {label}
          </button>
        ))}
      </div>
      
      <GlassCard style={{ overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 70px 1fr 100px", padding: "10px 18px", borderBottom: `1px solid ${T.border}`, fontSize: 9, color: T.textDim, letterSpacing: 2, fontFamily: "monospace" }}>
          <span>FILENAME</span>
          <span>VERDICT</span>
          <span>SCORE</span>
          <span>TIMESTAMP</span>
          <span>ACTION</span>
        </div>
        
        {filtered.length === 0 ? (
          <div style={{ padding: "40px 18px", textAlign: "center", color: T.textMuted, fontSize: 13 }}>
            {history.length === 0 ? "No scans recorded yet." : "No results match this filter."}
          </div>
        ) : (
          filtered.map((item, i) => { 
            const score = Number(item?.risk_score) || 0; 
            const col = score >= 7 ? T.red : score >= 4 ? T.amber : T.green; 
            const verdict = score >= 7 ? "MALICIOUS" : score >= 4 ? "SUSPICIOUS" : "BENIGN"; 
            return (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 70px 1fr 100px", padding: "11px 18px", borderBottom: `1px solid rgba(255,255,255,0.03)`, alignItems: "center", transition: "background 0.15s", cursor: "default" }}>
                <span style={{ fontFamily: "'Courier New',monospace", fontSize: 12, color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {item?.filename || "—"}
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <Circle size={5} fill={col} color={col} />
                  <span style={{ fontSize: 11, color: col, fontFamily: "monospace" }}>{verdict}</span>
                </span>
                <span style={{ fontSize: 13, fontWeight: 700, color: col, fontFamily: "monospace" }}>{score.toFixed(1)}</span>
                <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace" }}>
                  {item?.timestamp ? new Date(item.timestamp).toLocaleString() : "—"}
                </span>
                <button 
                  onClick={() => onSelect(item)} 
                  style={{ padding: "4px 10px", borderRadius: 6, background: T.indigoLo, border: `1px solid rgba(99,102,241,0.3)`, color: "#a5b4fc", fontSize: 11, cursor: "pointer", fontFamily: "monospace" }}
                >
                  Details
                </button>
              </div>
            ); 
          })
        )}
      </GlassCard>
    </div>
  );
}

export function SettingsPage({ settings, onChange }) {
  const set = (key, val) => { 
    const next = { ...settings, [key]: val }; 
    onChange(next); 
    saveSettings(next); 
  };
  
  const Section = ({ title, icon: Icon, children }) => (
    <GlassCard style={{ padding: 22, marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18, paddingBottom: 12, borderBottom: `1px solid ${T.border}` }}>
        <div style={{ width: 30, height: 30, borderRadius: 8, background: T.indigoLo, border: `1px solid rgba(99,102,241,0.2)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon size={13} color={T.indigo} />
        </div>
        <span style={{ fontSize: 13, fontWeight: 600, color: T.text }}>{title}</span>
      </div>
      {children}
    </GlassCard>
  );
  
  const Row = ({ label, sub, children }) => (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
      <div>
        <div style={{ fontSize: 13, color: T.text }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>{sub}</div>}
      </div>
      {children}
    </div>
  );
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={Settings} title="Settings" subtitle="Engine configuration, API endpoints, and security preferences" />
      
      <Section title="API Configuration" icon={Server}>
        <Row label="Backend Endpoint URL" sub="FastAPI server address for scan requests">
          <input 
            value={settings.endpoint} 
            onChange={e => set("endpoint", e.target.value)} 
            placeholder="http://localhost:8000" 
            style={{ width: 240, padding: "7px 11px", borderRadius: 7, background: "rgba(255,255,255,0.04)", border: `1px solid ${T.border}`, color: T.text, fontSize: 12, fontFamily: "monospace", outline: "none" }} 
          />
        </Row>
        <Row label="Threshold Sensitivity" sub={`Verdict sensitivity (1 = lenient · 10 = strict) — current: ${settings.sensitivity}`}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace", minWidth: 10 }}>1</span>
            <input 
              type="range" 
              min={1} 
              max={10} 
              step={1} 
              value={settings.sensitivity} 
              onChange={e => set("sensitivity", +e.target.value)} 
              style={{ width: 140, accentColor: T.indigo, cursor: "pointer" }} 
            />
            <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace" }}>10</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: T.indigo, fontFamily: "monospace", minWidth: 16, textAlign: "center" }}>{settings.sensitivity}</span>
          </div>
        </Row>
      </Section>
      
      <Section title="Scan Engine" icon={Cpu}>
        <Row label="Heuristic Analysis" sub="ML-based anomaly detection">
          <Toggle value={settings.heuristic} onChange={v => set("heuristic", v)} />
        </Row>
        <Row label="Deep Pattern Matching" sub="Extended YARA rule-set">
          <Toggle value={settings.deepPattern} onChange={v => set("deepPattern", v)} />
        </Row>
      </Section>
      
      <Section title="Notifications" icon={Bell}>
        <Row label="Sound on Threat Detection" sub="Play alert tone">
          <Toggle value={settings.soundAlert} onChange={v => set("soundAlert", v)} />
        </Row>
        <Row label="Desktop Alerts" sub="OS-level notification">
          <Toggle value={settings.desktopAlert} onChange={v => set("desktopAlert", v)} />
        </Row>
      </Section>
    </div>
  );
}

export { loadHistory, saveHistory, loadSettings, saveSettings, T };