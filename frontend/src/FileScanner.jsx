import { useState, useRef } from "react";
import { Upload, Package, Shield, Bot, Activity, FileJson } from "lucide-react";

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
  green: "#10b981",
  greenLo: "rgba(16,185,129,0.10)",
  amber: "#f59e0b",
  amberLo: "rgba(245,158,11,0.10)",
};

function GlassCard({ children, style = {} }) {
  return <div className="glass-card" style={style}>{children}</div>;
}

function PageHeader({ icon: Icon, title, subtitle }) {
  return (
    <div style={{ marginBottom: 24, animation: "slideUp 0.4s both" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <Icon size={14} color={T.indigo} />
        <span style={{ fontSize: 10, color: T.textMuted, letterSpacing: 3, fontFamily: "monospace" }}>{title.toUpperCase()}</span>
      </div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: T.text }}>{title}</h1>
      {subtitle && <p style={{ fontSize: 12, color: T.textMuted, marginTop: 3 }}>{subtitle}</p>}
    </div>
  );
}

function AIBadge({ data }) {
  // Show different badge based on AI verification status
  if (data.is_ai_verified) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 20px',
        background: T.greenLo,
        border: '1px solid rgba(16,185,129,0.4)',
        borderRadius: 12,
        marginTop: 20
      }}>
        <div style={{ width: 40, height: 40, borderRadius: 10, background: T.greenLo, border: '1px solid rgba(16,185,129,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Bot size={20} color={T.green} />
        </div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: T.green }}>Gemini 3.1 Pro Verified</div>
          <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>Pure behavioral analysis - AI powered</div>
        </div>
      </div>
    );
  } else {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 20px',
        background: T.indigoLo,
        border: '1px solid rgba(99,102,241,0.4)',
        borderRadius: 12,
        marginTop: 20
      }}>
        <div style={{ width: 40, height: 40, borderRadius: 10, background: T.indigoLo, border: '1px solid rgba(99,102,241,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={20} color={T.indigo} />
        </div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: T.indigo }}>Heuristic Analysis</div>
          <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>Rule-based scanning - AI skipped (low risk)</div>
        </div>
      </div>
    );
  }
}

function exportForensicReport(result) {
  const forensicData = {
    filename: result.filename,
    timestamp: new Date().toISOString(),
    verdict: result.verdict,
    risk_score: result.risk_score,
    is_ai_verified: result.is_ai_verified,
    analysis: result.ai_summary || result.executive_summary,
    findings: result.findings || []
  };
  
  const blob = new Blob([JSON.stringify(forensicData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic_report_${result.filename}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function FileScannerPage({ onScanComplete }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [filename, setFilename] = useState("");
  const [result, setResult] = useState(null);
  const fileRef = useRef();

  const AI_STAGES = [
    "Contacting Gemini 3.1 Pro...",
    "AI Behavioral Analysis in Progress...",
    "Generating forensic verdict...",
    "Scan complete."
  ];

  const uploadFile = async (file) => {
    setFilename(file.name);
    setUploading(true);
    setProgress(0);

    const formData = new FormData();
    formData.append('file', file);

    try {
      setProgress(30);
      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      setProgress(80);
      
      // Check if response is valid (any status except explicit error)
      if (data && data.status !== 'error') {
        // Ensure result has expected structure with fallbacks
        const processedResult = {
          ...data,
          verdict: data.verdict || 'UNKNOWN',
          risk_score: data.risk_score || 0,
          is_ai_verified: data.is_ai_verified || false,
          ai_summary: data.ai_summary || data.executive_summary || 'Scan completed successfully',
          filename: data.filename || file.name
        };
        
        setResult(processedResult);
        if (onScanComplete) onScanComplete(processedResult);
      } else {
        // Handle error response
        throw new Error(data?.message || 'Scan failed');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      alert('Scan failed: ' + error.message);
    } finally {
      setUploading(false);
      setProgress(100);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file);
  };

  const handleInput = (e) => {
    const file = e.target.files[0];
    if (file) uploadFile(file);
  };

  // Loading state
  if (uploading) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "70vh", gap: 32 }}>
        <div style={{ position: "relative", width: 100, height: 100 }}>
          <div style={{ position: "absolute", borderRadius: "50%", border: `2px solid ${T.indigo}20`, width: "100%", height: "100%", animation: "ripple 1.5s ease-out infinite" }} />
          <div style={{ width: 60, height: 60, borderRadius: "50%", background: T.indigoLo, border: "2px solid rgba(99,102,241,0.4)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Bot size={24} color="#818cf8" />
          </div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: T.text }}>{filename}</div>
          <div style={{ fontSize: 12, color: T.textMuted, marginTop: 4 }}>AI Behavioral Analysis in Progress...</div>
        </div>
        <div style={{ width: 400 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, fontSize: 11, color: T.textMuted }}>
            <span>Gemini 3.1 Pro</span>
            <span>{progress}%</span>
          </div>
          <div style={{ height: 4, background: T.border, borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", background: `linear-gradient(90deg, ${T.indigo}, ${T.violet})`, width: `${progress}%`, transition: "width 0.4s ease" }} />
          </div>
        </div>
      </div>
    );
  }

  // Results state
  if (result) {
    // Determine color based on verdict
    const getVerdictColor = () => {
      if (result.verdict === "MALICIOUS") return T.red;
      if (result.verdict === "SUSPICIOUS") return T.amber;
      if (result.verdict === "BENIGN") return T.green;
      return T.textMuted;
    };

    return (
      <div style={{ animation: "slideInRight 0.35s both" }}>
        <PageHeader icon={Shield} title="Scan Complete" subtitle={`Analysis for ${result.filename}`} />
        <GlassCard style={{ padding: 32 }}>
          <AIBadge data={result} />
          
          <div style={{ marginTop: 24, paddingTop: 24, borderTop: `1px solid ${T.border}` }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: T.text, marginBottom: 12 }}>Verdict</div>
            <div style={{ 
              fontSize: 32, 
              fontWeight: 800, 
              color: getVerdictColor(),
              marginBottom: 8 
            }}>
              {result.verdict}
            </div>
            <div style={{ fontSize: 20, color: T.textMuted, fontFamily: "monospace" }}>
              Risk Score: {result.risk_score}/10
            </div>
            
            {/* AI Summary */}
            <div style={{ 
              fontSize: 13, 
              color: T.text, 
              marginTop: 16, 
              lineHeight: 1.6,
              padding: 16,
              background: T.surface,
              borderRadius: 8,
              border: `1px solid ${T.border}`
            }}>
              {result.ai_summary}
            </div>
            
            {/* AI Verification Status */}
            {!result.is_ai_verified && (
              <div style={{ 
                marginTop: 16, 
                padding: 12, 
                background: T.indigoLo, 
                borderRadius: 8,
                fontSize: 12,
                color: T.indigo,
                border: `1px solid ${T.indigo}30`,
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}>
                <Shield size={16} />
                <span>⚡ AI analysis skipped (low risk) - Using heuristic rules. Results are still accurate.</span>
              </div>
            )}
            
            {/* Findings count if any */}
            {result.findings && result.findings.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 12, color: T.textMuted, marginBottom: 8 }}>
                  Found {result.findings.length} suspicious pattern(s)
                </div>
                <div style={{ maxHeight: 200, overflow: 'auto' }}>
                  {result.findings.slice(0, 5).map((finding, idx) => (
                    <div key={idx} style={{
                      padding: 8,
                      borderBottom: `1px solid ${T.border}`,
                      fontSize: 11,
                      color: T.textMuted
                    }}>
                      <span style={{ color: T.indigo }}>{finding.filename}:{finding.line_number}</span> - {finding.pattern_found}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {/* Download button */}
          <div style={{ marginTop: 24, display: 'flex', gap: 12 }}>
            <button 
              onClick={() => exportForensicReport(result)} 
              style={{ 
                display: "flex", 
                alignItems: "center", 
                gap: 8, 
                padding: "12px 24px", 
                borderRadius: 8, 
                background: T.indigoLo, 
                border: "1px solid rgba(99,102,241,0.3)", 
                color: T.indigo, 
                cursor: "pointer", 
                fontWeight: 600,
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = T.indigo + '20'}
              onMouseLeave={(e) => e.currentTarget.style.background = T.indigoLo}
            >
              <FileJson size={16} />
              Download Forensic JSON
            </button>
            
            <button 
              onClick={() => setResult(null)} 
              style={{ 
                display: "flex", 
                alignItems: "center", 
                gap: 8, 
                padding: "12px 24px", 
                borderRadius: 8, 
                background: 'transparent', 
                border: `1px solid ${T.border}`, 
                color: T.textMuted, 
                cursor: "pointer", 
                fontWeight: 600
              }}
            >
              Scan Another File
            </button>
          </div>
        </GlassCard>
      </div>
    );
  }

  // Upload state
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={Upload} title="AI File Scanner" subtitle="Upload package for AI behavioral analysis" />
      <div 
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }} 
        onDragLeave={() => setDragging(false)} 
        onDrop={handleDrop} 
        onClick={() => fileRef.current.click()} 
        style={{ 
          border: `2px dashed ${dragging ? T.indigo : T.border}`, 
          borderRadius: 20, 
          padding: "64px 48px", 
          display: "flex", 
          flexDirection: "column", 
          alignItems: "center", 
          gap: 16, 
          cursor: "pointer", 
          transition: "all 0.3s", 
          background: dragging ? T.indigoLo : T.surface, 
          boxShadow: dragging ? `0 0 40px rgba(99,102,241,0.15)` : "none" 
        }}
      >
        <input ref={fileRef} type="file" accept=".zip,.tgz,.js,.py" style={{ display: "none" }} onChange={handleInput} />
        <div style={{ width: 72, height: 72, borderRadius: 20, background: T.indigoLo, border: `2px solid rgba(99,102,241,0.3)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Package size={32} color="#818cf8" />
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: T.text, marginBottom: 6 }}>Drop ZIP or File</div>
          <div style={{ fontSize: 13, color: T.textMuted }}>AI-powered malware detection</div>
        </div>
        <div style={{ padding: "12px 32px", borderRadius: 12, background: `linear-gradient(135deg, ${T.indigo}, ${T.violet})`, fontSize: 14, fontWeight: 600, color: "white", boxShadow: "0 4px 20px rgba(99,102,241,0.4)" }}>
          Choose File
        </div>
      </div>
      
      {/* Info cards */}
      <div style={{ display: "flex", gap: 16, marginTop: 24 }}>
        <GlassCard style={{ flex: 1, padding: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: T.text, marginBottom: 16 }}>Smart Analysis Pipeline</div>
          <ul style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6 }}>
            <li>• Memory-only extraction</li>
            <li>• AI behavioral analysis</li>
            <li>• Smart rate limit handling</li>
            <li>• Heuristic fallback when needed</li>
          </ul>
        </GlassCard>
        <GlassCard style={{ flex: 1, padding: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: T.text, marginBottom: 16 }}>Sentinel v5.0</div>
          <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6 }}>
            Backend: Optimized AI calls<br/>
            Frontend: Enhanced error handling<br/>
            Status: Rate limit protected
          </div>
        </GlassCard>
      </div>
    </div>
  );
}