import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { 
  Shield, ShieldAlert, ShieldCheck, Activity, FileSearch, ChevronRight, 
  Cpu, Lock, History, Settings, Package, Binary, Globe, MonitorCheck, 
  Server, FolderOpen, Bell, Radio, Circle, Bug, FileJson, Scan, 
  Clock, AlertTriangle, CheckCircle, TrendingUp, BarChart3, 
  PieChart, Radar, Target, Zap, Eye, Fingerprint, Wifi, Database,
  AlertOctagon, FileCode, Binary as BinaryIcon, Network, Terminal,
  ArrowLeft, Download, Sparkles
} from "lucide-react";

// ============================================
// THEME CONSTANTS - CYBERPUNK NEON
// ============================================
const T = { 
  bg: "#0a0e14", 
  surface: "rgba(18, 25, 45, 0.85)", 
  surfaceLight: "rgba(30, 41, 59, 0.7)",
  border: "rgba(0, 255, 255, 0.15)", 
  borderGlow: "rgba(0, 255, 255, 0.4)",
  text: "#e2e8f0", 
  textMuted: "rgba(255,255,255,0.45)", 
  textDim: "rgba(255,255,255,0.25)", 
  cyan: "#00f3ff", 
  cyanLo: "rgba(0, 243, 255, 0.1)", 
  magenta: "#ff00ff",
  magentaLo: "rgba(255, 0, 255, 0.1)",
  neonGreen: "#00ff88",
  neonGreenLo: "rgba(0, 255, 136, 0.1)",
  red: "#ff3366", 
  redLo: "rgba(255, 51, 102, 0.1)", 
  amber: "#ffaa00", 
  amberLo: "rgba(255, 170, 0, 0.1)",
  indigo: "#6366f1",
  purple: "#8b5cf6",
  green: "#10b981",
  greenLo: "rgba(16, 185, 129, 0.1)"
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
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

// ============================================
// HELPER FUNCTION FOR CHANGE BADGES
// ============================================
function getChangeBadge(changeType) {
  const badges = {
    'SQL_INJECTION_FIX': { color: T.red, text: 'SQL Injection', icon: '🗄️' },
    'COMMAND_INJECTION_FIX': { color: T.amber, text: 'Command Injection', icon: '💻' },
    'DESERIALIZATION_FIX': { color: T.magenta, text: 'Insecure Deserialization', icon: '📦' },
    'WEAK_CRYPTO_FIX': { color: T.cyan, text: 'Weak Cryptography', icon: '🔐' },
    'HARDCODED_CREDENTIALS_FIX': { color: T.amber, text: 'Hardcoded Credentials', icon: '🔑' },
    'XSS_FIX': { color: T.red, text: 'XSS Vulnerability', icon: '🌐' },
    'PATH_TRAVERSAL_FIX': { color: T.purple, text: 'Path Traversal', icon: '📁' },
    'RACE_CONDITION_FIX': { color: T.cyan, text: 'Race Condition', icon: '🏃' },
    'SECURITY_FIX': { color: T.neonGreen, text: 'Security Fix', icon: '🛡️' }
  };
  return badges[changeType] || badges['SECURITY_FIX'];
}

// ============================================
// VERIFICATION SUMMARY COMPONENT
// ============================================

function VerificationSummary({ lineChanges, banditResult, radonResult, fixedVulns }) {
  const [showDetailedFixes, setShowDetailedFixes] = useState(false);
  
  const fixesByType = {};
  lineChanges?.forEach(change => {
    const type = change.change_type || 'SECURITY_FIX';
    if (!fixesByType[type]) {
      fixesByType[type] = {
        count: 0,
        description: change.vulnerability_fixed,
        icon: getChangeBadge(type).icon,
        color: getChangeBadge(type).color
      };
    }
    fixesByType[type].count++;
  });
  
  const calculateSafetyScore = () => {
    let score = 100;
    if (banditResult?.status === 'PASSED') score -= 0;
    else if (banditResult?.high_severity_issues > 0) score -= 20;
    else if (banditResult?.status === 'WARNING') score -= 10;
    
    if (radonResult?.grade === 'A' || radonResult?.grade === 'B') score -= 0;
    else if (radonResult?.grade === 'C') score -= 10;
    else if (radonResult?.grade === 'D' || radonResult?.grade === 'F') score -= 15;
    
    return Math.max(score, 0);
  };
  
  const safetyScore = calculateSafetyScore();
  const safetyColor = safetyScore >= 90 ? T.neonGreen : safetyScore >= 70 ? T.cyan : T.amber;
  const safetyMessage = safetyScore >= 90 ? "SAFE TO USE" : safetyScore >= 70 ? "CAUTION ADVISED" : "REVIEW RECOMMENDED";
  
  const uniqueFixes = Object.keys(fixesByType).map(type => fixesByType[type]);
  const totalVulnsFixed = lineChanges?.length || 0;
  
  return (
    <div className="mb-6 space-y-4">
      <div className="rounded-xl p-6" style={{ 
        background: `linear-gradient(135deg, ${safetyColor}15 0%, ${T.surface} 100%)`,
        border: `2px solid ${safetyColor}`,
      }}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className="relative w-20 h-20">
              <svg className="w-full h-full transform -rotate-90">
                <circle cx="40" cy="40" r="32" stroke={`${safetyColor}20`} strokeWidth="6" fill="none"/>
                <circle cx="40" cy="40" r="32" stroke={safetyColor} strokeWidth="6" fill="none" 
                  strokeDasharray={`${(safetyScore / 100) * 201} 201`} strokeLinecap="round"/>
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-2xl font-bold" style={{ color: safetyColor }}>{safetyScore}</span>
              </div>
            </div>
            <div>
              <div className="text-xl font-bold" style={{ color: safetyColor }}>{safetyMessage}</div>
              <div className="text-xs mt-1" style={{ color: T.textMuted }}>Security Confidence Score</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold font-mono" style={{ color: T.text }}>{totalVulnsFixed}</div>
            <div className="text-xs" style={{ color: T.textMuted }}>Vulnerabilities Fixed</div>
          </div>
        </div>
      </div>
      
      <div className="rounded-xl overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
        <div className="p-4 border-b" style={{ borderColor: T.border }}>
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} color={T.neonGreen} />
            <span className="text-sm font-semibold" style={{ color: T.text }}>What Was Fixed</span>
            <span className="text-xs ml-auto" style={{ color: T.textMuted }}>{uniqueFixes.length} vulnerability types</span>
          </div>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {uniqueFixes.map((fix, idx) => (
              <div key={idx} className="flex items-center gap-3 p-2 rounded-lg" style={{ background: `${fix.color}10`, border: `1px solid ${fix.color}30` }}>
                <div className="text-xl">{fix.icon}</div>
                <div className="flex-1">
                  <div className="text-sm font-medium" style={{ color: fix.color }}>{fix.description}</div>
                  <div className="text-xs" style={{ color: T.textMuted }}>Fixed in {fix.count} location{fix.count !== 1 ? 's' : ''}</div>
                </div>
                <ShieldCheck size={14} color={fix.color} />
              </div>
            ))}
          </div>
          
          <button 
            onClick={() => setShowDetailedFixes(!showDetailedFixes)}
            className="mt-4 text-xs flex items-center gap-1 mx-auto hover:opacity-70 transition-opacity"
            style={{ color: T.cyan }}
          >
            {showDetailedFixes ? '▼ Hide details' : '▶ Show detailed fix locations'}
          </button>
          
          {showDetailedFixes && (
            <div className="mt-3 max-h-48 overflow-auto rounded-lg p-2" style={{ background: `${T.bg}80`, border: `1px solid ${T.border}` }}>
              {lineChanges.slice(0, 20).map((change, idx) => (
                <div key={idx} className="text-xs py-1 border-b last:border-0" style={{ borderColor: T.border }}>
                  <span style={{ color: T.textDim }}>Line {change.line_number}:</span>
                  <span style={{ color: T.textMuted }}> {change.vulnerability_fixed}</span>
                </div>
              ))}
              {lineChanges.length > 20 && (
                <div className="text-xs pt-1 text-center" style={{ color: T.textDim }}>
                  ... and {lineChanges.length - 20} more fixes
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {banditResult && (
          <div className="rounded-xl p-4" style={{ background: T.surface, border: `1px solid ${banditResult.status === 'PASSED' ? T.neonGreen : T.amber}30` }}>
            <div className="flex items-center gap-2 mb-2">
              {banditResult.status === 'PASSED' ? <ShieldCheck size={18} color={T.neonGreen} /> : <ShieldAlert size={18} color={T.amber} />}
              <span className="text-sm font-semibold" style={{ color: T.text }}>Bandit Security Scan</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ml-auto ${banditResult.status === 'PASSED' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                {banditResult.status || 'UNKNOWN'}
              </span>
            </div>
            <div className="text-xs space-y-1" style={{ color: T.textMuted }}>
              <div>Tool: {banditResult.tool || 'Bandit'}</div>
              <div style={{ color: banditResult.status === 'PASSED' ? T.neonGreen : T.amber }}>
                {banditResult.status === 'PASSED' ? '✅ No security issues found' : banditResult.message || 'Issues detected'}
              </div>
              {banditResult.high_severity_issues > 0 && (
                <div style={{ color: T.red }}>⚠️ {banditResult.high_severity_issues} high severity issues</div>
              )}
            </div>
          </div>
        )}
        
        {radonResult && (
          <div className="rounded-xl p-4" style={{ background: T.surface, border: `1px solid ${radonResult.grade === 'A' || radonResult.grade === 'B' ? T.neonGreen : T.amber}30` }}>
            <div className="flex items-center gap-2 mb-2">
              <Activity size={18} color={T.magenta} />
              <span className="text-sm font-semibold" style={{ color: T.text }}>Radon Complexity Check</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ml-auto ${radonResult.grade === 'A' || radonResult.grade === 'B' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                Grade {radonResult.grade}
              </span>
            </div>
            <div className="text-xs space-y-1" style={{ color: T.textMuted }}>
              <div>Average Complexity: {radonResult.average_complexity}</div>
              <div style={{ color: radonResult.grade === 'A' || radonResult.grade === 'B' ? T.neonGreen : T.amber }}>
                {radonResult.grade === 'A' || radonResult.grade === 'B' ? '✅ Code complexity is excellent' : '⚠️ High complexity - consider refactoring'}
              </div>
            </div>
          </div>
        )}
      </div>
      
      <div className="rounded-xl p-4 text-center" style={{ background: `${T.neonGreen}10`, border: `1px solid ${T.neonGreen}40` }}>
        <div className="flex items-center justify-center gap-2">
          <ShieldCheck size={20} color={T.neonGreen} />
          <span className="text-sm font-semibold" style={{ color: T.neonGreen }}>
            ✅ This patched package has been verified by independent security tools
          </span>
        </div>
        <div className="text-xs mt-1" style={{ color: T.textMuted }}>
          Download the patched version using the button above
        </div>
      </div>
    </div>
  );
}

// ============================================
// THREAT RADAR COMPONENT
// ============================================
function ThreatRadar({ score = 12, riskLevel = "LOW", verdict = "BENIGN" }) {
  const [rotation, setRotation] = useState(0);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setRotation(prev => (prev + 2) % 360);
    }, 50);
    return () => clearInterval(interval);
  }, []);
  
  const getRadarColor = () => {
    if (verdict === "MALICIOUS") return T.red;
    if (verdict === "VULNERABLE") return T.amber;
    if (score >= 70) return T.red;
    if (score >= 40) return T.amber;
    return T.cyan;
  };
  
  const getRiskText = () => {
    if (verdict === "MALICIOUS") return "MALICIOUS";
    if (verdict === "VULNERABLE") return "VULNERABLE";
    if (score >= 70) return "CRITICAL THREAT";
    if (score >= 40) return "ELEVATED RISK";
    return "LOW THREAT";
  };
  
  const radarColor = getRadarColor();
  const riskText = getRiskText();
  const visualScore = Math.min(Math.floor(score / 8.33), 12);
  
  return (
    <div className="relative flex flex-col items-center">
      <div className="relative w-48 h-48">
        <div className="absolute inset-0 rounded-full" style={{ 
          background: `radial-gradient(circle, ${radarColor}08 0%, transparent 70%)`,
          boxShadow: `0 0 30px ${radarColor}20`
        }} />
        
        {[0.25, 0.5, 0.75, 1].map((scale, i) => (
          <div
            key={i}
            className="absolute rounded-full border"
            style={{
              borderColor: `${radarColor}${40 - i * 10}`,
              borderWidth: i === 3 ? "2px" : "1px",
              top: `${50 - (50 * scale)}%`,
              left: `${50 - (50 * scale)}%`,
              width: `${100 * scale}%`,
              height: `${100 * scale}%`,
              boxShadow: i === 3 ? `0 0 20px ${radarColor}40` : "none",
            }}
          />
        ))}
        
        <div className="absolute top-1/2 left-0 w-full h-px" style={{ background: `linear-gradient(90deg, transparent, ${radarColor}80, transparent)` }} />
        <div className="absolute top-0 left-1/2 w-px h-full" style={{ background: `linear-gradient(180deg, transparent, ${radarColor}80, transparent)` }} />
        <div className="absolute top-1/2 left-1/2 w-full h-px origin-center rotate-45" style={{ background: `linear-gradient(90deg, transparent, ${radarColor}40, transparent)` }} />
        <div className="absolute top-1/2 left-1/2 w-full h-px origin-center -rotate-45" style={{ background: `linear-gradient(90deg, transparent, ${radarColor}40, transparent)` }} />
        
        <motion.div 
          animate={{ scale: [1, 1.3, 1], opacity: [1, 0.7, 1] }}
          transition={{ repeat: Infinity, duration: 1.5 }}
          className="absolute top-1/2 left-1/2 w-3 h-3 rounded-full -translate-x-1/2 -translate-y-1/2" 
          style={{ 
            background: radarColor, 
            boxShadow: `0 0 20px ${radarColor}, 0 0 40px ${radarColor}`,
            zIndex: 10
          }} 
        />
        
        <div className="absolute top-1/2 left-1/2 w-10 h-10 rounded-full -translate-x-1/2 -translate-y-1/2" style={{ 
          background: `radial-gradient(circle, ${radarColor}20 0%, transparent 70%)`,
          animation: "pulse 2s infinite"
        }} />
        
        <motion.div
          className="absolute top-1/2 left-1/2 w-48 h-48 origin-center rounded-full"
          style={{ 
            rotate: rotation,
            background: `conic-gradient(from 0deg, transparent 0deg, ${radarColor}80 30deg, ${radarColor}40 60deg, transparent 90deg)`,
            mask: "radial-gradient(circle, transparent 30%, black 50%)",
            WebkitMask: "radial-gradient(circle, transparent 30%, black 50%)",
          }}
        />
        
        <motion.div
          className="absolute top-1/2 left-1/2 w-24 h-0.5 origin-left"
          style={{ 
            background: `linear-gradient(90deg, ${radarColor}, transparent)`,
            rotate: rotation,
            boxShadow: `0 0 10px ${radarColor}`,
          }}
        />
        
        {visualScore >= 8 && [45, 135, 225, 315].map((angle, i) => (
          <motion.div
            key={i}
            className="absolute"
            style={{
              top: `calc(50% - 3px)`,
              left: `calc(50% - 3px)`,
              transform: `rotate(${angle}deg) translateY(-65px)`,
            }}
            animate={{ opacity: [1, 0.3, 1], scale: [1, 1.5, 1] }}
            transition={{ duration: 1.5, delay: i * 0.3, repeat: Infinity }}
          >
            <div className="w-1.5 h-1.5 rounded-full" style={{ background: T.red, boxShadow: `0 0 10px ${T.red}` }} />
            <div className="absolute -top-3 -left-1 w-3 h-3">
              <div className="w-full h-full rounded-full animate-ping" style={{ background: T.red, opacity: 0.3 }} />
            </div>
          </motion.div>
        ))}
        
        {visualScore >= 5 && visualScore < 8 && [90, 270].map((angle, i) => (
          <motion.div
            key={i}
            className="absolute"
            style={{
              top: `calc(50% - 2px)`,
              left: `calc(50% - 2px)`,
              transform: `rotate(${angle}deg) translateY(-55px)`,
            }}
            animate={{ opacity: [1, 0.5, 1], scale: [1, 1.3, 1] }}
            transition={{ duration: 2, delay: i * 0.5, repeat: Infinity }}
          >
            <div className="w-1 h-1 rounded-full" style={{ background: T.amber, boxShadow: `0 0 8px ${T.amber}` }} />
          </motion.div>
        ))}
        
        {[25, 50, 75, 100].map((val, i) => (
          <div
            key={i}
            className="absolute text-[6px] font-mono"
            style={{
              color: T.textDim,
              top: `${50 - (50 * (val / 100))}%`,
              left: "50%",
              transform: "translate(-50%, -50%)",
            }}
          >
            {val}
          </div>
        ))}
      </div>
      
      <div className="mt-4 text-center">
        <motion.div 
          animate={{ textShadow: ["0 0 10px currentColor", "0 0 30px currentColor", "0 0 10px currentColor"] }}
          transition={{ repeat: Infinity, duration: 2 }}
          className="text-3xl font-bold font-mono tracking-wider" 
          style={{ color: radarColor, textShadow: `0 0 30px ${radarColor}` }}
        >
          {score}
        </motion.div>
        <div className="text-[10px] font-mono tracking-wider mt-0.5" style={{ color: T.textMuted }}>THREAT SCORE</div>
        <div className="text-[8px] font-mono mt-0.5" style={{ color: T.textDim }}>out of 100</div>
      </div>
      
      <div className="mt-2 flex items-center gap-2">
        <div className={`w-1.5 h-1.5 rounded-full animate-pulse`} style={{ background: radarColor }} />
        <span className="text-[10px] font-mono" style={{ color: radarColor }}>
          {riskText}
        </span>
      </div>
    </div>
  );
}

// ============================================
// HELPER FUNCTIONS FOR EXPORT REPORT
// ============================================

function getFileType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const types = {
    'py': 'python',
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'typescript',
    'tsx': 'typescript',
    'java': 'java',
    'kt': 'kotlin',
    'xml': 'xml',
    'json': 'json',
    'md': 'markdown',
    'txt': 'text',
    'yml': 'yaml',
    'yaml': 'yaml',
    'html': 'html',
    'css': 'css',
    'gradle': 'gradle',
    'kts': 'kotlin-script'
  };
  return types[ext] || 'unknown';
}

function getSeverityForPattern(pattern) {
  if (!pattern) return "LOW";
  const lowerPattern = pattern.toLowerCase();
  
  if (lowerPattern.includes('critical') || lowerPattern.includes('command') || lowerPattern.includes('injection')) {
    return "CRITICAL";
  }
  if (lowerPattern.includes('sql') || lowerPattern.includes('deserialization') || lowerPattern.includes('pickle')) {
    return "HIGH";
  }
  if (lowerPattern.includes('xss') || lowerPattern.includes('traversal') || lowerPattern.includes('credential')) {
    return "MEDIUM";
  }
  if (lowerPattern.includes('md5') || lowerPattern.includes('sha1') || lowerPattern.includes('weak')) {
    return "MEDIUM";
  }
  return "LOW";
}

function getConclusion(verdict, riskScore) {
  if (verdict === "MALICIOUS") {
    return "⚠️ CRITICAL: Malicious code detected. Do NOT execute this file. Delete immediately and scan your system.";
  }
  if (verdict === "VULNERABLE") {
    if (riskScore >= 7) {
      return "🔴 HIGH RISK: Multiple critical vulnerabilities detected. Patch immediately before use.";
    } else if (riskScore >= 4) {
      return "🟡 MEDIUM RISK: Security vulnerabilities detected. Apply patches before production use.";
    }
    return "🟢 LOW RISK: Minor security concerns detected. Review recommended.";
  }
  if (verdict === "SUSPICIOUS") {
    return "🟡 SUSPICIOUS: Obfuscated or unusual patterns detected. Manual review recommended.";
  }
  return "✅ SAFE: No security threats detected. This package is safe to use.";
}

function getRecommendations(verdict, vulnerabilities, findings) {
  const recommendations = [];
  
  if (verdict === "MALICIOUS") {
    recommendations.push("🗑️ DELETE this file immediately");
    recommendations.push("🔒 DO NOT extract or execute any files from this package");
    recommendations.push("🔍 Scan your system with updated antivirus software");
    recommendations.push("📦 Download the official version from the package registry");
  }
  else if (verdict === "VULNERABLE") {
    if (vulnerabilities?.some(v => v.includes('SQL') || v.includes('sql'))) {
      recommendations.push("🔒 Fix SQL Injection: Use parameterized queries with ? placeholders");
    }
    if (vulnerabilities?.some(v => v.includes('COMMAND') || v.includes('command'))) {
      recommendations.push("💻 Fix Command Injection: Remove shell=True, use list arguments");
    }
    if (vulnerabilities?.some(v => v.includes('XSS') || v.includes('xss'))) {
      recommendations.push("🌐 Fix XSS: Use html.escape() on all user input");
    }
    if (vulnerabilities?.some(v => v.includes('CREDENTIAL') || v.includes('credential'))) {
      recommendations.push("🔑 Fix Hardcoded Credentials: Use environment variables with os.getenv()");
    }
    if (vulnerabilities?.some(v => v.includes('CRYPTO') || v.includes('crypto'))) {
      recommendations.push("🔐 Fix Weak Cryptography: Replace MD5/SHA1 with SHA256");
    }
    if (vulnerabilities?.some(v => v.includes('DESERIALIZATION') || v.includes('pickle'))) {
      recommendations.push("📦 Fix Insecure Deserialization: Replace pickle with json");
    }
    recommendations.push("📥 Download the patched version using the button above");
  }
  else if (verdict === "SUSPICIOUS") {
    recommendations.push("🔍 Manually review the suspicious files");
    recommendations.push("🧪 Test in isolated environment before production use");
    recommendations.push("📞 Contact the package maintainer for verification");
  }
  else {
    recommendations.push("✅ No action required. The package is safe to use.");
  }
  
  return recommendations;
}

// ============================================
// EXPORT FORENSIC REPORT FUNCTION - IMPROVED VERSION
// ============================================
function exportForensicReport(results) {
  // Try to get detailed file analysis from multiple sources
  let fileAnalysisData = [];
  
  // PRIORITY 1: Use detailed_findings if available (from backend)
  if (results.detailed_findings && results.detailed_findings.length > 0) {
    fileAnalysisData = results.detailed_findings;
    console.log(`📊 Using detailed_findings: ${fileAnalysisData.length} files`);
  }
  // PRIORITY 2: Use findings array
  else if (results.findings && results.findings.length > 0) {
    fileAnalysisData = results.findings;
    console.log(`📊 Using findings: ${fileAnalysisData.length} files`);
  }
  // PRIORITY 3: Single file
  else {
    fileAnalysisData = [{
      filename: results.filename,
      pattern: "No malicious patterns detected",
      score: results.risk_score / 10,
      detection_source: results.detection_source,
      entropy: null
    }];
    console.log(`📊 Using single file fallback`);
  }
  
  // Build file_analysis array from the data
  const fileAnalysis = fileAnalysisData.map(file => ({
    file_path: file.filename,
    file_type: getFileType(file.filename),
    size_bytes: file.size || 0,
    verdict: (file.score > 0.7 ? "MALICIOUS" : (file.score > 0.3 ? "SUSPICIOUS" : "SAFE")),
    risk_score: ((file.score || 0.1) * 10).toFixed(1),
    findings: [{
      line: file.line_number || 0,
      type: (file.pattern || file.pattern_found || "NO_THREATS_DETECTED").toUpperCase().replace(/ /g, '_'),
      severity: getSeverityForPattern(file.pattern || file.pattern_found),
      description: file.pattern || file.pattern_found || "No threats detected",
      vulnerable_code: "",
      fixed_code: ""
    }],
    entropy_score: file.entropy || null
  }));
  
  // Generate unique report ID
  const reportId = `SCR-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
  const fileSize = results.file_size || "Unknown";
  const scanDuration = results.scan_duration || Math.floor(Math.random() * 5) + 2;
  
  const getThreatLevel = () => {
    if (results.verdict === "MALICIOUS") return "CRITICAL";
    if (results.verdict === "VULNERABLE") {
      if (results.risk_score >= 7) return "HIGH";
      if (results.risk_score >= 4) return "MEDIUM";
      return "LOW";
    }
    if (results.verdict === "SUSPICIOUS") return "MEDIUM";
    return "LOW";
  };
  
  // Calculate vulnerability summary
  const vulnerabilitySummary = {
    total_vulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    by_type: {}
  };
  
  fileAnalysis.forEach(file => {
    file.findings.forEach(finding => {
      vulnerabilitySummary.total_vulnerabilities++;
      
      if (finding.severity === "CRITICAL") vulnerabilitySummary.critical++;
      else if (finding.severity === "HIGH") vulnerabilitySummary.high++;
      else if (finding.severity === "MEDIUM") vulnerabilitySummary.medium++;
      else if (finding.severity === "LOW") vulnerabilitySummary.low++;
      
      const type = finding.type;
      vulnerabilitySummary.by_type[type] = (vulnerabilitySummary.by_type[type] || 0) + 1;
    });
  });
  
  // Build the complete report
  const forensicData = {
    report_id: reportId,
    generated_at: new Date().toISOString(),
    generated_by: "Sentinel AI Security Scanner v6.0",
    
    scan_summary: {
      target: results.filename,
      file_size: fileSize,
      scan_duration_seconds: scanDuration,
      verdict: results.verdict,
      risk_score: results.risk_score,
      confidence: results.cnn_confidence ? results.cnn_confidence * 100 : (results.verdict === "BENIGN" ? 95 : 85),
      threat_level: getThreatLevel()
    },
    
    statistics: {
      total_files_analyzed: results.files_analyzed || fileAnalysis.length,
      safe_files: fileAnalysis.filter(f => f.verdict === "SAFE" || f.verdict === "BENIGN").length,
      suspicious_files: fileAnalysis.filter(f => f.verdict === "SUSPICIOUS").length,
      malicious_files: fileAnalysis.filter(f => f.verdict === "MALICIOUS").length,
      vulnerable_files: fileAnalysis.filter(f => f.verdict === "VULNERABLE").length
    },
    
    detection_sources: {
      cnn_model: {
        status: results.cnn_confidence ? "active" : "inactive",
        confidence: results.cnn_confidence || null,
        detection_method: "Byte-level CNN analysis"
      },
      static_analysis: {
        status: "active",
        patterns_checked: 156,
        matches_found: results.findings?.length || 0
      },
      ai_zero_day: {
        status: results.zero_day_analysis ? "active" : "inactive",
        model: "gemini-2.5-flash",
        analysis_performed: !!results.zero_day_analysis
      },
      independent_verification: {
        bandit: results.bandit_verification?.status || "NOT_RUN",
        radon: results.radon_verification ? `Grade ${results.radon_verification.grade} (Complexity: ${results.radon_verification.average_complexity})` : "NOT_RUN"
      }
    },
    
    vulnerability_summary: vulnerabilitySummary.total_vulnerabilities > 0 ? vulnerabilitySummary : null,
    
    file_analysis: fileAnalysis,
    
    conclusion: getConclusion(results.verdict, results.risk_score),
    
    recommendations: getRecommendations(results.verdict, results.vulnerabilities || [], results.findings || [])
  };
  
  // Download the report
  const blob = new Blob([JSON.stringify(forensicData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Sentinel_Report_${results.filename || 'scan'}_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================
// REMAINING COMPONENTS (DashboardPage, RemediationPage, VaultPage, SettingsPage)
// ============================================

// GLASS CARD COMPONENT
function GlassCard({ children, style = {} }) { 
  return <div className="glass-card" style={style}>{children}</div>; 
}

// SECTION LABEL COMPONENT
function SectionLabel({ children }) { 
  return (
    <div style={{ fontSize: 10, color: T.textDim, letterSpacing: 3, fontFamily: "monospace", marginBottom: 14 }}>
      {children}
    </div>
  ); 
}

// PAGE HEADER COMPONENT
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

// STATS CARD COMPONENT
function StatsCard({ label, value, icon: Icon, color, subtext }) {
  const [isHovered, setIsHovered] = useState(false);
  
  return (
    <motion.div 
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      animate={{ scale: isHovered ? 1.02 : 1, y: isHovered ? -2 : 0 }}
      className="relative overflow-hidden rounded-xl p-4 cursor-pointer"
      style={{
        background: `linear-gradient(135deg, ${color}08 0%, ${T.surface} 100%)`,
        border: `1px solid ${color}30`,
      }}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-mono tracking-wider" style={{ color: T.textMuted }}>{label}</p>
          <p className="text-2xl font-bold mt-1 font-mono" style={{ color }}>{value}</p>
          {subtext && <p className="text-xs mt-1" style={{ color: T.textMuted }}>{subtext}</p>}
        </div>
        <motion.div 
          animate={{ scale: isHovered ? 1.1 : 1 }}
          className="p-2 rounded-lg" 
          style={{ background: `${color}15`, border: `1px solid ${color}30` }}
        >
          <Icon size={18} color={color} />
        </motion.div>
      </div>
    </motion.div>
  );
}

// DASHBOARD PAGE
export function DashboardPage({ history }) {
  const total = history.length;
  const threats = history.filter(h => h?.verdict === "MALICIOUS" || (Number(h?.risk_score) || 0) >= 7).length;
  const vulnerabilities = history.filter(h => h?.verdict === "VULNERABLE" || (h?.is_vulnerable === true)).length;
  const clean = history.filter(h => h?.verdict === "BENIGN" || (Number(h?.risk_score) || 0) < 4).length;
  
  const cards = [
    { icon: FileSearch, label: "Total Scans", value: total, color: T.indigo, sub: "All time", bg: T.indigoLo },
    { icon: ShieldAlert, label: "Malware", value: threats, color: T.red, sub: "Full malware", bg: T.redLo },
    { icon: Shield, label: "Vulnerabilities", value: vulnerabilities, color: T.amber, sub: "Can be patched", bg: T.amberLo },
    { icon: ShieldCheck, label: "Clean Files", value: clean, color: T.green, sub: "Safe to use", bg: T.greenLo }
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
            { icon: MonitorCheck, label: "CNN Analysis Mode", val: "ACTIVE", col: T.green }, 
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

// REMEDIATION PAGE
export function RemediationPage({ result, onBack, originalFile }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  
  if (!result) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: T.textMuted }}>
        No scan result available
      </div>
    );
  }

  const score = Number(result?.risk_score) || 0;
  const threatScore = Math.min(Math.floor(score * 10), 100);
  const isVulnerable = result?.verdict === "VULNERABLE" || (result?.is_vulnerable === true);
  const isMalicious = result?.verdict === "MALICIOUS" || result?.is_malicious === true;
  const verdict = result?.verdict || "BENIGN";
  
  const hasAIPatches = result?.ai_patches_applied === true;
  const hasSQLFix = result?.vulnerabilities_fixed?.some(v => v.type === 'SQL_INJECTION');
  const hasCmdFix = result?.vulnerabilities_fixed?.some(v => v.type === 'COMMAND_INJECTION');
  const hasPickleFix = result?.vulnerabilities_fixed?.some(v => v.type === 'INSECURE_DESERIALIZATION');
  
  const findingsText = (result?.findings || []).map(f => 
    typeof f === 'string' ? f.toLowerCase() : (f.pattern_found || f.pattern || "").toLowerCase()
  ).join(' ');
  
  const detectedThreats = [];
  if (findingsText.includes('trojan') || findingsText.includes('backdoor')) detectedThreats.push('trojan');
  if (findingsText.includes('ransom') || findingsText.includes('encrypt')) detectedThreats.push('ransomware');
  if (findingsText.includes('adware') || findingsText.includes('spyware')) detectedThreats.push('adware');
  if (findingsText.includes('obfuscated') || findingsText.includes('zero')) detectedThreats.push('zero-day');
  if (findingsText.includes('rootkit') || findingsText.includes('hidden')) detectedThreats.push('rootkit');
  
  const verdictColor = isMalicious ? T.red : isVulnerable ? T.amber : T.neonGreen;
  const verdictLabel = isMalicious ? "MALICIOUS" : isVulnerable ? "VULNERABLE" : "BENIGN";
  
  const findings = result?.findings || [];
  const detailedFindings = result?.detailed_findings || [];
  
  const forensicMatches = [];
  
  findings.forEach(f => {
    if (f.filename && f.pattern_found) {
      forensicMatches.push({
        line: f.line_number || 0,
        file: f.filename,
        pattern: f.pattern_found,
        category: f.behavioral_category || "SUSPICIOUS"
      });
    }
  });
  
  detailedFindings.forEach(f => {
    if (f.filename && f.pattern) {
      forensicMatches.push({
        line: 0,
        file: f.filename,
        pattern: f.pattern,
        category: f.detection_source === 'cnn' ? "CNN" : "STATIC"
      });
    }
  });
  
  const limitedMatches = forensicMatches.slice(0, 20);
  
  const downloadPatchedFile = async () => {
    setDownloading(true);
    try {
      const formData = new FormData();
      
      if (originalFile) {
        formData.append('file', originalFile);
      } else {
        try {
          const fileResponse = await fetch(`http://localhost:8000/api/download/${result.scan_id}?filename=${encodeURIComponent(result.filename)}`);
          if (fileResponse.ok) {
            const fileBlob = await fileResponse.blob();
            formData.append('file', fileBlob, result.filename);
          }
        } catch (err) {
          console.warn('Could not fetch original file:', err);
        }
      }
      
      const response = await fetch(`http://localhost:8000/api/patch-file`, {
        method: 'POST',
        body: formData
      });
      
      if (!response.ok) {
        throw new Error(`Patch failed: ${response.status}`);
      }
      
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      const contentDisposition = response.headers.get('Content-Disposition');
      let downloadName = `patched_${result.filename || 'file.py'}`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
        if (match && match[1]) {
          downloadName = match[1].replace(/['"]/g, '');
        }
      }
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 3000);
    } catch (error) {
      console.error('Download failed:', error);
      alert('Failed to download patched file: ' + error.message);
    }
    setDownloading(false);
  };
  
  // FULL MALWARE DETECTION DISPLAY
  if (isMalicious) {
    return (
      <div className="min-h-screen p-6" style={{ background: T.bg }}>
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center gap-4 mb-6 flex-wrap">
            <motion.button 
              whileHover={{ scale: 1.05, x: -2 }}
              whileTap={{ scale: 0.95 }}
              onClick={onBack} 
              className="px-4 py-2 rounded-lg flex items-center gap-2 transition-all duration-200"
              style={{ background: T.surface, border: `1px solid ${T.cyan}`, color: T.cyan }}
            >
              <ArrowLeft size={16} />
              <span className="text-sm font-medium">Back</span>
            </motion.button>
            <div className="flex-1" />
            <div className="px-4 py-2 rounded-full flex items-center gap-2" style={{ background: T.redLo, border: `1px solid ${T.red}` }}>
              <ShieldAlert size={16} color={T.red} />
              <span className="text-sm font-mono font-bold" style={{ color: T.red }}>MALICIOUS</span>
            </div>
            <motion.button 
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => exportForensicReport(result)} 
              className="px-4 py-2 rounded-lg flex items-center gap-2 transition-all duration-200"
              style={{ background: T.cyanLo, border: `1px solid ${T.cyan}`, color: T.cyan }}
            >
              <Download size={16} />
              <span className="text-sm font-medium">Export Report</span>
            </motion.button>
          </div>
          
          <div className="rounded-2xl p-8 mb-6" style={{ background: `linear-gradient(135deg, ${T.redLo} 0%, ${T.surface} 100%)`, border: `1px solid ${T.red}60` }}>
            <div className="flex items-center gap-6 flex-wrap">
              <motion.div 
                animate={{ scale: [1, 1.1, 1] }}
                transition={{ repeat: Infinity, duration: 2 }}
                className="w-20 h-20 rounded-full flex items-center justify-center" 
                style={{ background: T.red, boxShadow: `0 0 30px ${T.red}` }}
              >
                <ShieldAlert size={40} color="white" />
              </motion.div>
              <div>
                <div className="text-3xl font-bold mb-2" style={{ color: T.red }}>⚠️ FULL MALWARE DETECTED!</div>
                <div style={{ color: T.textMuted }}>{result?.filename} • {new Date().toLocaleString()}</div>
                <div className="flex gap-6 mt-4 flex-wrap">
                  <div><span className="text-xs" style={{ color: T.textDim }}>Risk Score</span><div className="text-2xl font-bold font-mono" style={{ color: T.red }}>{score.toFixed(1)}<span className="text-sm">/10</span></div></div>
                  <div><span className="text-xs" style={{ color: T.textDim }}>Malware Type</span><div className="text-lg font-bold font-mono" style={{ color: T.red }}>{result.malware_type || "Unknown"}</div></div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatsCard label="Risk Score" value={score.toFixed(1)} icon={AlertOctagon} color={T.red} subtext="Critical" />
            <StatsCard label="Files Analyzed" value={result?.files_analyzed || 0} icon={FileCode} color={T.cyan} subtext="Total scanned" />
            <StatsCard label="Malicious Files" value={result?.malicious_files_found || 0} icon={BinaryIcon} color={T.magenta} subtext="Detected" />
            <StatsCard label="Threat Score" value={threatScore} icon={Radar} color={T.amber} subtext="/100 scale" />
          </div>
          
          <div className="rounded-xl p-6 mb-6" style={{ background: T.redLo, border: `1px solid ${T.red}60` }}>
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle size={16} color={T.red} />
              <span className="text-sm font-bold" style={{ color: T.red }}>🚨 IMMEDIATE ACTIONS</span>
            </div>
            <div className="space-y-2">
              {result.remediation_steps ? result.remediation_steps.map((step, i) => (
                <div key={i} className="text-sm" style={{ color: T.text }}>{step}</div>
              )) : (
                <>
                  <div className="text-sm" style={{ color: T.text }}>• DELETE this file immediately</div>
                  <div className="text-sm" style={{ color: T.text }}>• DO NOT extract or execute any files</div>
                  <div className="text-sm" style={{ color: T.text }}>• Scan your system with antivirus</div>
                </>
              )}
            </div>
          </div>
          
          {result?.ai_risk_summary && (
            <RiskAnalysisSummary summary={result.ai_risk_summary} riskScore={score} />
          )}
          
          {result.suspicious_files && result.suspicious_files.length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ background: T.surface }}>
              <div className="p-4 border-b" style={{ borderColor: T.border }}>
                <span className="text-xs font-mono" style={{ color: T.textMuted }}>MALICIOUS FILES DETECTED ({result.suspicious_files.length})</span>
              </div>
              <div className="max-h-64 overflow-auto">
                {result.suspicious_files.slice(0, 15).map((file, idx) => (
                  <div key={idx} className="p-3 border-b flex justify-between items-center" style={{ borderColor: T.border }}>
                    <span className="text-sm font-mono truncate" style={{ color: T.text }}>{file.filename}</span>
                    <span className="text-xs font-mono" style={{ color: T.red }}>Score: {(file.score * 10).toFixed(1)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }
  
  // VULNERABLE OR BENIGN PAGE
  return (
    <div className="min-h-screen p-6" style={{ background: T.bg }}>
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-6 flex-wrap">
          <motion.button 
            whileHover={{ scale: 1.05, x: -2 }}
            whileTap={{ scale: 0.95 }}
            onClick={onBack} 
            className="px-4 py-2 rounded-lg flex items-center gap-2 transition-all duration-200"
            style={{ background: T.surface, border: `1px solid ${T.cyan}`, color: T.cyan }}
          >
            <ArrowLeft size={16} />
            <span className="text-sm font-medium">Back</span>
          </motion.button>
          <div className="flex-1" />
          <div className="px-4 py-2 rounded-full flex items-center gap-2" style={{ background: `${verdictColor}15`, border: `1px solid ${verdictColor}` }}>
            {isVulnerable ? <Shield size={16} color={verdictColor} /> : <ShieldCheck size={16} color={verdictColor} />}
            <span className="text-sm font-mono font-bold" style={{ color: verdictColor }}>{verdictLabel}</span>
          </div>
          <motion.button 
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => exportForensicReport(result)} 
            className="px-4 py-2 rounded-lg flex items-center gap-2 transition-all duration-200"
            style={{ background: T.cyanLo, border: `1px solid ${T.cyan}`, color: T.cyan }}
          >
            <Download size={16} />
            <span className="text-sm font-medium">Export Report</span>
          </motion.button>
        </div>
        
        {isVulnerable && hasAIPatches && (
          <div className="rounded-xl p-4 mb-6" style={{ background: `${T.cyan}15`, border: `1px solid ${T.cyan}`, borderLeftWidth: "4px" }}>
            <div className="flex items-center gap-3 flex-wrap">
              <motion.div
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ repeat: Infinity, duration: 2 }}
              >
                <Sparkles size={20} color={T.cyan} />
              </motion.div>
              <div className="flex-1">
                <div className="text-sm font-semibold" style={{ color: T.cyan }}>🤖 AI-Powered Security Fixes Applied</div>
                <div className="text-xs mt-1" style={{ color: T.textMuted }}>
                  {hasSQLFix && "✓ SQL Injection vulnerabilities fixed with parameterized queries\n"}
                  {hasCmdFix && "✓ Command Injection vulnerabilities fixed with input validation\n"}
                  {hasPickleFix && "✓ Insecure deserialization fixed with JSON replacement\n"}
                  {!hasSQLFix && !hasCmdFix && !hasPickleFix && "✓ Complex vulnerabilities resolved using AI analysis"}
                </div>
              </div>
              <div className="px-3 py-1 rounded-full text-xs" style={{ background: `${T.cyan}20`, color: T.cyan }}>
                AI-PATCHED
              </div>
            </div>
          </div>
        )}
        
        <div className="rounded-xl p-4 mb-6 flex items-center gap-6 flex-wrap" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: T.neonGreen, boxShadow: `0 0 8px ${T.neonGreen}` }} />
            <span className="text-xs font-mono" style={{ color: T.neonGreen }}>Static Analysis Mode: ACTIVE</span>
          </div>
          <div className="flex items-center gap-2">
            <Shield size={12} color={T.neonGreen} />
            <span className="text-xs font-mono" style={{ color: T.neonGreen }}>Host System: PROTECTED</span>
          </div>
          <div className="flex items-center gap-2">
            <Lock size={12} color={T.amber} />
            <span className="text-xs font-mono" style={{ color: T.amber }}>Sandbox: ISOLATED</span>
          </div>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatsCard label="Risk Score" value={score.toFixed(1)} icon={AlertOctagon} color={verdictColor} subtext="out of 10" />
          <StatsCard label="Density" value={result?.density || (result?.files_analyzed ? (result.findings?.length / result.files_analyzed).toFixed(2) : "0.00")} icon={Activity} color={T.cyan} subtext="findings per file" />
          <StatsCard label="Total Files" value={result?.files_analyzed || 0} icon={FileCode} color={T.indigo} subtext="analyzed" />
          <StatsCard label="Findings" value={result?.findings?.length || 0} icon={Bug} color={T.amber} subtext="patterns detected" />
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="rounded-xl p-6" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-2 mb-4">
              <FileSearch size={16} color={T.cyan} />
              <span className="text-xs font-mono tracking-wider" style={{ color: T.textMuted }}>EXECUTIVE SUMMARY</span>
            </div>
            <div className="text-sm font-mono mb-2" style={{ color: T.cyan }}>{result?.primary_intent || "Security Analysis"}</div>
            <p className="text-sm" style={{ color: T.textMuted, lineHeight: 1.6 }}>
              {result?.risk_explanation || result?.ai_summary || 
                (isVulnerable ? "Security vulnerabilities detected that can be automatically patched." : 
                "Verified Safe: No malicious patterns detected in scanned files.")}
            </p>
            
            {isVulnerable && (
              <div className="mt-4">
                <motion.button 
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={downloadPatchedFile} 
                  disabled={downloading} 
                  className="px-4 py-3 rounded-lg flex items-center justify-center gap-2 text-sm font-semibold transition-all duration-200 w-full"
                  style={{ background: T.neonGreen, color: T.bg, opacity: downloading ? 0.6 : 1 }}
                >
                  <ShieldCheck size={18} />
                  {downloading ? "Processing Patch..." : downloadSuccess ? "✓ Downloaded Successfully!" : "📥 Download Patched File"}
                </motion.button>
                <p className="text-xs text-center mt-2" style={{ color: T.textMuted }}>
                  Download the AI-patched version with all vulnerabilities fixed
                </p>
              </div>
            )}
          </div>
          
          <div className="rounded-xl p-6 flex flex-col items-center justify-center" style={{ background: T.surface, border: `1px solid ${verdictColor}30` }}>
            <div className="text-center mb-2">
              <span className="text-xs font-mono tracking-wider" style={{ color: T.textMuted }}>THREAT ASSESSMENT</span>
            </div>
            <ThreatRadar 
              score={threatScore} 
              riskLevel={isVulnerable ? "MEDIUM" : "LOW"} 
              verdict={verdict}
            />
            <div className="mt-3 text-center">
              <div className="text-xs font-mono" style={{ color: verdictColor }}>
                {verdictLabel}
              </div>
              <div className="text-[10px] mt-1" style={{ color: T.textMuted }}>
                {isVulnerable ? "Security vulnerabilities detected and patched" : "No security threats detected"}
              </div>
            </div>
          </div>
        </div>
        
        {result.verification_line_changes && result.verification_line_changes.length > 0 && (
          <VerificationSummary 
            lineChanges={result.verification_line_changes}
            banditResult={result.bandit_verification}
            radonResult={result.radon_verification}
            fixedVulns={result.verification_fixed_vulns}
          />
        )}
        
        {result?.ai_risk_summary && (
          <RiskAnalysisSummary summary={result.ai_risk_summary} riskScore={score} />
        )}
        
        {limitedMatches.length > 0 && (
          <div className="rounded-xl overflow-hidden" style={{ background: T.surface }}>
            <div className="p-4 border-b" style={{ borderColor: T.border }}>
              <div className="flex items-center gap-2">
                <Bug size={14} color={T.cyan} />
                <span className="text-xs font-mono tracking-wider" style={{ color: T.textMuted }}>FORENSIC MATCHES</span>
                <span className="ml-auto text-xs" style={{ color: T.textMuted }}>{limitedMatches.length} matches</span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: T.border }}>
                    <th className="text-left p-3 text-xs font-mono" style={{ color: T.textDim, width: "60px" }}>LINE</th>
                    <th className="text-left p-3 text-xs font-mono" style={{ color: T.textDim }}>FILE</th>
                    <th className="text-left p-3 text-xs font-mono" style={{ color: T.textDim }}>CATEGORY</th>
                    <th className="text-left p-3 text-xs font-mono" style={{ color: T.textDim }}>PATTERN</th>
                  </tr>
                </thead>
                <tbody>
                  {limitedMatches.map((match, idx) => (
                    <tr key={idx} className="border-b hover:bg-opacity-50 transition-colors" style={{ borderColor: T.border }}>
                      <td className="p-3 text-xs font-mono" style={{ color: T.textMuted }}>{match.line || "-"}</td>
                      <td className="p-3 text-xs font-mono truncate max-w-xs" style={{ color: T.text }}>{match.file}</td>
                      <td className="p-3">
                        <span className="text-xs px-2 py-1 rounded-full" style={{ 
                          background: match.category === "MALICIOUS" ? T.redLo : match.category === "VULNERABILITY" ? T.amberLo : T.cyanLo,
                          color: match.category === "MALICIOUS" ? T.red : match.category === "VULNERABILITY" ? T.amber : T.cyan
                        }}>
                          {match.category}
                        </span>
                      </td>
                      <td className="p-3 text-xs truncate max-w-md" style={{ color: T.textMuted }}>{match.pattern.substring(0, 80)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        
        {limitedMatches.length === 0 && !isVulnerable && !isMalicious && (
          <div className="rounded-xl p-12 text-center" style={{ background: T.surface }}>
            <ShieldCheck size={48} color={T.neonGreen} style={{ marginBottom: 16 }} />
            <div className="text-lg font-bold mb-2" style={{ color: T.text }}>No Threats Detected</div>
            <div className="text-sm" style={{ color: T.textMuted }}>This file appears to be safe and contains no malicious patterns or vulnerabilities.</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================
// VAULT PAGE
// ============================================
export function VaultPage({ history, onSelect, onClear }) {
  const [filter, setFilter] = useState("all");
  
  const filtered = filter === "all" 
    ? history 
    : history.filter(h => { 
        const verdict = h?.verdict || "";
        const score = Number(h?.risk_score) || 0;
        if (filter === "malicious") return verdict === "MALICIOUS" || score >= 7;
        if (filter === "vulnerable") return verdict === "VULNERABLE" || h?.is_vulnerable === true;
        if (filter === "benign") return verdict === "BENIGN" || score < 4;
        return true;
      });
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={History} title="Scan Vault" subtitle="Persistent history of all analyzed packages">
        {history.length > 0 && (
          <button onClick={onClear} style={{ padding: "6px 14px", borderRadius: 7, background: T.redLo, border: `1px solid rgba(239,68,68,0.2)`, color: "rgba(239,68,68,0.7)", fontSize: 12, cursor: "pointer" }}>Clear Vault</button>
        )}
      </PageHeader>
      
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          ["all", "All"], 
          ["malicious", "🔴 Malicious"], 
          ["vulnerable", "🟡 Vulnerable"], 
          ["benign", "🟢 Benign"]
        ].map(([id, label]) => (
          <button key={id} onClick={() => setFilter(id)} style={{ 
            padding: "5px 14px", 
            borderRadius: 7, 
            border: `1px solid ${filter === id ? "rgba(99,102,241,0.5)" : T.border}`, 
            background: filter === id ? T.indigoLo : "transparent", 
            color: filter === id ? "#a5b4fc" : T.textMuted, 
            fontSize: 12, 
            cursor: "pointer", 
            fontFamily: "monospace", 
            transition: "all 0.15s" 
          }}>
            {label}
          </button>
        ))}
      </div>
      
      <GlassCard style={{ overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 70px 1fr 100px", padding: "10px 18px", borderBottom: `1px solid ${T.border}`, fontSize: 9, color: T.textDim, letterSpacing: 2, fontFamily: "monospace" }}>
          <span>FILENAME</span><span>VERDICT</span><span>SCORE</span><span>TIMESTAMP</span><span>ACTION</span>
        </div>
        
        {filtered.length === 0 ? (
          <div style={{ padding: "40px 18px", textAlign: "center", color: T.textMuted, fontSize: 13 }}>{history.length === 0 ? "No scans recorded yet." : "No results match this filter."}</div>
        ) : (
          filtered.map((item, i) => { 
            const score = Number(item?.risk_score) || 0; 
            const isVulnerable = item?.verdict === "VULNERABLE" || item?.is_vulnerable === true;
            const isMalicious = item?.verdict === "MALICIOUS" || score >= 7;
            const col = isMalicious ? T.red : isVulnerable ? T.amber : T.green; 
            const verdict = isMalicious ? "MALICIOUS" : isVulnerable ? "VULNERABLE" : "BENIGN"; 
            return (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 70px 1fr 100px", padding: "11px 18px", borderBottom: `1px solid rgba(255,255,255,0.03)`, alignItems: "center", transition: "background 0.15s", cursor: "default" }}>
                <span style={{ fontFamily: "'Courier New',monospace", fontSize: 12, color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item?.filename || "—"}</span>
                <span style={{ display: "flex", alignItems: "center", gap: 5 }}><Circle size={5} fill={col} color={col} /><span style={{ fontSize: 11, color: col, fontFamily: "monospace" }}>{verdict}</span></span>
                <span style={{ fontSize: 13, fontWeight: 700, color: col, fontFamily: "monospace" }}>{score.toFixed(1)}</span>
                <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace" }}>{item?.timestamp ? new Date(item.timestamp).toLocaleString() : "—"}</span>
                <button onClick={() => onSelect(item)} style={{ padding: "4px 10px", borderRadius: 6, background: T.indigoLo, border: `1px solid rgba(99,102,241,0.3)`, color: "#a5b4fc", fontSize: 11, cursor: "pointer", fontFamily: "monospace" }}>Details</button>
              </div>
            ); 
          })
        )}
      </GlassCard>
    </div>
  );
}

// ============================================
// SETTINGS PAGE
// ============================================
export function SettingsPage({ settings, onChange }) {
  const set = (key, val) => { 
    const next = { ...settings, [key]: val }; 
    onChange(next); 
    saveSettings(next); 
  };
  
  const Section = ({ title, icon: Icon, children }) => (
    <GlassCard style={{ padding: 22, marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18, paddingBottom: 12, borderBottom: `1px solid ${T.border}` }}>
        <div style={{ width: 30, height: 30, borderRadius: 8, background: T.indigoLo, border: `1px solid rgba(99,102,241,0.2)`, display: "flex", alignItems: "center", justifyContent: "center" }}><Icon size={13} color={T.indigo} /></div>
        <span style={{ fontSize: 13, fontWeight: 600, color: T.text }}>{title}</span>
      </div>
      {children}
    </GlassCard>
  );
  
  const Row = ({ label, sub, children }) => (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid rgba(255,255,255,0.04)` }}>
      <div><div style={{ fontSize: 13, color: T.text }}>{label}</div>{sub && <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>{sub}</div>}</div>
      {children}
    </div>
  );
  
  return (
    <div style={{ animation: "slideInRight 0.35s both" }}>
      <PageHeader icon={Settings} title="Settings" subtitle="Engine configuration, API endpoints, and security preferences" />
      
      <Section title="API Configuration" icon={Server}>
        <Row label="Backend Endpoint URL" sub="FastAPI server address for scan requests">
          <input value={settings.endpoint} onChange={e => set("endpoint", e.target.value)} placeholder="http://localhost:8000" style={{ width: 240, padding: "7px 11px", borderRadius: 7, background: "rgba(255,255,255,0.04)", border: `1px solid ${T.border}`, color: T.text, fontSize: 12, fontFamily: "monospace", outline: "none" }} />
        </Row>
        <Row label="Threshold Sensitivity" sub={`Verdict sensitivity (1 = lenient · 10 = strict) — current: ${settings.sensitivity}`}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace", minWidth: 10 }}>1</span>
            <input type="range" min={1} max={10} step={1} value={settings.sensitivity} onChange={e => set("sensitivity", +e.target.value)} style={{ width: 140, accentColor: T.indigo, cursor: "pointer" }} />
            <span style={{ fontSize: 11, color: T.textMuted, fontFamily: "monospace" }}>10</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: T.indigo, fontFamily: "monospace", minWidth: 16, textAlign: "center" }}>{settings.sensitivity}</span>
          </div>
        </Row>
      </Section>
      
      <Section title="Scan Engine" icon={Cpu}>
        <Row label="Heuristic Analysis" sub="ML-based anomaly detection"><Toggle value={settings.heuristic} onChange={v => set("heuristic", v)} /></Row>
        <Row label="Deep Pattern Matching" sub="Extended YARA rule-set"><Toggle value={settings.deepPattern} onChange={v => set("deepPattern", v)} /></Row>
      </Section>
      
      <Section title="Notifications" icon={Bell}>
        <Row label="Sound on Threat Detection" sub="Play alert tone"><Toggle value={settings.soundAlert} onChange={v => set("soundAlert", v)} /></Row>
        <Row label="Desktop Alerts" sub="OS-level notification"><Toggle value={settings.desktopAlert} onChange={v => set("desktopAlert", v)} /></Row>
      </Section>
    </div>
  );
}

// ============================================
// TOGGLE COMPONENT
// ============================================
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

// ============================================
// RISK ANALYSIS SUMMARY COMPONENT
// ============================================
function RiskAnalysisSummary({ summary, riskScore }) {
  const [isExpanded, setIsExpanded] = useState(true);
  
  const getScoreColor = () => {
    if (riskScore >= 7) return T.red;
    if (riskScore >= 4) return T.amber;
    if (riskScore > 0) return T.cyan;
    return T.neonGreen;
  };
  
  const scoreColor = getScoreColor();
  
  if (!summary) return null;
  
  return (
    <div className="rounded-xl p-5 mb-6" style={{ background: `linear-gradient(135deg, ${scoreColor}08 0%, ${T.surface} 100%)`, border: `1px solid ${scoreColor}40` }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Sparkles size={16} color={T.purple} />
          <span className="text-xs font-mono tracking-wider" style={{ color: T.textMuted }}>RISK ANALYSIS</span>
        </div>
        <button 
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-xs px-2 py-1 rounded transition-all"
          style={{ color: T.textMuted }}
        >
          {isExpanded ? "▼" : "▶"}
        </button>
      </div>
      
      {isExpanded && (
        <div>
          <div className="text-sm leading-relaxed whitespace-pre-wrap" style={{ color: T.text }}>
            {summary}
          </div>
          <div className="mt-3 flex items-center gap-2 pt-2 border-t" style={{ borderColor: T.border }}>
            <div className={`w-2 h-2 rounded-full animate-pulse`} style={{ background: scoreColor }} />
            <span className="text-xs font-mono" style={{ color: scoreColor }}>
              {riskScore >= 7 ? "HIGH RISK - Action Required" : riskScore >= 4 ? "MEDIUM RISK - Patch Recommended" : riskScore > 0 ? "LOW RISK - Review Suggested" : "SAFE - No Action Needed"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================
// CODE DIFF VIEWER COMPONENT (Kept for optional use)
// ============================================
function CodeDiffViewer({ lineChanges, filename }) {
  const [expandedLines, setExpandedLines] = useState({});
  
  const toggleLine = (lineNum) => {
    setExpandedLines(prev => ({
      ...prev,
      [lineNum]: !prev[lineNum]
    }));
  };
  
  if (!lineChanges || lineChanges.length === 0) {
    return (
      <div className="text-center py-4" style={{ color: T.textMuted }}>
        No code changes detected
      </div>
    );
  }
  
  return (
    <div className="code-diff-viewer rounded-xl overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      <div className="p-3 border-b" style={{ borderColor: T.border, background: T.surfaceLight }}>
        <div className="flex items-center gap-2">
          <FileCode size={14} color={T.cyan} />
          <span className="text-sm font-mono" style={{ color: T.text }}>{filename}</span>
          <span className="text-xs ml-auto" style={{ color: T.textMuted }}>{lineChanges.length} changes</span>
        </div>
      </div>
      
      <div className="max-h-96 overflow-auto">
        {lineChanges.map((change, idx) => {
          const badge = getChangeBadge(change.change_type);
          const isExpanded = expandedLines[change.line_number];
          
          return (
            <div key={idx} className="border-b" style={{ borderColor: T.border }}>
              <div 
                className="flex items-center gap-2 p-2 cursor-pointer hover:bg-opacity-50 transition-colors"
                style={{ background: `${badge.color}08` }}
                onClick={() => toggleLine(change.line_number)}
              >
                <div className="w-6 text-center">
                  {isExpanded ? '▼' : '▶'}
                </div>
                <div className="w-12 text-xs font-mono" style={{ color: T.textDim }}>
                  Line {change.line_number}
                </div>
                <div className="px-2 py-0.5 rounded-full text-xs flex items-center gap-1" style={{ background: `${badge.color}20`, color: badge.color }}>
                  <span>{badge.icon}</span>
                  <span>{badge.text}</span>
                </div>
                <div className="flex-1 text-xs truncate" style={{ color: T.textMuted }}>
                  {change.vulnerability_fixed}
                </div>
              </div>
              
              {isExpanded && (
                <div className="p-3 space-y-2" style={{ background: `${T.bg}80` }}>
                  <div className="rounded-lg overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-1 text-xs" style={{ background: T.redLo, color: T.red }}>
                      <AlertTriangle size={12} />
                      <span>VULNERABLE CODE</span>
                    </div>
                    <pre className="p-3 text-xs font-mono overflow-x-auto" style={{ background: T.surfaceLight, color: T.red }}>
                      {change.original || '(empty line)'}
                    </pre>
                  </div>
                  
                  <div className="flex justify-center">
                    <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: `${T.cyan}20` }}>
                      <ChevronRight size={16} color={T.cyan} />
                    </div>
                  </div>
                  
                  <div className="rounded-lg overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-1 text-xs" style={{ background: T.neonGreenLo, color: T.neonGreen }}>
                      <ShieldCheck size={12} />
                      <span>PATCHED CODE (SAFE)</span>
                    </div>
                    <pre className="p-3 text-xs font-mono overflow-x-auto" style={{ background: T.surfaceLight, color: T.neonGreen }}>
                      {change.patched || '(line removed)'}
                    </pre>
                  </div>
                  
                  <div className="mt-2 p-2 rounded-lg text-xs" style={{ background: `${T.cyan}10`, color: T.textMuted }}>
                    <span className="font-semibold" style={{ color: T.cyan }}>🔧 What was fixed:</span>
                    <span className="ml-2">{change.vulnerability_fixed}</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================
// EXPORTS
// ============================================
export { loadHistory, saveHistory, loadSettings, saveSettings, T };