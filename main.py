import os
import sys
import uuid
import shutil
import asyncio
import logging
import glob
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from collections import defaultdict
import time
import numpy as np

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(__file__))

from backend_ml.inference.zip_scanner import ZipExtractor, extract_files_for_cnn_smart, extract_binary_files
from cnn_detector import CNNMalwareDetector
from zero_day_detector import ZeroDayDetector
from vulnerability_patcher import VulnerabilityPatcher
from ai_engine import SmartMalwareAnalyzer

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger("sentinel")

app = FastAPI(title="Sentinel AI Backend - CNN Only", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = "temp_scans"
MODELS_DIR = "models"

os.makedirs(MODELS_DIR, exist_ok=True)

# Initialize CNN Detector
cnn_detector = None
try:
    model_paths = [
        os.path.join(MODELS_DIR, 'simple_model_final.h5'),
        os.path.join(MODELS_DIR, 'final_malware_cnn.h5'),
        'simple_model_final.h5',
        'models/simple_model_final.h5'
    ]
    
    model_path = None
    for path in model_paths:
        if os.path.exists(path):
            model_path = path
            break
    
    if model_path:
        cnn_detector = CNNMalwareDetector(model_path=model_path)
        logger.info(f"✅ CNN Malware Detector initialized successfully from {model_path}")
    else:
        logger.warning(f"⚠️ CNN model not found. CNN detection disabled.")
        cnn_detector = CNNMalwareDetector()
except Exception as e:
    logger.error(f"⚠️ CNN Detector initialization failed: {e}")
    cnn_detector = CNNMalwareDetector()

# Initialize Zero-Day Detector (Gemini for zero-day only)
zero_day_detector = None
try:
    api_key = os.getenv('GEMINI_API_KEY')
    if api_key:
        zero_day_detector = ZeroDayDetector(api_key=api_key)
        logger.info("✅ Zero-Day Detector initialized (Gemini for zero-day only)")
    else:
        logger.warning("⚠️ GEMINI_API_KEY not found. Zero-day detection disabled.")
except Exception as e:
    logger.error(f"Failed to initialize Zero-Day Detector: {e}")

# ============================================
# Initialize Vulnerability Patcher with GROQ (preferred) or Gemini
# ============================================
groq_api_key = os.getenv('GROQ_API_KEY')
gemini_api_key = os.getenv('GEMINI_API_KEY')

try:
    if groq_api_key:
        patcher = VulnerabilityPatcher(groq_api_key=groq_api_key)
        logger.info("✅ Vulnerability Patcher initialized with GROQ AI (faster, more reliable)")
    elif gemini_api_key:
        patcher = VulnerabilityPatcher(gemini_api_key=gemini_api_key)
        logger.info("⚠️ Vulnerability Patcher initialized with Gemini AI (fallback)")
    else:
        patcher = VulnerabilityPatcher()
        logger.info("⚠️ Vulnerability Patcher initialized in rule-based mode (no AI)")
except Exception as e:
    logger.error(f"⚠️ Vulnerability Patcher initialization failed: {e}")
    patcher = VulnerabilityPatcher()

# ============================================
# Initialize AI Analyzer for Git Hook
# ============================================
_ai_analyzer = None

def get_ai_analyzer():
    global _ai_analyzer
    if _ai_analyzer is None:
        try:
            _ai_analyzer = SmartMalwareAnalyzer()
            logger.info("✅ AI Analyzer (Gemini) initialized for Git hook")
        except Exception as e:
            logger.error(f"❌ Failed to initialize AI analyzer: {e}")
            _ai_analyzer = None
    return _ai_analyzer

# Models
class Finding(BaseModel):
    filename: str
    line_number: Optional[int] = 0
    pattern_found: str
    calculated_risk: float
    behavioral_category: str
    reasoning: str

class DetailedFinding(BaseModel):
    filename: str
    pattern: str
    score: float
    detection_source: str
    reasoning: str
    entropy: Optional[float] = None

class ZeroDayAnalysis(BaseModel):
    is_malicious: bool
    confidence: float
    reasoning: str
    malware_type: Optional[str] = None
    risk_level: str
    source: str
    gemini_confidence: Optional[float] = None

class VulnerabilityFixed(BaseModel):
    type: str
    description: str
    file: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None

class LineChange(BaseModel):
    line_number: int
    original: str
    patched: str
    change_type: str
    vulnerability_fixed: str

class VerificationDetails(BaseModel):
    tool: str
    status: str
    message: Optional[str] = None
    grade: Optional[str] = None
    average_complexity: Optional[float] = None
    high_severity_issues: Optional[int] = None
    medium_severity_issues: Optional[int] = None

class ScanResult(BaseModel):
    filename: str
    status: str
    verdict: str
    risk_score: float
    primary_intent: str
    findings: List[Finding]
    ai_summary: Optional[str] = None
    timestamp: str = datetime.now().isoformat()
    is_ai_verified: bool = True
    cnn_confidence: Optional[float] = None
    detection_source: Optional[str] = None
    files_analyzed: Optional[int] = None
    malicious_files_found: Optional[int] = None
    detailed_findings: Optional[List[DetailedFinding]] = None
    risk_explanation: Optional[str] = None
    detection_details: Optional[str] = None
    zero_day_analysis: Optional[ZeroDayAnalysis] = None
    # Patching fields
    safe_zip_available: Optional[bool] = False
    safe_zip_path: Optional[str] = None
    patched_files_count: Optional[int] = 0
    patched_files_list: Optional[List[str]] = None
    vulnerabilities_fixed: Optional[List[VulnerabilityFixed]] = None
    ai_patches_applied: Optional[bool] = False
    # Full malware fields
    malware_type: Optional[str] = None
    safe_alternative: Optional[str] = None
    install_command: Optional[str] = None
    remediation_steps: Optional[List[str]] = None
    malware_explanations: Optional[List[str]] = None
    action: Optional[str] = None
    # Add scan_id for download
    scan_id: Optional[str] = None
    # AI Risk Summary
    ai_risk_summary: Optional[str] = None
    # Verification fields
    verification_line_changes: Optional[List[LineChange]] = None
    verification_fixed_vulns: Optional[List[Dict]] = None
    bandit_verification: Optional[VerificationDetails] = None
    radon_verification: Optional[VerificationDetails] = None
    verification_status: Optional[str] = None

# ============================================
# REQUEST MODEL FOR GIT HOOK ENDPOINT
# ============================================
class ScanFileRequest(BaseModel):
    filename: str
    content: str

def generate_risk_explanation(cnn_result: dict, risk_score: float, zero_day_result=None) -> str:
    if not cnn_result:
        return "Analysis completed - no results available."
    
    is_malicious = cnn_result.get('is_malicious', False)
    is_vulnerable = cnn_result.get('is_vulnerable', False)
    confidence = cnn_result.get('confidence', 0)
    files_analyzed = cnn_result.get('files_analyzed', 0)
    malicious_files = cnn_result.get('malicious_files', 0)
    detection_source = cnn_result.get('detection_source', 'unknown')
    
    if zero_day_result and zero_day_result.get('source') == 'gemini_ai':
        explanation = f"⚠️ ZERO-DAY THREAT DETECTED! Risk Score: {risk_score:.1f}/10. "
        explanation += f"AI Analysis: {zero_day_result.get('reasoning', '')} "
        explanation += f"Confidence: {zero_day_result.get('confidence', 0):.1%}."
        return explanation
    
    if is_malicious:
        explanation = f"⚠️ FULL MALWARE DETECTED! Risk Score: {risk_score:.1f}/10. "
        explanation += f"Detection via {detection_source}. "
        explanation += f"Confidence: {confidence:.1%}. "
        explanation += f"Found {malicious_files} malicious files out of {files_analyzed} analyzed."
        
        findings_list = cnn_result.get('findings', [])
        if findings_list:
            explanation += f" Indicators: {', '.join(findings_list[:3])}"
    
    elif is_vulnerable:
        explanation = f"🟡 VULNERABILITIES DETECTED! Risk Score: {risk_score:.1f}/10. "
        explanation += f"These are security vulnerabilities that CAN BE PATCHED. "
        explanation += f"Found {len(cnn_result.get('vulnerabilities', []))} vulnerability types."
    
    else:
        explanation = f"✅ BENIGN - Risk Score: {risk_score:.1f}/10. "
        explanation += f"Analysis of {files_analyzed} files completed. "
        explanation += f"Confidence: {confidence:.1%}. "
        
        all_patterns = cnn_result.get('all_patterns', [])
        if all_patterns:
            max_score = max([p.get('score', 0) for p in all_patterns], default=0)
            explanation += f"Highest detected score: {max_score:.4f} (below 0.5 threshold). "
        else:
            explanation += f"No suspicious patterns detected. "
    
    return explanation

def generate_detection_details(cnn_result: dict, zero_day_result=None) -> str:
    if not cnn_result:
        return "Analysis completed."
    
    if zero_day_result and zero_day_result.get('source') == 'gemini_ai':
        return f"Zero-day detection using Gemini AI. CNN score: {zero_day_result.get('original_cnn_score', 0):.2f} → AI analysis: {zero_day_result.get('reasoning', '')[:100]}"
    
    detection_source = cnn_result.get('detection_source', 'unknown')
    files_analyzed = cnn_result.get('files_analyzed', 0)
    malicious_files = cnn_result.get('malicious_files', 0)
    is_malicious = cnn_result.get('is_malicious', False)
    is_vulnerable = cnn_result.get('is_vulnerable', False)
    
    if is_malicious:
        details = f"⚠️ FULL MALWARE detected via {detection_source}. "
        details += f"Found {malicious_files} files with malicious patterns out of {files_analyzed} analyzed. "
        details += f"Confidence: {cnn_result.get('confidence', 0):.1%}."
    elif is_vulnerable:
        vulnerabilities = cnn_result.get('vulnerabilities', [])
        details = f"🟡 VULNERABILITIES detected via {detection_source}. "
        details += f"Found {len(vulnerabilities)} vulnerability types: {', '.join(vulnerabilities[:3])}. "
        details += f"These can be automatically patched."
    else:
        details = f"Analysis completed on {files_analyzed} files. "
        details += f"Verdict: BENIGN. All files appear safe."
    
    return details

# ============================================
# FULL MALWARE REMEDIATION FUNCTIONS
# ============================================

def get_malware_type_from_findings(findings):
    findings_lower = [f.lower() for f in findings]
    
    malware_patterns = {
        'ransomware': ['ransomware', 'encrypt', 'decrypt', 'ransom', 'cryptolocker', 'wannacry'],
        'trojan': ['trojan', 'backdoor', 'remote access', 'rat'],
        'worm': ['worm', 'self-replicate', 'spread'],
        'cryptominer': ['miner', 'cryptominer', 'stratum', 'mining pool'],
        'keylogger': ['keylogger', 'keylog', 'key stroke'],
        'credential_stealer': ['credential', 'steal', 'exfil', '.env', 'password'],
        'rootkit': ['rootkit', 'hidden', 'stealth'],
        'botnet': ['botnet', 'c2', 'command and control', 'irc'],
        'infostealer': ['infostealer', 'data theft', 'exfiltration'],
    }
    
    for malware_type, patterns in malware_patterns.items():
        for pattern in patterns:
            if any(pattern in f for f in findings_lower):
                return malware_type.replace('_', ' ').title()
    
    return "Unknown Malware"

def get_malware_explanation(findings):
    explanations = []
    findings_lower = [f.lower() for f in findings]
    
    if any('credential' in f for f in findings_lower):
        explanations.append("• Contains credential stealing code")
    if any('c2' in f or 'command' in f for f in findings_lower):
        explanations.append("• Attempts to contact C2 server")
    if any('obfuscate' in f or 'packed' in f for f in findings_lower):
        explanations.append("• Uses obfuscation to hide payload")
    if any('exec' in f or 'shell' in f for f in findings_lower):
        explanations.append("• Executes arbitrary commands")
    if any('network' in f or 'http' in f for f in findings_lower):
        explanations.append("• Makes unauthorized network connections")
    if any('persistence' in f for f in findings_lower):
        explanations.append("• Installs persistence mechanisms")
    if any('encrypt' in f for f in findings_lower):
        explanations.append("• Encrypts files (ransomware behavior)")
    if any('keylog' in f for f in findings_lower):
        explanations.append("• Logs keystrokes (keylogger)")
    
    if not explanations:
        explanations.append("• Contains malicious patterns")
    
    return explanations

def get_safe_alternative_command(filename):
    safe_alternatives = {
        'react-dome': ('react', 'npm install react'),
        'babel-c0re': ('babel-core', 'npm install babel-core'),
        'axios-fix': ('axios', 'npm install axios'),
        'lodash-utility': ('lodash', 'npm install lodash'),
        'request-fix': ('request', 'npm install request'),
        'express-fix': ('express', 'npm install express'),
        'mongoose-fix': ('mongoose', 'npm install mongoose'),
        'jsonwebtoken-fix': ('jsonwebtoken', 'npm install jsonwebtoken'),
        'passport-fix': ('passport', 'npm install passport'),
        'requests-fix': ('requests', 'pip install requests'),
        'flask-fix': ('flask', 'pip install flask'),
        'django-fix': ('django', 'pip install django'),
        'numpy-fix': ('numpy', 'pip install numpy'),
        'pandas-fix': ('pandas', 'pip install pandas'),
    }
    
    filename_lower = filename.lower()
    for malicious_name, (safe_name, command) in safe_alternatives.items():
        if malicious_name in filename_lower:
            return safe_name, command
    
    if filename.endswith('.py'):
        return "the official package", "pip install <package_name>"
    elif filename.endswith('.js') or filename.endswith('.zip'):
        return "the official package", "npm install <package_name>"
    else:
        return "the official package", "Download from official source"

def get_remediation_steps(score, findings, filename):
    malware_type = get_malware_type_from_findings(findings)
    explanations = get_malware_explanation(findings)
    safe_name, install_command = get_safe_alternative_command(filename)
    
    steps = [
        "🗑️ DELETE this file immediately",
        "🔒 DO NOT extract or execute any files from this package",
        f"🛡️ {malware_type} detected - can infect your system",
        "🔍 Scan your system with updated antivirus software"
    ]
    
    if safe_name:
        steps.append(f"📦 Use {safe_name} from official registry instead: `{install_command}`")
    else:
        steps.append("📦 Download the official version from the package registry")
    
    return {
        'malware_type': malware_type,
        'explanations': explanations,
        'steps': steps,
        'safe_alternative': safe_name,
        'install_command': install_command
    }

def get_safe_alternative(filename):
    safe_alternatives = {
        'react-dome': 'react',
        'babel-c0re': 'babel-core',
        'axios-fix': 'axios',
        'lodash-utility': 'lodash',
        'request-fix': 'request',
        'express-fix': 'express',
        'mongoose-fix': 'mongoose',
        'jwt-fix': 'jsonwebtoken',
        'passport-fix': 'passport',
        'socket-fix': 'socket.io'
    }
    
    filename_lower = filename.lower()
    for malicious_name, safe_name in safe_alternatives.items():
        if malicious_name in filename_lower:
            return safe_name
    return None

def purge_system_cache():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TEMP_DIR)
    logger.info("Cache purged.")

@app.on_event("startup")
async def startup_event():
    purge_system_cache()

# ============================================
# ENDPOINT FOR GIT HOOK - WITH AI ENGINE INTEGRATION
# ============================================

@app.post("/api/scan/single")
async def scan_single_file(request: ScanFileRequest):
    """
    ENDPOINT for Git hook integration.
    Uses Gemini AI for accurate malware detection.
    """
    try:
        content = request.content
        filename = request.filename
        
        is_malicious = False
        score = 0.1
        reason = "No issues detected"
        
        # Step 1: Extract suspicious patterns from the file
        patterns = []
        
        # Define malicious patterns
        malicious_check_patterns = {
            'eval(atob': {'desc': 'Base64 encoded eval() malware', 'score': 0.85},
            'eval(': {'desc': 'Eval() execution', 'score': 0.70},
            'child_process.exec': {'desc': 'Command injection', 'score': 0.90},
            'exec(`': {'desc': 'Command execution', 'score': 0.85},
            'PASSWORD = ': {'desc': 'Hardcoded credentials', 'score': 0.75},
            'API_KEY = ': {'desc': 'Hardcoded API key', 'score': 0.75},
            'document.write': {'desc': 'XSS vulnerability', 'score': 0.80},
            'rm -rf': {'desc': 'Dangerous command', 'score': 0.95},
            'CryptoMiner': {'desc': 'Cryptominer detected', 'score': 0.85},
            'pickle.loads': {'desc': 'Insecure deserialization', 'score': 0.80},
            'innerHTML': {'desc': 'XSS risk', 'score': 0.60},
            'require("child_process")': {'desc': 'Command execution capability', 'score': 0.85},
            'execSync': {'desc': 'Synchronous command execution', 'score': 0.85},
            'spawn': {'desc': 'Process spawning', 'score': 0.70},
        }
        
        max_pattern_score = 0.1
        reason_found = None
        
        # Check for patterns
        for pattern, info in malicious_check_patterns.items():
            if pattern in content:
                max_pattern_score = max(max_pattern_score, info['score'])
                reason_found = info['desc']
                patterns.append({
                    'filename': filename,
                    'pattern_text': info['desc'],
                    'score': info['score']
                })
        
        # Also check line by line for suspicious code
        lines = content.split('\n')
        for line_num, line in enumerate(lines):
            line_lower = line.lower()
            suspicious_keywords = ['eval', 'exec', 'password', 'api_key', 'secret', 'child_process', 'rm -rf']
            for keyword in suspicious_keywords:
                if keyword in line_lower and len(line.strip()) > 10:
                    patterns.append({
                        'filename': filename,
                        'pattern_text': line.strip()[:200],
                        'score': 0.75 if keyword in ['eval', 'exec'] else 0.60
                    })
                    break
        
        # Step 2: Use AI for intelligent analysis if patterns found
        if patterns:
            try:
                ai_analyzer = get_ai_analyzer()
                if ai_analyzer:
                    logger.info(f"🤖 AI analyzing {len(patterns)} patterns for {filename}")
                    ai_result = ai_analyzer.analyze_patterns(patterns)
                    
                    is_malicious = ai_result.get('verdict') == 'MALICIOUS'
                    score = ai_result.get('risk_score', max_pattern_score * 10) / 10
                    reason = ai_result.get('summary', reason_found or "Suspicious patterns detected")
                    
                    logger.info(f"🤖 AI Result: {ai_result.get('verdict')} (score={score})")
                else:
                    # Fallback to pattern matching
                    is_malicious = max_pattern_score > 0.6
                    score = max_pattern_score
                    reason = reason_found or "Suspicious patterns detected (AI unavailable)"
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                # Fallback to simple detection
                is_malicious = max_pattern_score > 0.6
                score = max_pattern_score
                reason = reason_found or f"Pattern detected (AI error: {str(e)[:50]})"
        else:
            is_malicious = False
            score = 0.1
            reason = "No suspicious patterns detected"
        
        return {
            "is_malicious": is_malicious,
            "score": round(score, 2),
            "reason": reason
        }
        
    except Exception as e:
        logger.error(f"Single file scan failed: {e}")
        # Return safe by default to not block developer workflow
        return {
            "is_malicious": False,
            "score": 0.1,
            "reason": f"Scan error: {str(e)[:100]}"
        }

# ============================================
# ENDPOINT: Patch Single File
# ============================================
@app.post("/api/patch-file")
async def patch_single_file(file: UploadFile = File(...)):
    """Patch a single Python file and return the patched version"""
    scan_id = hashlib.md5(f"{file.filename}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
    
    try:
        content = await file.read()
        
        # Use same patcher (already initialized with Groq/Gemini)
        patched_content, changes, was_patched = patcher.patch_file(content, file.filename)
        
        if was_patched:
            return Response(
                content=patched_content,
                media_type="text/x-python",
                headers={
                    "Content-Disposition": f"attachment; filename=patched_{file.filename}",
                    "X-Patched-Vulnerabilities": str(len(changes)),
                    "X-AI-Patches-Applied": str(any('AI-powered' in c.get('description', '') for c in changes))
                }
            )
        else:
            return Response(
                content=content,
                media_type="text/x-python",
                headers={"Content-Disposition": f"attachment; filename={file.filename}"}
            )
            
    except Exception as e:
        logger.error(f"Single file patching failed: {e}")
        raise HTTPException(status_code=500, detail=f"Patching failed: {str(e)}")

# ============================================
# SCAN ENDPOINT (EXISTING - UNCHANGED)
# ============================================
@app.post("/api/scan", response_model=ScanResult)
async def perform_scan(file: UploadFile = File(...)):
    scan_id = hashlib.md5(f"{file.filename}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]
    file_location = os.path.join(TEMP_DIR, f"{scan_id}_{file.filename}")
    safe_zip_path = None
    
    try:
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f"[SMART SCAN] Processing {file.filename}")

        try:
            files_for_cnn = extract_files_for_cnn_smart(
                open(file_location, 'rb').read(),
                file.filename
            )
        except ImportError:
            from backend_ml.inference.zip_scanner import extract_files_for_cnn
            files_for_cnn = extract_files_for_cnn(
                open(file_location, 'rb').read(),
                file.filename
            )
        
        if not files_for_cnn:
            return ScanResult(
                filename=file.filename,
                status="success",
                verdict="BENIGN",
                risk_score=0.0,
                primary_intent="CNN Analysis Only",
                findings=[],
                ai_summary="No analyzable files found in the package.",
                is_ai_verified=False,
                cnn_confidence=None,
                detection_source=None,
                files_analyzed=0,
                malicious_files_found=0,
                detailed_findings=[],
                risk_explanation="No analyzable files found.",
                detection_details="No files with supported extensions.",
                safe_zip_available=False,
                action="SAFE",
                scan_id=scan_id,
                ai_risk_summary=None,
                verification_line_changes=None,
                verification_fixed_vulns=None,
                bandit_verification=None,
                radon_verification=None,
                verification_status=None
            )

        logger.info(f"📦 Extracted {len(files_for_cnn)} files for CNN analysis")

        cnn_result = None
        final_verdict = "BENIGN"
        risk_score = 0.0
        zero_day_result = None
        safe_zip_available = False
        patched_files_count = 0
        patched_files_list = []
        vulnerabilities_fixed = []
        ai_patches_applied = False
        ai_risk_summary = None
        
        verification_line_changes = []
        verification_fixed_vulns = []
        bandit_verification = None
        radon_verification = None
        verification_status = None
        
        if cnn_detector and files_for_cnn:
            try:
                logger.info(f"🤖 Running CNN analysis on {len(files_for_cnn)} files...")
                cnn_result = cnn_detector.predict_package(files_for_cnn)
                logger.info(f"🤖 CNN Prediction: {cnn_result}")
                
                if cnn_result:
                    is_malicious = cnn_result.get('is_malicious', False)
                    is_vulnerable = cnn_result.get('is_vulnerable', False)
                    cnn_score = cnn_result.get('raw_score', 0.5)
                    risk_score = cnn_score * 10
                    detection_source = cnn_result.get('detection_source', 'unknown')
                    findings_list = cnn_result.get('findings', [])
                    vulnerabilities_list = cnn_result.get('vulnerabilities', [])
                    malicious_count = cnn_result.get('malicious_files', 0)
                    total_files = cnn_result.get('files_analyzed', 0)
                    
                    # Build detailed_findings from all_patterns
                    detailed_findings = []
                    all_patterns = cnn_result.get('all_patterns', [])
                    
                    for pattern_info in all_patterns:
                        filename = pattern_info.get('filename', 'unknown')
                        findings_list_for_file = pattern_info.get('findings', [])
                        score = pattern_info.get('score', 0)
                        detection_source_file = pattern_info.get('detection_source', 'unknown')
                        entropy = pattern_info.get('entropy')
                        
                        if findings_list_for_file:
                            pattern_text = ', '.join(findings_list_for_file)
                        else:
                            pattern_text = "No malicious patterns detected"
                        
                        detailed_findings.append(DetailedFinding(
                            filename=filename,
                            pattern=pattern_text,
                            score=score,
                            detection_source=detection_source_file,
                            reasoning=f"Found {len(findings_list_for_file)} indicators" if findings_list_for_file else "No suspicious patterns detected",
                            entropy=entropy
                        ))
                    
                    logger.info(f"📊 Built detailed_findings for {len(detailed_findings)} files")
                    
                    # CASE 1: FULL MALWARE
                    if is_malicious:
                        logger.info(f"🔴 REAL MALWARE DETECTED! Score: {cnn_score:.2f}")
                        
                        remediation = get_remediation_steps(cnn_score, findings_list, file.filename)
                        
                        ai_summary = f"⚠️ FULL MALWARE DETECTED! Type: {remediation['malware_type']}. "
                        ai_summary += f"Risk Score: {risk_score:.1f}/10. "
                        ai_summary += f"Found {malicious_count} malicious files. "
                        ai_summary += f"DO NOT execute. Delete immediately."
                        
                        if zero_day_detector and zero_day_detector.available:
                            try:
                                summary_data = {
                                    'filename': file.filename,
                                    'verdict': "MALICIOUS",
                                    'risk_score': risk_score,
                                    'findings': findings_list,
                                    'vulnerabilities': vulnerabilities_list,
                                    'malicious_files_found': malicious_count,
                                    'files_analyzed': total_files,
                                    'detection_source': detection_source
                                }
                                ai_risk_summary = zero_day_detector.generate_risk_summary(summary_data)
                            except Exception as e:
                                logger.error(f"Failed to generate AI risk summary: {e}")
                        
                        proper_findings = []
                        for i, finding_text in enumerate(findings_list[:10]):
                            proper_findings.append(Finding(
                                filename=file.filename,
                                line_number=0,
                                pattern_found=finding_text,
                                calculated_risk=risk_score,
                                behavioral_category="MALICIOUS",
                                reasoning=f"Detected malicious pattern: {finding_text}"
                            ))
                        
                        return ScanResult(
                            filename=file.filename,
                            status="success",
                            verdict="MALICIOUS",
                            risk_score=round(risk_score, 1),
                            primary_intent="Malware Detection",
                            findings=proper_findings,
                            ai_summary=ai_summary,
                            is_ai_verified=True,
                            cnn_confidence=cnn_score,
                            detection_source=detection_source,
                            files_analyzed=total_files,
                            malicious_files_found=malicious_count,
                            detailed_findings=detailed_findings,
                            risk_explanation=f"⚠️ {remediation['malware_type']} detected. Score: {risk_score:.1f}/10.",
                            detection_details=f"Detection via {detection_source}. {malicious_count} files identified as malicious.",
                            malware_type=remediation['malware_type'],
                            safe_alternative=remediation['safe_alternative'],
                            install_command=remediation.get('install_command'),
                            remediation_steps=remediation['steps'],
                            malware_explanations=remediation['explanations'],
                            action="DELETE_AND_GET_OFFICIAL",
                            safe_zip_available=False,
                            scan_id=scan_id,
                            ai_risk_summary=ai_risk_summary,
                            verification_line_changes=[],
                            verification_fixed_vulns=[],
                            bandit_verification=None,
                            radon_verification=None,
                            verification_status=None
                        )
                    
                    # CASE 2: VULNERABILITIES ONLY
                    elif is_vulnerable:
                        logger.info(f"🟡 VULNERABILITIES DETECTED! Score: {cnn_score:.2f}")
                        
                        with open(file_location, 'rb') as f:
                            original_zip = f.read()
                        
                        patched_zip, changes, patched_count, patched_names = patcher.patch_zip(original_zip, file.filename)
                        
                        ai_patches_applied = any('AI-powered' in change.get('description', '') for change in changes)
                        
                        # Extract verification data
                        for change in changes:
                            if change.get('type') == 'VERIFICATION':
                                verification_line_changes = change.get('line_changes', [])
                                verification_fixed_vulns = change.get('fixed_vulnerabilities', [])
                                verification_status = change.get('description', 'Unknown').replace('Verification: ', '')
                                
                                bandit_data = change.get('bandit_result', {})
                                if bandit_data:
                                    bandit_verification = VerificationDetails(
                                        tool=bandit_data.get('tool', 'Bandit'),
                                        status=bandit_data.get('status', 'UNKNOWN'),
                                        message=bandit_data.get('message', ''),
                                        high_severity_issues=bandit_data.get('high_severity_issues', 0),
                                        medium_severity_issues=bandit_data.get('medium_severity_issues', 0)
                                    )
                                    logger.info(f"   📊 Bandit: {bandit_data.get('status', 'UNKNOWN')}")
                                
                                radon_data = change.get('radon_result', {})
                                if radon_data:
                                    radon_verification = VerificationDetails(
                                        tool=radon_data.get('tool', 'Radon'),
                                        status=radon_data.get('status', 'UNKNOWN'),
                                        grade=radon_data.get('grade', ''),
                                        average_complexity=radon_data.get('average_complexity', 0),
                                        message=radon_data.get('message', '')
                                    )
                                    logger.info(f"   📊 Radon: Grade {radon_data.get('grade', '?')}")
                                
                                break
                        
                        # Convert line changes to models
                        line_changes_model = []
                        for lc in verification_line_changes:
                            line_changes_model.append(LineChange(
                                line_number=lc.get('line_number', 0),
                                original=lc.get('original', ''),
                                patched=lc.get('patched', ''),
                                change_type=lc.get('change_type', 'SECURITY_FIX'),
                                vulnerability_fixed=lc.get('vulnerability_fixed', 'Security vulnerability fixed')
                            ))
                        
                        if patched_count > 0:
                            safe_zip_available = True
                            patched_files_count = patched_count
                            patched_files_list = patched_names
                            vulnerabilities_fixed = [VulnerabilityFixed(
                                type=v.get('type', 'UNKNOWN'),
                                description=v.get('description', ''),
                                file=v.get('file', None),
                                old_value=v.get('old_value', None),
                                new_value=v.get('new_value', None)
                            ) for v in changes if v.get('type') != 'VERIFICATION']
                            
                            safe_zip_path = os.path.join(TEMP_DIR, f"safe_{scan_id}_{file.filename}")
                            with open(safe_zip_path, 'wb') as f:
                                f.write(patched_zip)
                            
                            logger.info(f"✅ Safe ZIP created: {safe_zip_path}")
                            logger.info(f"   Patched {patched_count} files, fixed {len(changes)} vulnerabilities")
                            if ai_patches_applied:
                                logger.info(f"   🤖 AI-powered patches applied")
                            if verification_status:
                                logger.info(f"   🔒 Verification: {verification_status}")
                            
                            final_verdict = "VULNERABLE"
                            action = "PATCH_AVAILABLE"
                        else:
                            final_verdict = "VULNERABLE"
                            action = "REVIEW"
                        
                        # Generate AI Risk Summary
                        if zero_day_detector and zero_day_detector.available:
                            try:
                                summary_data = {
                                    'filename': file.filename,
                                    'verdict': final_verdict,
                                    'risk_score': risk_score,
                                    'findings': findings_list,
                                    'vulnerabilities': vulnerabilities_list,
                                    'malicious_files_found': 0,
                                    'files_analyzed': total_files,
                                    'detection_source': detection_source
                                }
                                ai_risk_summary = zero_day_detector.generate_risk_summary(summary_data)
                            except Exception as e:
                                logger.error(f"Failed to generate AI risk summary: {e}")
                        
                        ai_patch_note = " 🤖 AI-powered fixes applied" if ai_patches_applied else ""
                        ai_summary = f"🟡 VULNERABILITIES DETECTED! Found {len(vulnerabilities_list)} vulnerability types: {', '.join(vulnerabilities_list[:5])}. "
                        ai_summary += f"These can be automatically patched. Risk Score: {risk_score:.1f}/10.{ai_patch_note}"
                        
                        proper_findings = []
                        for vuln_type in vulnerabilities_list[:10]:
                            proper_findings.append(Finding(
                                filename=file.filename,
                                line_number=0,
                                pattern_found=vuln_type.replace('_', ' ').title(),
                                calculated_risk=risk_score,
                                behavioral_category="VULNERABILITY",
                                reasoning=f"Security vulnerability detected: {vuln_type}"
                            ))
                        
                        return ScanResult(
                            filename=file.filename,
                            status="success",
                            verdict=final_verdict,
                            risk_score=round(risk_score, 1),
                            primary_intent="Vulnerability Detection",
                            findings=proper_findings,
                            ai_summary=ai_summary,
                            is_ai_verified=True,
                            cnn_confidence=cnn_score,
                            detection_source=detection_source,
                            files_analyzed=total_files,
                            malicious_files_found=0,
                            detailed_findings=detailed_findings,
                            risk_explanation=f"🟡 {len(vulnerabilities_list)} vulnerability types detected. Score: {risk_score:.1f}/10.",
                            detection_details=f"Detection via {detection_source}. Vulnerabilities can be patched.",
                            safe_zip_available=safe_zip_available,
                            safe_zip_path=safe_zip_path,
                            patched_files_count=patched_files_count,
                            patched_files_list=patched_files_list,
                            vulnerabilities_fixed=vulnerabilities_fixed,
                            ai_patches_applied=ai_patches_applied,
                            action=action,
                            scan_id=scan_id,
                            ai_risk_summary=ai_risk_summary,
                            verification_line_changes=line_changes_model,
                            verification_fixed_vulns=verification_fixed_vulns,
                            bandit_verification=bandit_verification,
                            radon_verification=radon_verification,
                            verification_status=verification_status
                        )
                    
                    # CASE 3: ZERO-DAY / SUSPICIOUS
                    elif 0.3 <= cnn_score < 0.7:
                        logger.info(f"🟡 SUSPICIOUS SCORE ({cnn_score:.2f}) - Checking with zero-day detection...")
                        
                        if zero_day_detector and zero_day_detector.available:
                            logger.info(f"🤖 Activating zero-day detection...")
                            suspicious_files = cnn_result.get('suspicious_files', [])
                            if suspicious_files:
                                top_suspicious = suspicious_files[0]
                                file_content = top_suspicious.get('content', b'')
                                filename = top_suspicious.get('filename', 'unknown')
                                
                                zero_day_result = zero_day_detector.analyze_suspicious_package(
                                    file_content, filename, cnn_result
                                )
                                
                                if zero_day_result:
                                    cnn_result['is_malicious'] = zero_day_result['is_malicious']
                                    cnn_result['confidence'] = zero_day_result['confidence']
                                    cnn_result['detection_source'] = zero_day_result['source']
                                    cnn_result['zero_day_analysis'] = zero_day_result
                                    
                                    if zero_day_result['is_malicious']:
                                        final_verdict = "MALICIOUS"
                                        action = "ZERO_DAY_DETECTED"
                                        risk_score = zero_day_result['confidence'] * 10
                                    
                                    logger.info(f"🤖 Zero-day verdict: {'MALICIOUS' if zero_day_result['is_malicious'] else 'SUSPICIOUS'} (conf: {zero_day_result['confidence']:.2%})")
                        
                        final_verdict = "SUSPICIOUS"
                        action = "REVIEW"
                        
                        if zero_day_detector and zero_day_detector.available:
                            try:
                                summary_data = {
                                    'filename': file.filename,
                                    'verdict': final_verdict,
                                    'risk_score': risk_score,
                                    'findings': findings_list,
                                    'vulnerabilities': vulnerabilities_list,
                                    'malicious_files_found': 0,
                                    'files_analyzed': total_files,
                                    'detection_source': detection_source
                                }
                                ai_risk_summary = zero_day_detector.generate_risk_summary(summary_data)
                            except Exception as e:
                                logger.error(f"Failed to generate AI risk summary: {e}")
                        
                        return ScanResult(
                            filename=file.filename,
                            status="success",
                            verdict=final_verdict,
                            risk_score=round(risk_score, 1),
                            primary_intent="Security Scan",
                            findings=proper_findings if 'proper_findings' in locals() else [],
                            ai_summary=ai_summary if 'ai_summary' in locals() else "Analysis complete",
                            is_ai_verified=True,
                            cnn_confidence=cnn_score,
                            detection_source=detection_source,
                            files_analyzed=total_files,
                            malicious_files_found=0,
                            detailed_findings=detailed_findings,
                            risk_explanation=f"🟡 Suspicious patterns detected. Score: {risk_score:.1f}/10.",
                            detection_details=f"Analysis via {detection_source} completed.",
                            safe_zip_available=False,
                            action=action,
                            scan_id=scan_id,
                            ai_risk_summary=ai_risk_summary,
                            verification_line_changes=None,
                            verification_fixed_vulns=None,
                            bandit_verification=None,
                            radon_verification=None,
                            verification_status=None
                        )
                    
                    # CASE 4: BENIGN
                    else:
                        logger.info(f"🟢 BENIGN FILE (Score: {cnn_score:.2f})")
                        final_verdict = "BENIGN"
                        action = "SAFE"
                        
                        if zero_day_detector and zero_day_detector.available:
                            try:
                                summary_data = {
                                    'filename': file.filename,
                                    'verdict': final_verdict,
                                    'risk_score': risk_score,
                                    'findings': findings_list,
                                    'vulnerabilities': vulnerabilities_list,
                                    'malicious_files_found': 0,
                                    'files_analyzed': total_files,
                                    'detection_source': detection_source
                                }
                                ai_risk_summary = zero_day_detector.generate_risk_summary(summary_data)
                            except Exception as e:
                                logger.error(f"Failed to generate AI risk summary: {e}")
                        
                        ai_summary = f"✅ File appears BENIGN. Confidence: {cnn_result.get('confidence', 0):.1%}. All files analyzed appear safe."
                        
                        proper_findings = [Finding(
                            filename=file.filename,
                            line_number=0,
                            pattern_found="No threats detected",
                            calculated_risk=0,
                            behavioral_category="BENIGN",
                            reasoning="No malware or vulnerabilities found"
                        )]
                        
                        return ScanResult(
                            filename=file.filename,
                            status="success",
                            verdict=final_verdict,
                            risk_score=round(risk_score, 1),
                            primary_intent="Security Scan",
                            findings=proper_findings,
                            ai_summary=ai_summary,
                            is_ai_verified=True,
                            cnn_confidence=cnn_score,
                            detection_source=detection_source,
                            files_analyzed=total_files,
                            malicious_files_found=0,
                            detailed_findings=detailed_findings,
                            risk_explanation=f"✅ No threats detected. Score: {risk_score:.1f}/10.",
                            detection_details=f"Analysis via {detection_source} completed.",
                            safe_zip_available=False,
                            action=action,
                            scan_id=scan_id,
                            ai_risk_summary=ai_risk_summary,
                            verification_line_changes=None,
                            verification_fixed_vulns=None,
                            bandit_verification=None,
                            radon_verification=None,
                            verification_status=None
                        )
                    
            except Exception as e:
                logger.error(f"CNN analysis failed: {e}")
                return ScanResult(
                    filename=file.filename,
                    status="error",
                    verdict="ERROR",
                    risk_score=0.0,
                    primary_intent="CNN Analysis Failed",
                    findings=[],
                    ai_summary=f"CNN analysis error: {str(e)[:200]}",
                    is_ai_verified=False,
                    detection_source=None,
                    files_analyzed=0,
                    malicious_files_found=0,
                    detailed_findings=[],
                    risk_explanation="Analysis failed.",
                    detection_details=f"Error: {str(e)[:100]}",
                    safe_zip_available=False,
                    action="ERROR",
                    scan_id=scan_id,
                    ai_risk_summary=None,
                    verification_line_changes=None,
                    verification_fixed_vulns=None,
                    bandit_verification=None,
                    radon_verification=None,
                    verification_status=None
                )
        else:
            return ScanResult(
                filename=file.filename,
                status="success",
                verdict="BENIGN",
                risk_score=0.0,
                primary_intent="CNN Analysis Only",
                findings=[],
                ai_summary="CNN detector not available.",
                is_ai_verified=False,
                cnn_confidence=None,
                detection_source=None,
                files_analyzed=0,
                malicious_files_found=0,
                detailed_findings=[],
                risk_explanation="CNN detector unavailable.",
                detection_details="CNN model could not be loaded.",
                safe_zip_available=False,
                action="SAFE",
                scan_id=scan_id,
                ai_risk_summary=None,
                verification_line_changes=None,
                verification_fixed_vulns=None,
                bandit_verification=None,
                radon_verification=None,
                verification_status=None
            )

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return ScanResult(
            filename=file.filename,
            status="error",
            verdict="ERROR",
            risk_score=0.0,
            primary_intent="Scan Failed",
            findings=[],
            ai_summary=f"Scan error: {str(e)[:200]}",
            is_ai_verified=False,
            cnn_confidence=None,
            detection_source=None,
            files_analyzed=0,
            malicious_files_found=0,
            detailed_findings=[],
            risk_explanation=f"Scan failed: {str(e)[:100]}",
            detection_details="Error occurred during scan.",
            safe_zip_available=False,
            action="ERROR",
            scan_id=scan_id,
            ai_risk_summary=None,
            verification_line_changes=None,
            verification_fixed_vulns=None,
            bandit_verification=None,
            radon_verification=None,
            verification_status=None
        )
    finally:
        if os.path.exists(file_location):
            os.remove(file_location)
            logger.info(f"Cleaned up {file_location}")

@app.get("/api/download/{scan_id}")
async def download_safe_zip(scan_id: str, filename: str = None):
    """Download the patched safe version of the ZIP"""
    safe_zip_pattern = os.path.join(TEMP_DIR, f"safe_{scan_id}_*.zip")
    
    files = glob.glob(safe_zip_pattern)
    if files:
        latest_file = max(files, key=os.path.getctime)
        return FileResponse(
            latest_file, 
            media_type='application/zip',
            filename=f"safe_{os.path.basename(latest_file).replace(f'safe_{scan_id}_', '')}"
        )
    
    if filename:
        safe_zip_pattern = os.path.join(TEMP_DIR, f"safe_*_{filename}")
        files = glob.glob(safe_zip_pattern)
        if files:
            latest_file = max(files, key=os.path.getctime)
            return FileResponse(
                latest_file, 
                media_type='application/zip',
                filename=f"safe_{filename}"
            )
    
    safe_zip_pattern = os.path.join(TEMP_DIR, f"*{scan_id}*.zip")
    files = glob.glob(safe_zip_pattern)
    if files:
        latest_file = max(files, key=os.path.getctime)
        return FileResponse(
            latest_file, 
            media_type='application/zip',
            filename=f"safe_{os.path.basename(latest_file)}"
        )
    
    raise HTTPException(status_code=404, detail="Safe ZIP not found. The scan may not have generated a patched version.")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "cnn_available": cnn_detector is not None and cnn_detector.available,
        "zero_day_available": zero_day_detector is not None and zero_day_detector.available,
        "patcher_available": True,
        "patcher_ai_mode": "GROQ" if patcher.use_groq else ("GEMINI" if hasattr(patcher, 'use_gemini') and patcher.use_gemini else "RULE_BASED"),
        "mode": "CNN with Zero-Day AI Detection + AI-Powered Vulnerability Patching (Groq preferred)",
        "model_path": cnn_detector.model_path if cnn_detector and hasattr(cnn_detector, 'model_path') else None
    }

@app.get("/api/scan/status")
async def scan_status():
    return {
        "max_files_analyzed": 100,
        "cnn_status": "available" if cnn_detector and cnn_detector.available else "unavailable",
        "zero_day_status": "available" if zero_day_detector and zero_day_detector.available else "unavailable",
        "patcher_status": "available",
        "patcher_ai_enabled": patcher.use_groq if hasattr(patcher, 'use_groq') else False
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)