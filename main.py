import os
import sys
import uuid
import shutil
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from collections import defaultdict
import time

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Local Imports
sys.path.insert(0, os.path.dirname(__file__))

from backend_ml.inference.zip_scanner import extract_critical_patterns, ZipExtractor
from ai_engine import SmartMalwareAnalyzer

# --- Configuration & Logging ---
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger("sentinel")

app = FastAPI(title="Sentinel AI Backend", version="5.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = "temp_scans"

# Global rate limiter
class RateLimiter:
    def __init__(self, requests_per_minute=2):
        self.requests_per_minute = requests_per_minute
        self.request_timestamps = []
        self.min_interval = 35  # 35 seconds between requests (safer than 30)
        self.last_request_time = None
        self.queue = asyncio.Queue()
        self.processing = False
        
    async def wait_if_needed(self):
        """Wait if we need to respect rate limits"""
        now = datetime.now()
        
        # Clean old timestamps
        self.request_timestamps = [ts for ts in self.request_timestamps 
                                  if now - ts < timedelta(minutes=1)]
        
        # Check if we've hit the limit
        if len(self.request_timestamps) >= self.requests_per_minute:
            oldest = min(self.request_timestamps)
            wait_time = 60 - (now - oldest).seconds
            if wait_time > 0:
                logger.info(f"⏳ Rate limit: waiting {wait_time + 2} seconds...")
                await asyncio.sleep(wait_time + 2)
        
        # Add delay between requests
        if self.last_request_time:
            time_since_last = (now - self.last_request_time).seconds
            if time_since_last < self.min_interval:
                wait_time = self.min_interval - time_since_last
                logger.info(f"⏳ Cooling down: waiting {wait_time} seconds...")
                await asyncio.sleep(wait_time)
        
        self.request_timestamps.append(datetime.now())
        self.last_request_time = datetime.now()

# Initialize rate limiter
rate_limiter = RateLimiter()

# Models
class Finding(BaseModel):
    filename: str
    line_number: Optional[int] = 0
    pattern_found: str
    calculated_risk: float
    behavioral_category: str
    reasoning: str

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
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    key_indicators: Optional[List[str]] = None

def purge_system_cache():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TEMP_DIR)
    logger.info("Cache purged.")

@app.on_event("startup")
async def startup_event():
    purge_system_cache()

@app.post("/api/scan", response_model=ScanResult)
async def perform_scan(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())[:8]
    file_location = os.path.join(TEMP_DIR, f"{scan_id}_{file.filename}")
    
    try:
        # Save uploaded file
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f"[SMART SCAN] Processing {file.filename}")

        # Extract patterns
        all_patterns = extract_critical_patterns(
            open(file_location, 'rb').read(), 
            file.filename
        )
        
        if not all_patterns:
            return ScanResult(
                filename=file.filename,
                status="success",
                verdict="BENIGN",
                risk_score=0.0,
                primary_intent="No suspicious patterns found",
                findings=[],
                ai_summary="No analyzable patterns found in the file.",
                is_ai_verified=False
            )

        logger.info(f"Extracted {len(all_patterns)} patterns total")

        # IMPORTANT: Wait for rate limit before AI call
        await rate_limiter.wait_if_needed()

        # Initialize analyzer and analyze
        analyzer = SmartMalwareAnalyzer()
        report = analyzer.analyze_patterns(all_patterns)
        
        logger.info(f"Analysis complete: risk={report['risk_score']:.1f}, verdict={report['verdict']}")

        # Create findings from top patterns
        findings = []
        top_patterns = sorted(all_patterns, key=lambda p: p['score'], reverse=True)[:15]
        
        for pat in top_patterns:
            finding = Finding(
                filename=pat['filename'],
                line_number=pat['line_number'],
                pattern_found=pat['pattern_text'][:100] + "..." if len(pat['pattern_text']) > 100 else pat['pattern_text'],
                calculated_risk=float(pat['score']) * (report['risk_score'] / 10.0),
                behavioral_category=report['risk_level'],
                reasoning=f"Pattern score: {pat['score']}"
            )
            findings.append(finding)

        # Generate summary
        ai_summary = report['summary']
        if report.get('key_indicators'):
            ai_summary += f" Indicators: {', '.join(report['key_indicators'])}"

        return ScanResult(
            filename=file.filename,
            status="success",
            verdict=report['verdict'],
            risk_score=report['risk_score'],
            primary_intent=f"AI Behavioral Analysis ({report.get('malware_type', 'unknown')})",
            findings=findings,
            ai_summary=ai_summary,
            is_ai_verified=report.get('is_ai_verified', True),
            ml_prediction=report.get('malware_type'),
            ml_confidence=report.get('confidence'),
            key_indicators=report.get('key_indicators', [])
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
            is_ai_verified=False
        )
    finally:
        if os.path.exists(file_location):
            os.remove(file_location)
            logger.info(f"Cleaned up {file_location}")

# Optional: Add a health check endpoint
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)