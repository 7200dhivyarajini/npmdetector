"""
SmartMalwareAnalyzer - Using Gemini 2.5 Flash with Fixed JSON Parsing
"""

import json
import time
import re
import hashlib
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.ai")

# Get Gemini API key from environment
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

if not GEMINI_API_KEY:
    logger.error("❌ GEMINI_API_KEY not found in .env file!")
    raise ValueError("GEMINI_API_KEY environment variable is required")

# Working models
WORKING_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

class RateLimiter:
    """Simple rate limiter"""
    def __init__(self):
        self.last_request_time = None
        self.min_request_interval = 1  # 1 second between requests
        self.daily_request_count = 0
        self.daily_reset_date = datetime.now().date()
        
    def wait_if_needed(self):
        now = datetime.now()
        
        # Reset daily counter if new day
        if now.date() > self.daily_reset_date:
            self.daily_request_count = 0
            self.daily_reset_date = now.date()
            logger.info("📊 Daily request counter reset")
        
        # Check daily limit
        if self.daily_request_count >= 1000:
            logger.warning("⚠️ Daily request limit reached. Using fallback.")
            return False
        
        # Rate limiting between requests
        if self.last_request_time:
            time_since_last = (now - self.last_request_time).total_seconds()
            if time_since_last < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last)
        
        self.last_request_time = datetime.now()
        self.daily_request_count += 1
        return True

class SmartMalwareAnalyzer:
    def __init__(self, api_key: str = None):
        """
        Initialize the malware analyzer with Gemini AI
        
        Args:
            api_key: Optional API key (defaults to GEMINI_API_KEY from .env)
        """
        # Use provided key or from environment
        self.api_key = api_key or GEMINI_API_KEY
        
        if not self.api_key:
            raise ValueError("API key is required. Set GEMINI_API_KEY in .env file")
        
        self.client = genai.Client(api_key=self.api_key)
        self.model_id = "gemini-2.5-flash"
        self.backup_model = "gemini-2.5-flash-lite"
        self.rate_limiter = RateLimiter()
        self._cache = {}  # Cache for similar pattern results
        
    def extract_json_from_response(self, text: str) -> dict:
        """
        Extract JSON from model response (even if wrapped in markdown or split across lines)
        """
        if not text:
            raise ValueError("Empty response text")
        
        # Clean the text
        text = text.strip()
        
        # Remove markdown code blocks
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        
        text = text.strip()
        
        # Method 1: Find matching braces (handles split JSON)
        brace_count = 0
        start_idx = -1
        in_string = False
        escape_next = False
        
        for i, char in enumerate(text):
            if escape_next:
                escape_next = False
                continue
                
            if char == '\\':
                escape_next = True
                continue
                
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            
            if not in_string:
                if char == '{':
                    if start_idx == -1:
                        start_idx = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_idx != -1:
                        json_str = text[start_idx:i+1]
                        try:
                            return json.loads(json_str)
                        except json.JSONDecodeError:
                            # Try to fix common issues
                            try:
                                # Fix unescaped newlines
                                fixed = json_str.replace('\n', '\\n').replace('\r', '\\r')
                                return json.loads(fixed)
                            except:
                                continue
        
        # Method 2: Try regex pattern
        json_match = re.search(r'({[\s\S]*?})', text)
        if json_match:
            try:
                json_str = json_match.group(1)
                # Fix common issues
                json_str = json_str.replace('\n', '\\n').replace('\r', '\\r')
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
        
        # Method 3: Try to find incomplete JSON and complete it
        if start_idx != -1:
            partial_json = text[start_idx:]
            # Try to add missing closing braces
            open_braces = partial_json.count('{') - partial_json.count('}')
            if open_braces > 0:
                partial_json += '}' * open_braces
                try:
                    return json.loads(partial_json)
                except:
                    pass
        
        raise ValueError(f"Could not extract JSON from: {text[:200]}")
    
    def filter_critical_patterns(self, patterns: List[Dict[str, Any]], max_patterns: int = 20) -> List[Dict[str, Any]]:
        """Filter to only the most critical patterns"""
        if not patterns:
            return []
        sorted_patterns = sorted(patterns, key=lambda p: p.get('score', 0), reverse=True)
        return sorted_patterns[:max_patterns]
    
    def create_pattern_fingerprint(self, patterns: List[Dict[str, Any]]) -> str:
        """Create a unique fingerprint for pattern cache"""
        if not patterns:
            return "empty"
        pattern_texts = []
        for p in patterns[:10]:
            text = p.get('pattern_text', '')[:100]
            pattern_texts.append(text)
        return hashlib.md5(''.join(pattern_texts).encode()).hexdigest()
    
    def analyze_with_ai(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns using Gemini AI"""
        if not patterns:
            return self.rule_based_fallback(patterns)
        
        # Check cache first
        pattern_hash = self.create_pattern_fingerprint(patterns)
        if pattern_hash in self._cache:
            cache_time, cached_result = self._cache[pattern_hash]
            if datetime.now() - cache_time < timedelta(hours=1):
                logger.info("📦 Returning cached result")
                return cached_result.copy()
        
        # Check rate limit before proceeding
        if not self.rate_limiter.wait_if_needed():
            logger.warning("⚠️ Rate limit reached, using fallback")
            return self.rule_based_fallback(patterns)
        
        # Prepare concise patterns for AI
        concise_patterns = []
        for p in patterns[:20]:
            text = p.get('pattern_text', '')
            if len(text) > 150:
                text = text[:150] + "..."
            concise_patterns.append({
                'file': p.get('filename', 'unknown').split('/')[-1],
                'code': text,
                'score': p.get('score', 0)
            })
        
        # Prompt for JSON output - more explicit about format
        prompt = f"""You are a malware analysis expert. Analyze these code patterns.

{json.dumps(concise_patterns, indent=2)}

You MUST respond with ONLY a valid JSON object. Do not include any markdown, explanations, or additional text.

Required JSON format:
{{
    "risk_level": "HIGH",
    "risk_score": 8.5,
    "summary": "Brief analysis here",
    "verdict": "MALICIOUS",
    "malware_type": "trojan"
}}

Valid values:
- risk_level: "HIGH", "MEDIUM", or "LOW"
- risk_score: number between 0.0 and 10.0
- summary: short description (max 100 chars)
- verdict: "MALICIOUS", "SUSPICIOUS", or "BENIGN"
- malware_type: "ransomware", "trojan", "worm", "cryptominer", "keylogger", "infostealer", "backdoor", or null

Respond with ONLY the JSON object:"""
        
        # Try primary model
        try:
            self.rate_limiter.wait_if_needed()
            logger.info(f"🤖 Analyzing with {self.model_id}...")
            
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=500
                )
            )
            
            # Extract JSON from response
            result = self.extract_json_from_response(response.text)
            
            # Validate required fields
            required = ['risk_level', 'risk_score', 'summary', 'verdict']
            if not all(k in result for k in required):
                raise ValueError(f"Missing required fields: {required}")
            
            logger.info(f"✅ Gemini analysis complete")
            
            # Cache result
            self._cache[pattern_hash] = (datetime.now(), result.copy())
            
            return {
                "risk_level": result.get("risk_level", "LOW"),
                "risk_score": float(result.get("risk_score", 0)),
                "summary": result.get("summary", "Analysis complete"),
                "verdict": result.get("verdict", "BENIGN"),
                "malware_type": result.get("malware_type"),
                "is_ai_verified": True
            }
            
        except Exception as e:
            logger.error(f"❌ Primary model failed: {str(e)}")
            
            # Try backup model
            try:
                logger.info(f"🔄 Trying backup model: {self.backup_model}...")
                
                # Shorter prompt for backup model
                backup_prompt = f"""Analyze these code patterns and return ONLY valid JSON:
{json.dumps(concise_patterns[:10], indent=2)}

Return exactly: {{"risk_level":"HIGH/MEDIUM/LOW","risk_score":0.0-10.0,"summary":"text","verdict":"MALICIOUS/SUSPICIOUS/BENIGN","malware_type":"type or null"}}"""
                
                response = self.client.models.generate_content(
                    model=self.backup_model,
                    contents=backup_prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=500
                    )
                )
                
                result = self.extract_json_from_response(response.text)
                
                logger.info(f"✅ Backup model analysis complete")
                
                # Cache result
                self._cache[pattern_hash] = (datetime.now(), result.copy())
                
                return {
                    "risk_level": result.get("risk_level", "LOW"),
                    "risk_score": float(result.get("risk_score", 0)),
                    "summary": result.get("summary", "Analysis complete"),
                    "verdict": result.get("verdict", "BENIGN"),
                    "malware_type": result.get("malware_type"),
                    "is_ai_verified": True
                }
                
            except Exception as e2:
                logger.error(f"❌ Backup model also failed: {str(e2)}")
                return self.rule_based_fallback(patterns)
    
    def rule_based_fallback(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced rule-based analysis when AI is unavailable"""
        if not patterns:
            return {
                "risk_level": "LOW",
                "risk_score": 0.0,
                "summary": "No patterns detected",
                "verdict": "BENIGN",
                "malware_type": None,
                "is_ai_verified": False
            }
        
        # Calculate risk score
        avg_score = sum(p.get('score', 0) for p in patterns) / len(patterns)
        max_score = max((p.get('score', 0) for p in patterns), default=0)
        
        # Count suspicious pattern types
        malicious_keywords = {
            'eval': 0.8,
            'exec': 0.8,
            'child_process': 0.9,
            'powershell': 0.7,
            'base64': 0.6,
            'atob': 0.6,
            'btoa': 0.5,
            'crypto': 0.5,
            'miner': 0.9,
            'stratum': 0.9,
            'password': 0.6,
            'secret': 0.6,
            'api_key': 0.6,
            'rm -rf': 1.0,
            'document.write': 0.5,
            'innerHTML': 0.4
        }
        
        malicious_count = 0
        for p in patterns:
            text = p.get('pattern_text', '').lower()
            for keyword, weight in malicious_keywords.items():
                if keyword in text:
                    malicious_count += 1
                    break
        
        # Calculate final score
        base_score = avg_score * 0.4 + max_score * 0.3 + (malicious_count * 0.3)
        final_score = min(base_score * 10, 10.0)
        
        # Determine verdict
        if final_score >= 7.0:
            verdict = "MALICIOUS"
            level = "HIGH"
        elif final_score >= 4.0:
            verdict = "SUSPICIOUS"
            level = "MEDIUM"
        else:
            verdict = "BENIGN"
            level = "LOW"
        
        logger.info(f"📊 Rule-based: avg={avg_score:.2f}, max={max_score:.2f}, malicious={malicious_count}, final={final_score:.1f}")
        
        return {
            "risk_level": level,
            "risk_score": round(final_score, 1),
            "summary": f"Rule-based analysis: {len(patterns)} patterns, {malicious_count} suspicious",
            "verdict": verdict,
            "malware_type": None,
            "is_ai_verified": False
        }
    
    def analyze_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main entry point for pattern analysis
        
        Args:
            patterns: List of pattern dictionaries with keys:
                - filename: str
                - pattern_text: str
                - score: float (0-1)
        
        Returns:
            Dictionary with analysis results
        """
        if not patterns:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "summary": "No patterns to analyze",
                "verdict": "BENIGN",
                "malware_type": None,
                "is_ai_verified": False
            }
        
        logger.info(f"🔍 Analyzing {len(patterns)} patterns")
        
        # Reduce patterns if too many
        if len(patterns) > 50:
            patterns_to_analyze = self.filter_critical_patterns(patterns, 20)
            logger.info(f"📊 Filtered to {len(patterns_to_analyze)} critical patterns")
        else:
            patterns_to_analyze = patterns
        
        # Analyze with AI
        result = self.analyze_with_ai(patterns_to_analyze)
        
        logger.info(f"✅ Final verdict: {result['verdict']} (score={result['risk_score']:.1f})")
        return result

# Export the class
GeminiEngine = SmartMalwareAnalyzer


# ============================================
# Test code
# ============================================
if __name__ == "__main__":
    print("="*60)
    print("Smart Malware Analyzer - Gemini AI Engine")
    print("="*60)
    
    # Check if API key is available
    if GEMINI_API_KEY:
        print(f"✅ API Key found: {GEMINI_API_KEY[:20]}...")
    else:
        print("❌ No API key found in .env file!")
        exit(1)
    
    # Create analyzer instance
    analyzer = SmartMalwareAnalyzer()
    
    # Test patterns
    test_patterns = [
        {
            "filename": "test.js",
            "pattern_text": "eval(atob('dmFyIG5ldCA9IG5ldyBSZXF1ZXN0KCk7'))",
            "score": 0.85
        },
        {
            "filename": "test.js",
            "pattern_text": "const PASSWORD = 'admin12345'",
            "score": 0.75
        }
    ]
    
    print("\n🧪 Running test analysis...")
    result = analyzer.analyze_patterns(test_patterns)
    
    print(f"\n📊 Result:")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Risk Score: {result['risk_score']}/10")
    print(f"   Risk Level: {result['risk_level']}")
    print(f"   Summary: {result['summary']}")
    print(f"   AI Verified: {result['is_ai_verified']}")