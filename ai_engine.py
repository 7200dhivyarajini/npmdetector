"""
SmartMalwareAnalyzer - Using Gemini 2.5 Flash with Fixed JSON Parsing
"""

import json
import time
import re
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
from google import genai
from google.genai import types

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.ai")

# Default API key
DEFAULT_API_KEY = "AIzaSyBkGal1VL6Gi5aN8hgeZSkZAaO32KUfaak"

# Working models
WORKING_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

class RateLimiter:
    """Simple rate limiter"""
    def __init__(self):
        self.last_request_time = None
        self.min_request_interval = 1
        self.daily_request_count = 0
        self.daily_reset_date = datetime.now().date()
        
    def wait_if_needed(self):
        now = datetime.now()
        
        if now.date() > self.daily_reset_date:
            self.daily_request_count = 0
            self.daily_reset_date = now.date()
        
        if self.last_request_time:
            time_since_last = (now - self.last_request_time).seconds
            if time_since_last < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last)
        
        self.last_request_time = now
        self.daily_request_count += 1

class SmartMalwareAnalyzer:
    def __init__(self, api_key: str = DEFAULT_API_KEY):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.5-flash"
        self.backup_model = "gemini-2.5-flash-lite"
        self.rate_limiter = RateLimiter()
        self._cache = {}
        
    def extract_json_from_response(self, text: str) -> dict:
        """Extract JSON from model response (even if wrapped in markdown)"""
        # Try to find JSON between ```json and ``` markers
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass
        
        # Try to find any JSON-like structure
        json_match = re.search(r'({[\s\S]*})', text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass
        
        # Try parsing the whole text
        try:
            return json.loads(text)
        except:
            raise ValueError(f"Could not extract JSON from: {text[:200]}")
    
    def filter_critical_patterns(self, patterns: List[Dict[str, Any]], max_patterns: int = 20) -> List[Dict[str, Any]]:
        if not patterns:
            return []
        sorted_patterns = sorted(patterns, key=lambda p: p['score'], reverse=True)
        return sorted_patterns[:max_patterns]
    
    def create_pattern_fingerprint(self, patterns):
        if not patterns:
            return "empty"
        pattern_texts = []
        for p in patterns[:10]:
            text = p.get('pattern_text', '')[:100]
            pattern_texts.append(text)
        return hashlib.md5(''.join(pattern_texts).encode()).hexdigest()
    
    def analyze_with_ai(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not patterns:
            return self.rule_based_fallback(patterns)
        
        # Check cache
        pattern_hash = self.create_pattern_fingerprint(patterns)
        if pattern_hash in self._cache:
            cache_time, cached_result = self._cache[pattern_hash]
            if datetime.now() - cache_time < timedelta(hours=1):
                logger.info("📦 Returning cached result")
                return cached_result
        
        # Prepare patterns
        concise_patterns = []
        for p in patterns[:20]:
            text = p['pattern_text']
            if len(text) > 150:
                text = text[:150] + "..."
            concise_patterns.append({
                'file': p['filename'].split('/')[-1],
                'code': text,
                'score': p['score']
            })
        
        # CRITICAL FIX: More explicit prompt for JSON
        prompt = f"""You are a malware analysis expert. Analyze these code patterns.

{json.dumps(concise_patterns, indent=2)}

You MUST respond with ONLY a valid JSON object. No other text, no markdown, no explanation.

Required JSON format:
{{
    "risk_level": "HIGH" or "MEDIUM" or "LOW",
    "risk_score": number between 0.0 and 10.0,
    "summary": "brief analysis",
    "verdict": "MALICIOUS" or "SUSPICIOUS" or "BENIGN",
    "malware_type": "ransomware/trojan/etc or null"
}}

JSON response:"""
        
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
            
            # Validate
            required = ['risk_level', 'risk_score', 'summary', 'verdict']
            if not all(k in result for k in required):
                raise ValueError(f"Missing fields")
            
            logger.info(f"✅ Analysis complete")
            self._cache[pattern_hash] = (datetime.now(), result)
            
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
            
            # Try backup with even stricter prompt
            try:
                logger.info(f"🔄 Trying {self.backup_model}...")
                
                backup_prompt = prompt + "\n\nIMPORTANT: Respond with ONLY the JSON object, nothing else."
                
                response = self.client.models.generate_content(
                    model=self.backup_model,
                    contents=backup_prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=500
                    )
                )
                
                result = self.extract_json_from_response(response.text)
                
                logger.info(f"✅ Backup analysis complete")
                self._cache[pattern_hash] = (datetime.now(), result)
                
                return {
                    "risk_level": result.get("risk_level", "LOW"),
                    "risk_score": float(result.get("risk_score", 0)),
                    "summary": result.get("summary", "Analysis complete"),
                    "verdict": result.get("verdict", "BENIGN"),
                    "malware_type": result.get("malware_type"),
                    "is_ai_verified": True
                }
                
            except Exception as e2:
                logger.error(f"❌ Backup also failed: {str(e2)}")
                return self.rule_based_fallback(patterns)
    
    def rule_based_fallback(self, patterns):
        """Enhanced rule-based analysis"""
        if not patterns:
            return {
                "risk_level": "LOW",
                "risk_score": 0.0,
                "summary": "No patterns",
                "verdict": "BENIGN",
                "malware_type": None,
                "is_ai_verified": False
            }
        
        # Calculate risk score
        avg_score = sum(p['score'] for p in patterns) / len(patterns)
        max_score = max((p['score'] for p in patterns), default=0)
        
        # Count suspicious patterns
        execution = sum(1 for p in patterns if any(
            x in p['pattern_text'].lower() for x in ['eval(', 'exec(', 'child_process', 'powershell']
        ))
        
        # Final score
        final_score = min(avg_score * 0.5 + max_score * 0.3 + execution * 0.5, 10.0)
        
        if final_score >= 7.0:
            verdict = "MALICIOUS"
            level = "HIGH"
        elif final_score >= 4.0:
            verdict = "SUSPICIOUS"
            level = "MEDIUM"
        else:
            verdict = "BENIGN"
            level = "LOW"
        
        return {
            "risk_level": level,
            "risk_score": round(final_score, 1),
            "summary": f"Rule-based: avg score {avg_score:.1f}",
            "verdict": verdict,
            "malware_type": None,
            "is_ai_verified": False
        }
    
    def analyze_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not patterns:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "summary": "No patterns",
                "verdict": "BENIGN",
                "malware_type": None,
                "is_ai_verified": False
            }
        
        logger.info(f"🔍 Analyzing {len(patterns)} patterns")
        
        if len(patterns) > 50:
            patterns_to_analyze = self.filter_critical_patterns(patterns, 20)
        else:
            patterns_to_analyze = patterns
        
        result = self.analyze_with_ai(patterns_to_analyze)
        logger.info(f"✅ Final: {result['verdict']} (score={result['risk_score']:.1f})")
        return result

GeminiEngine = SmartMalwareAnalyzer