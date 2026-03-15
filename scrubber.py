"""
PrivacyScrubber - Redact sensitive data before AI analysis
"""

import re
import json

class PrivacyScrubber:
    def __init__(self):
        self.api_key_pattern = r'AIzaSy[A-Za-z0-9_-]{35}'
        self.secret_patterns = [
            r'(?i)(api[_-]?key|secret|password|token|auth|private[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9+/=-_]{20,})["\']?',
            r'(?i)(password|secret)\s*=\s*["\']([^"\']{10,})["\']',
        ]
        self.path_patterns = [
            r'C:\\\\?(?:Users|Windows|Program Files|Temp|tmp)[\\\\\w\s.]*',
            r'/home/[\\w/]*',
            r'/Users/[\\w/]*',
            r'/tmp/[\\w/]*',
            r'/var/[\\w/]*',
            r'[A-Za-z]:\\\\(?:Users|Windows|Program Files)[\\\\\\w\\s.]*',
        ]
        self.ip_pattern = r'\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|localhost))(?:\d{1,3}\.){3}\d{1,3}\b'

    def scrub_patterns(self, text: str) -> str:
        """Apply all scrubbing patterns to text"""
        scrubbed = text
        
        # Scrub API keys
        scrubbed = re.sub(self.api_key_pattern, '[API_KEY_REDACTED]', scrubbed)
        
        # Scrub secrets and passwords
        for pattern in self.secret_patterns:
            scrubbed = re.sub(pattern, r'\1=[REDACTED]', scrubbed, flags=re.IGNORECASE)
        
        # Scrub paths
        for pattern in self.path_patterns:
            scrubbed = re.sub(pattern, '[LOCAL_PATH_REDACTED]', scrubbed)
        
        # Scrub IP addresses
        scrubbed = re.sub(self.ip_pattern, '[IP_REDACTED]', scrubbed)
        
        return scrubbed

    def scrub_json(self, data: dict | list) -> dict | list:
        """Recursively scrub JSON-serializable data"""
        if isinstance(data, dict):
            return {k: self.scrub_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.scrub_json(item) for item in data]
        elif isinstance(data, str):
            return self.scrub_patterns(data)
        else:
            return data

# Test scrubber
if __name__ == "__main__":
    scrubber = PrivacyScrubber()
    test_text = """
    API key: AIzaSyBkGal1VL6Gi5aN8hgeZSkZAaO32KUfaak
    Path: C:\\Users\\Dhivya1256\\Documents
    Secret: password=supersecret123
    IP: 192.168.1.100
    """
    print("Scrubbing...")
    print(scrubber.scrub_patterns(test_text))
