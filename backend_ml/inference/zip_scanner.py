"""
Refactored ZIP Extractor for AI-Native Sentinel v5.0
Supports both legacy Class-based extraction and new Smart Pattern Extraction.
"""

import io
import logging
import os
import zipfile
import math
from collections import Counter
from typing import List, Dict, Tuple, Any

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sentinel.zip")

# Configuration
MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
IGNORED_DIRS = {'node_modules', '.git', '__pycache__', 'venv', '.venv'}
ANALYSABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".ps1", ".bat", ".cmd",
    ".rb", ".php", ".pl", ".go", ".rs", ".c", ".cpp", ".cs",
    ".java", ".vbs", ".lua", ".r", ".m",
}

# --- Helper Functions ---

def calculate_entropy(text: str) -> float:
    """Detects hidden/obfuscated code by measuring randomness."""
    if not text:
        return 0
    counter = Counter(text)
    probs = [count / len(text) for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    return entropy

def get_score(pattern: str) -> int:
    """Scoring logic for Critical Pattern extractor."""
    score = 0
    pattern_lower = pattern.lower()
    # High Priority: Execution Primitives (3 pts)
    if any(x in pattern for x in ['eval(', 'exec(', 'ChildProcess', 'powershell', 'child_process']):
        score += 3
    # Medium Priority: Encoding/Obfuscation (2 pts)
    if len(pattern) > 20 and calculate_entropy(pattern) > 4.5:
        score += 2
    # Low Priority: Network/IO (1 pt)
    if any(x in pattern_lower for x in ['http', 'https', 'fs.writefile', 'socket', 'axios']):
        score += 1
    return score

# --- The ZipExtractor Class (Fixes your ImportError) ---

class ZipExtractor:
    """
    Main class for handling ZIP files. 
    Provides methods for standard extraction and smart pattern mining.
    """
    def __init__(self, zip_path_or_bytes: Any, extract_to: str = "temp_scans"):
        self.data = zip_path_or_bytes
        self.extract_to = extract_to

    def extract_all(self, ignored_dirs=None) -> List[Tuple[str, str]]:
        """
        Legacy method used by main.py to extract files to disk.
        Returns a list of (absolute_path, filename).
        """
        if ignored_dirs is None:
            ignored_dirs = IGNORED_DIRS
        
        # If input is a path, read it; if bytes, use it
        if isinstance(self.data, str):
            with open(self.data, 'rb') as f:
                raw_bytes = f.read()
        else:
            raw_bytes = self.data

        extracted_files = []
        if not os.path.exists(self.extract_to):
            os.makedirs(self.extract_to)

        files = _extract_zip_logic(raw_bytes)
        for fname, content in files:
            # Re-verify ignored dirs just in case
            if any(ign in fname.lower() for ign in ignored_dirs):
                continue
            
            target_path = os.path.join(self.extract_to, fname)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            with open(target_path, 'wb') as f:
                f.write(content)
            extracted_files.append((target_path, fname))
            
        return extracted_files

# --- Modern Functional Interface ---

def _extract_zip_logic(raw_bytes: bytes) -> List[Tuple[str, bytes]]:
    """Internal logic to parse ZIP bytes and return file list."""
    results = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for info in zf.infolist():
                if info.filename.endswith("/") or any(ign in info.filename.lower() for ign in IGNORED_DIRS):
                    continue
                ext = os.path.splitext(info.filename)[1].lower()
                if ext not in ANALYSABLE_EXTENSIONS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    log.warning("SKIP %s (too large)", info.filename)
                    continue
                content_bytes = zf.read(info.filename)
                results.append((info.filename, content_bytes))
    except zipfile.BadZipFile:
        log.error("Invalid ZIP file uploaded.")
    return results

def extract_critical_patterns(raw_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Core of the Smart Analysis flow.
    Extracts high-score lines from the ZIP to batch them for Gemini.
    """
    patterns = []
    ext = os.path.splitext(filename)[1].lower()
    
    files = _extract_zip_logic(raw_bytes) if ext == ".zip" else [(filename, raw_bytes)]

    for fname, content_bytes in files:
        try:
            content = content_bytes.decode('utf-8', errors='ignore')
            lines = content.splitlines()
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if len(line) < 10:
                    continue
                score = get_score(line)
                if score >= 1:
                    patterns.append({
                        'filename': fname,
                        'line_number': line_num,
                        'pattern_text': line,
                        'score': score,
                        'entropy': calculate_entropy(line),
                        'type': 'code_line'
                    })
        except Exception as e:
            log.warning(f"Failed to process {fname}: {e}")

    patterns.sort(key=lambda p: p['score'], reverse=True)
    return patterns

# Compatibility export
extract_files_from_upload = _extract_zip_logic

__all__ = ["ZipExtractor", "extract_critical_patterns", "calculate_entropy", "get_score"]