# backend_ml/inference/zip_scanner.py
"""
ZIP Scanner - Smart extraction for CNN analysis
"""

import zipfile
import io
import os
import re
import math
from typing import List, Dict, Any, Tuple
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.zip")


class ZipExtractor:
    """Extract and analyze ZIP file contents"""
    
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.dat']
        self.code_extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.kt', '.swift', '.xml', '.json', '.html', '.htm', '.css']
        self.skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.mp3', '.mp4', '.wav', '.pdf', '.doc', '.docx', '.zip', '.tar', '.gz', '.pack', '.webp', '.woff', '.woff2', '.ttf', '.eot']
        
    def extract_zip(self, zip_bytes: bytes) -> List[Dict[str, Any]]:
        """Extract all files from ZIP and return metadata"""
        files = []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
                for info in zf.infolist():
                    if info.filename.endswith('/'):
                        continue
                    
                    try:
                        content = zf.read(info.filename)
                    except:
                        content = b''
                    
                    ext = os.path.splitext(info.filename)[1].lower()
                    
                    files.append({
                        'filename': info.filename,
                        'content': content,
                        'size': len(content),
                        'extension': ext,
                        'is_code': ext in self.code_extensions,
                        'is_suspicious': ext in self.suspicious_extensions,
                        'entropy': self.calculate_entropy(content)
                    })
        except Exception as e:
            logger.error(f"Failed to extract ZIP: {e}")
        
        return files
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy: -sum(p * log2(p))
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


# Create a global instance
_extractor = ZipExtractor()


def extract_files_for_cnn_smart(zip_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Smart extraction for CNN analysis - extracts only relevant files
    
    This is the main function that your main.py is trying to import
    """
    all_files = _extractor.extract_zip(zip_bytes)
    
    # Filter and prioritize files for CNN analysis
    analyzable_files = []
    suspicious_count = 0
    normal_count = 0
    
    print("\n" + "="*80)
    print(f"📁 SMART EXTRACTION FROM: {filename}")
    print("="*80)
    
    for file_info in all_files:
        filename_lower = file_info['filename'].lower()
        ext = file_info['extension']
        
        # Skip binary files that are not code
        if ext in _extractor.skip_extensions:
            print(f"   ⏭️ SKIPPED: {file_info['filename']} (extension: {ext})")
            continue
        
        # Skip very large files (> 5MB for performance)
        if file_info['size'] > 5 * 1024 * 1024:
            print(f"   ⏭️ SKIPPED: {file_info['filename']} (too large: {file_info['size']} bytes)")
            continue
        
        # Include code files and text files
        if ext in _extractor.code_extensions:
            print(f"   ✅ ANALYZABLE: {file_info['filename']} ({file_info['size']} bytes, entropy: {file_info['entropy']:.2f})")
            suspicious_count += 1
            analyzable_files.append({
                'filename': file_info['filename'],
                'content': file_info['content'],
                'entropy': file_info['entropy'],
                'size': file_info['size']
            })
        elif file_info['size'] < 50000 and _is_likely_text(file_info['content']):
            # Include text files even if not in code extensions
            print(f"   ✅ ANALYZABLE (no ext): {file_info['filename']} ({file_info['size']} bytes)")
            suspicious_count += 1
            analyzable_files.append({
                'filename': file_info['filename'],
                'content': file_info['content'],
                'entropy': file_info['entropy'],
                'size': file_info['size']
            })
        else:
            print(f"   ⏭️ SKIPPED: {file_info['filename']} (not analyzable)")
            normal_count += 1
    
    # Print summary
    print("\n" + "-"*80)
    print("📊 INTELLIGENT SAMPLING")
    print("-"*80)
    
    # Priority files (high entropy, small size)
    priority_files = [f for f in analyzable_files if f['entropy'] > 6.0 and f['size'] < 100000]
    normal_files = [f for f in analyzable_files if f not in priority_files]
    
    # Limit to 100 files total
    final_files = priority_files + normal_files
    if len(final_files) > 100:
        final_files = final_files[:100]
        print(f"   🎯 Intelligent sampling: {len(priority_files)} high priority, {len(normal_files[:100-len(priority_files)])} normal")
    else:
        print(f"   🎯 All {len(final_files)} files selected for analysis")
    
    # File type summary
    ext_summary = {}
    for f in all_files:
        ext = os.path.splitext(f['filename'])[1].lower() or '(no extension)'
        ext_summary[ext] = ext_summary.get(ext, 0) + 1
    
    print("\n" + "-"*80)
    print("📊 FILE TYPE SUMMARY:")
    for ext, count in sorted(ext_summary.items(), key=lambda x: -x[1])[:15]:
        print(f"   {ext}: {count} files")
    
    print("\n" + "-"*80)
    print("📊 EXTRACTION SUMMARY:")
    print(f"   Total files in ZIP: {len(all_files)}")
    print(f"   Suspicious files found: {suspicious_count}")
    print(f"   Normal files found: {normal_count}")
    print(f"   ✅ Total analyzable files: {len(final_files)} / {suspicious_count}")
    print(f"   📋 Analysis limit: 100 files")
    print("="*80 + "\n")
    
    return final_files


def extract_files_for_cnn(zip_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Alternative extraction function for CNN analysis
    """
    return extract_files_for_cnn_smart(zip_bytes, filename)


def extract_binary_files(zip_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Extract binary files (executables) for analysis
    """
    all_files = _extractor.extract_zip(zip_bytes)
    
    binary_files = []
    for file_info in all_files:
        ext = file_info['extension']
        if ext in ['.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.elf']:
            binary_files.append({
                'filename': file_info['filename'],
                'content': file_info['content'],
                'entropy': file_info['entropy'],
                'size': file_info['size']
            })
    
    return binary_files


def _is_likely_text(content: bytes) -> bool:
    """Check if content is likely text (not binary)"""
    if len(content) == 0:
        return True
    
    # Check first 2000 bytes
    sample = content[:min(2000, len(content))]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / len(sample) if sample else 1
    
    return ratio > 0.7


def is_text_content(content: bytes) -> bool:
    """Check if content is text (for compatibility with cnn_detector)"""
    return _is_likely_text(content)


# Export all required functions and classes
__all__ = [
    'ZipExtractor',
    'extract_files_for_cnn_smart',
    'extract_files_for_cnn',
    'extract_binary_files',
    'is_text_content'
]


if __name__ == "__main__":
    # Test the extractor
    import sys
    
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            zip_bytes = f.read()
        
        files = extract_files_for_cnn_smart(zip_bytes, sys.argv[1])
        
        print(f"\n📊 Final analyzable files: {len(files)}")
        for f in files[:10]:
            print(f"   - {f['filename']} ({f['size']} bytes, entropy: {f['entropy']:.2f})")
    else:
        print("Usage: python zip_scanner.py <zip_file>")