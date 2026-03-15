"""
Standalone Python test script to verify the malware detection engine without using the Streamlit UI.
This script acts as a 'headless' version of the app to verify that Task 1, 2, and 3 are working together.

Execution Flow:
1. Load malicious-packages.zip into memory using io.BytesIO
2. Call get_detailed_scan from backend_ml/feature_extraction/npm_detector.py
3. Call run_ai_analysis (get_gemini_analysis) from backend_ml/feature_extraction/gemini_audit.py
4. Print formatted summary to console
5. Save final dictionary as scan_report.json
"""

import io
import json
import os
import tempfile

# Import the detection functions
from backend_ml.feature_extraction.npm_detector import get_detailed_scan
from backend_ml.feature_extraction.groq_audit import get_gemini_analysis


def main():
    """
    Main function to run the headless malware detection scan.
    """
    print("=" * 80)
    print("MALICIOUS NPM DETECTOR - HEADLESS SCAN")
    print("=" * 80)
    print()

    # Path to the malicious-packages.zip file
    zip_path = "malicious-packages.zip"
    
    # Check if the ZIP file exists
    if not os.path.exists(zip_path):
        print(f"ERROR: {zip_path} not found in the current directory!")
        print(f"Current directory: {os.getcwd()}")
        return
    
    print(f"[*] Loading {zip_path} into memory using io.BytesIO...")
    
    # Load the ZIP file into memory using io.BytesIO
    with open(zip_path, 'rb') as f:
        zip_bytes = f.read()
    
    # Create BytesIO object
    zip_buffer = io.BytesIO(zip_bytes)
    
    print(f"[*] ZIP file loaded into memory. Size: {len(zip_bytes)} bytes")
    print()
    
    # Write the bytes to a temporary file since get_detailed_scan expects a file path
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
        temp_zip.write(zip_bytes)
        temp_zip_path = temp_zip.name
    
    print(f"[*] Temporary file created: {temp_zip_path}")
    print()
    
    try:
        # ============================================
        # TASK 1 & 2: Feature Extraction & Recursive Scanning
        # ============================================
        print("-" * 80)
        print("TASK 1 & 2: FEATURE EXTRACTION & RECURSIVE SCANNING")
        print("-" * 80)
        print()
        
        # Call get_detailed_scan from npm_detector.py
        print("[*] Running get_detailed_scan()...")
        detailed_scan_result = get_detailed_scan(temp_zip_path)
        
        # Extract key information
        risk_score = detailed_scan_result.get('risk_score', 0)
        total_files = detailed_scan_result.get('total_files_scanned', 0)
        suspicious_files = detailed_scan_result.get('suspicious_files_found', 0)
        jquery_critical = detailed_scan_result.get('jquery_critical', False)
        heuristic_findings = detailed_scan_result.get('heuristic_findings', {})
        
        print(f"    Total files found in ZIP: {total_files}")
        print(f"    Suspicious files found: {suspicious_files}")
        print(f"    Heuristic Risk Score: {risk_score:.4f}")
        
        # Highlight jQuery Trojan if triggered
        if jquery_critical:
            print()
            print("    *** CRITICAL: jQuery Trojan detected! ***")
            print("    The jquery.js file contains dangerous patterns (exec/spawn/child_process)")
        
        print()
        
        # ============================================
        # TASK 3: Gemini AI Analysis
        # ============================================
        print("-" * 80)
        print("TASK 3: GEMINI 2.0 AI FORENSIC ANALYSIS")
        print("-" * 80)
        print()
        
        # Call get_gemini_analysis (run_ai_analysis) from gemini_audit.py
        print("[*] Running get_gemini_analysis() with Gemini 2.0 Flash...")
        ai_analysis = get_gemini_analysis(heuristic_findings, risk_score)
        
        # Extract AI analysis results
        ai_risk_level = ai_analysis.get('risk_level', 'Unknown')
        ai_score = ai_analysis.get('score', 0)
        ai_reasoning = ai_analysis.get('reasoning', 'No reasoning provided')
        ai_remedy_steps = ai_analysis.get('remedy_steps', [])
        
        print(f"    AI Risk Level: {ai_risk_level}")
        print(f"    AI Score: {ai_score}/100")
        print()
        print("    Gemini 2.0 AI Forensic Reasoning:")
        print(f"    {ai_reasoning}")
        print()
        
        if ai_remedy_steps:
            print("    Recommended Remedy Steps:")
            for i, step in enumerate(ai_remedy_steps, 1):
                print(f"        {i}. {step}")
        
        print()
        
        # ============================================
        # Build Final Result Dictionary
        # ============================================
        final_result = {
            'scan_metadata': {
                'zip_file': zip_path,
                'zip_size_bytes': len(zip_bytes),
                'scan_type': 'headless'
            },
            'detailed_scan': detailed_scan_result,
            'ai_analysis': ai_analysis,
            'summary': {
                'total_files_found': total_files,
                'heuristic_risk_score': risk_score,
                'jquery_trojan_triggered': jquery_critical,
                'ai_risk_level': ai_risk_level,
                'ai_score': ai_score
            }
        }
        
        # ============================================
        # Save to scan_report.json
        # ============================================
        output_file = 'scan_report.json'
        print("-" * 80)
        print("SAVING RESULTS")
        print("-" * 80)
        print()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_result, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Results saved to {output_file}")
        print()
        
        # ============================================
        # Print Final Summary
        # ============================================
        print("=" * 80)
        print("FINAL SUMMARY")
        print("=" * 80)
        print()
        print(f"  Total Files Found in ZIP:    {total_files}")
        print(f"  Heuristic Risk Score:        {risk_score:.4f}")
        
        if jquery_critical:
            print(f"  jQuery Trojan Triggered:     YES (CRITICAL)")
        else:
            print(f"  jQuery Trojan Triggered:     No")
        
        print()
        print(f"  Gemini AI Risk Level:        {ai_risk_level}")
        print(f"  Gemini AI Score:            {ai_score}/100")
        print()
        print(f"  Results saved to:            {output_file}")
        print()
        print("=" * 80)
        print("SCAN COMPLETE")
        print("=" * 80)
        
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_zip_path):
            os.unlink(temp_zip_path)
            print(f"[*] Temporary file cleaned up: {temp_zip_path}")


if __name__ == "__main__":
    main()
