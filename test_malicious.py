import os
import json

# Test with malicious-package1.zip
zip_path = '../../Downloads/malicious-package1.zip'
if os.path.exists(zip_path):
    print(f'Found: {zip_path}')
    
    from backend_ml.feature_extraction.npm_detector import get_forensic_scan, get_verdict
    
    result = get_forensic_scan(zip_path)
    total_files = result['summary']['total_files_scanned']
    total_matches = result['summary']['total_matches']
    print(f'Scanned {total_files} files')
    print(f'Found {total_matches} matches')
    
    verdict = get_verdict(result['raw_matches'], zip_path, total_files)
    print(f'Verdict: {verdict["verdict"]}')
    print(f'Density: {verdict["density"]}')
    print(f'Reasoning: {verdict["reasoning"]}')
    
    # Check for goat/simulation in paths
    for m in result['raw_matches'][:10]:
        print(f"  File: {m.get('filepath')}")
else:
    print('No zip file found')
