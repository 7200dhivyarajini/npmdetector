import os
import json

# Use College-ERP.zip from Downloads
zip_path = '../../Downloads/College-ERP.zip'
if os.path.exists(zip_path):
    print(f'Found: {zip_path}')
    
    # Run scan
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
    
    # Save result.json
    with open('result.json', 'w') as f:
        json.dump(verdict, f, indent=2)
    
    # Save analysis.json
    with open('analysis.json', 'w') as f:
        json.dump(result, f, indent=2)
    
    print('Files saved!')
else:
    print('No zip file found')
