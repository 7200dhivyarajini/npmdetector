import json

# Read the analysis result
with open('analysis_result.json', 'r') as f:
    data = json.load(f)

# Print the terminal output
print(f"[{data['verdict']}] | [{data['refined_risk_score']}] | [{data['primary_reason']}]")
