# AI Agent for SAST Enhancement - Prototype Implementation

import openai
import json
import os

# --- CONFIGURATION ---
OPENAI_API_KEY = os.getenv("#######OPENAI_API_KEY#####")
openai.api_key = OPENAI_API_KEY

# --- VALIDATION MODULE ---
def validate_vulnerability(code_snippet, finding_description):
    prompt = f"""
You are a security expert AI agent.
Given the following code snippet and vulnerability description, validate if the vulnerability is real, reachable, and exploitable.

Code:
{code_snippet}

Finding:
{finding_description}

Respond with 'VALID' if it's a real issue or 'FALSE POSITIVE' otherwise. Provide a brief explanation.
"""

    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return response['choices'][0]['message']['content'].strip()

# --- PRIORITIZATION MODULE ---
def prioritize_finding(finding, metadata):
    base_severity = finding.get('severity', 'Medium')
    exposure = metadata.get('exposure', 'internal')
    critical_asset = metadata.get('critical_asset', False)

    score = 0
    if base_severity == 'Critical':
        score += 10
    elif base_severity == 'High':
        score += 8
    elif base_severity == 'Medium':
        score += 5

    if exposure == 'external':
        score += 5
    if critical_asset:
        score += 5

    if score >= 15:
        priority = 'P1 - Critical'
    elif score >= 10:
        priority = 'P2 - High'
    elif score >= 6:
        priority = 'P3 - Medium'
    else:
        priority = 'P4 - Low'

    return priority

# --- REMEDIATION SUGGESTION MODULE ---
def suggest_remediation(code_snippet, finding_description):
    prompt = f"""
You are a senior security engineer AI.
Given the following vulnerable code snippet and vulnerability description, suggest a secure fix.

Code:
{code_snippet}

Finding:
{finding_description}

Provide only the corrected code snippet and a 1-line explanation.
"""

    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return response['choices'][0]['message']['content'].strip()

# --- MAIN PROCESSOR ---
def process_sast_findings(raw_findings_json, codebase_context):
    results = []
    for finding in raw_findings_json['findings']:
        code_snippet = codebase_context.get(finding['file_path'], "")
        finding_description = finding['description']

        validation_result = validate_vulnerability(code_snippet, finding_description)

        if 'VALID' in validation_result:
            priority = prioritize_finding(finding, finding['metadata'])
            remediation = suggest_remediation(code_snippet, finding_description)

            results.append({
                "file": finding['file_path'],
                "finding": finding_description,
                "priority": priority,
                "remediation": remediation,
                "validation": validation_result
            })
    return results

# --- SAMPLE USAGE ---
if __name__ == "__main__":
    # Load sample findings
    with open("sample_sast_findings.json", "r") as f:
        raw_findings = json.load(f)

    # Load code context (in real system, pull from GitHub or local repo)
    codebase_context = {
        "src/payment_service.py": """
def process_payment(card_number, expiry_date):
    sql = f"SELECT * FROM cards WHERE number='{card_number}' AND expiry='{expiry_date}'"
    cursor.execute(sql)
"""
    }

    processed_results = process_sast_findings(raw_findings, codebase_context)

    # Output results
    print(json.dumps(processed_results, indent=2))
