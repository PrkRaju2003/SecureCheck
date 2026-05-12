import subprocess
import json
import os
from typing import List
from app.models import Finding

def run_sast_scan(repo_path: str) -> List[Finding]:
    findings = []
    
    # Run Bandit
    bandit_cmd = ["bandit", "-f", "json", "-r", repo_path]
    try:
        result = subprocess.run(bandit_cmd, capture_output=True, text=True)
        if result.stdout:
            bandit_data = json.loads(result.stdout)
            for item in bandit_data.get("results", []):
                findings.append(Finding(
                    file=item.get("filename", ""),
                    line=item.get("line_number", 0),
                    severity=item.get("issue_severity", "LOW"),
                    confidence=item.get("issue_confidence", "LOW"),
                    issue_text=item.get("issue_text", ""),
                    cwe_id=str(item.get("issue_cwe", {}).get("id", "N/A"))
                ))
    except Exception as e:
        print(f"Bandit scan error: {e}")

    # Run Semgrep
    semgrep_cmd = ["semgrep", "scan", "--config", "p/python", "--json", repo_path]
    try:
        result = subprocess.run(semgrep_cmd, capture_output=True, text=True)
        if result.stdout:
            semgrep_data = json.loads(result.stdout)
            for item in semgrep_data.get("results", []):
                findings.append(Finding(
                    file=item.get("path", ""),
                    line=item.get("start", {}).get("line", 0),
                    severity=item.get("extra", {}).get("severity", "INFO"),
                    confidence="HIGH",
                    issue_text=item.get("extra", {}).get("message", ""),
                    cwe_id=str(item.get("extra", {}).get("metadata", {}).get("cwe", ["N/A"])[0])
                ))
    except Exception as e:
        print(f"Semgrep scan error: {e}")

    # Deduplicate by file + line
    unique_findings = {}
    for f in findings:
        key = f"{f.file}:{f.line}"
        if key not in unique_findings or unique_findings[key].severity == "LOW":
            unique_findings[key] = f

    return list(unique_findings.values())