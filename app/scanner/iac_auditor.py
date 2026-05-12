import subprocess
import json
from typing import List
from app.models import IaCFinding

def run_iac_scan(repo_path: str) -> List[IaCFinding]:
    findings = []
    checkov_cmd = ["checkov", "-d", repo_path, "-o", "json"]
    
    try:
        result = subprocess.run(checkov_cmd, capture_output=True, text=True)
        # Checkov returns a list if multiple frameworks exist, or dict
        data = json.loads(result.stdout) if result.stdout else []
        if isinstance(data, dict):
            data = [data]
            
        for framework_res in data:
            results = framework_res.get("results", {})
            failed_checks = results.get("failed_checks", [])
            for check in failed_checks:
                check_id = check.get("check_id", "UNKNOWN")
                findings.append(IaCFinding(
                    check_id=check_id,
                    check_type=framework_res.get("check_type", "terraform"),
                    resource=check.get("resource", "unknown"),
                    severity="HIGH" if any(crit in check_id.upper() for crit in ["CKV_AWS_20", "CKV_AWS_19", "CKV_AWS_3"]) else "MEDIUM",
                    file_path=check.get("file_path", ""),
                    passed=False
                ))
    except Exception as e:
        print(f"Checkov scan error: {e}")
        
    return findings