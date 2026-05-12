import pytest
from unittest.mock import patch, MagicMock
import json
from app.models import Finding, IaCFinding
from app.scanner.sast import run_sast_scan
from app.scanner.iac_auditor import run_iac_scan
from app.scanner.threat_model import build_threat_model

# --- Mock Data ---

MOCK_BANDIT_OUTPUT = {
    "results": [
        {
            "filename": "app.py",
            "line_number": 10,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "Hardcoded password detected",
            "issue_cwe": {"id": "259"}
        }
    ]
}

MOCK_CHECKOV_OUTPUT = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "resource": "aws_s3_bucket.my_bucket",
                "file_path": "/main.tf"
            }
        ]
    }
}

# --- Tests ---

@patch("app.scanner.sast.subprocess.run")
def test_run_sast_scan(mock_run):
    # Setup mock to return dummy Bandit JSON for the first call, and empty for Semgrep
    mock_run.side_effect = [
        MagicMock(stdout=json.dumps(MOCK_BANDIT_OUTPUT), returncode=0), # Bandit call
        MagicMock(stdout=json.dumps({"results": []}), returncode=0)      # Semgrep call
    ]
    
    findings = run_sast_scan("./dummy_path")
    
    assert len(findings) == 1
    assert findings[0].file == "app.py"
    assert findings[0].severity == "HIGH"
    assert findings[0].cwe_id == "259"
    assert mock_run.call_count == 2

@patch("app.scanner.iac_auditor.subprocess.run")
def test_run_iac_scan(mock_run):
    # Setup mock to return dummy Checkov JSON
    mock_run.return_value = MagicMock(stdout=json.dumps(MOCK_CHECKOV_OUTPUT), returncode=1)
    
    findings = run_iac_scan("./dummy_path")
    
    assert len(findings) == 1
    assert findings[0].check_id == "CKV_AWS_20"
    assert findings[0].resource == "aws_s3_bucket.my_bucket"
    assert findings[0].passed is False
    assert findings[0].severity == "HIGH" # CKV_AWS_20 triggers the CRITICAL/HIGH flag

def test_build_threat_model():
    # Provide pure Python objects, no mocking required
    sast_findings = [
        Finding(
            file="app.py", line=12, severity="HIGH", confidence="HIGH",
            issue_text="SQL Injection vulnerability found in user input", cwe_id="89"
        )
    ]
    iac_findings = [
        IaCFinding(
            check_id="CKV_AWS_1", check_type="terraform", resource="aws_iam_policy.admin",
            severity="MEDIUM", file_path="/main.tf", passed=False
        )
    ]
    
    tm = build_threat_model(sast_findings, iac_findings)
    
    # Assert STRIDE categorization worked based on keywords
    assert tm.findings_by_stride["Tampering"] == 1 # SQL Injection maps to Tampering
    assert tm.findings_by_stride["Information Disclosure"] == 1 # Fallback/IAM maps here or Elevation of Privilege depending on text
    
    # Assert Risk Score is calculated
    assert tm.total_risk_score > 0.0
    
    # Assert top critical lists the SQL injection
    assert len(tm.top_critical) > 0
    assert "sql" in tm.top_critical[0]["issue"].lower()