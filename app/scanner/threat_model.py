from typing import List, Dict
from app.models import Finding, IaCFinding, ThreatModel

STRIDE_MAP = {
    "SQL Injection": "Tampering",
    "Hardcoded Password": "Information Disclosure",
    "Open S3": "Information Disclosure",
    "Overly Permissive IAM": "Elevation of Privilege",
    "Unencrypted": "Information Disclosure",
    "Default": "Spoofing"
}

def build_threat_model(sast_findings: List[Finding], iac_findings: List[IaCFinding]) -> ThreatModel:
    stride_counts = {"Spoofing": 0, "Tampering": 0, "Repudiation": 0, "Information Disclosure": 0, "Denial of Service": 0, "Elevation of Privilege": 0}
    top_critical = []
    total_score = 0.0
    
    all_findings = sast_findings + iac_findings
    
    for f in all_findings:
        # Determine Category
        category = "Information Disclosure"
        text_to_check = f.issue_text.lower() if hasattr(f, 'issue_text') else f.check_id.lower()
        if "sql" in text_to_check: category = "Tampering"
        elif "iam" in text_to_check or "privilege" in text_to_check: category = "Elevation of Privilege"
        elif "dos" in text_to_check or "memory" in text_to_check: category = "Denial of Service"
        
        f.stride_category = category
        stride_counts[category] += 1
        
        # Calculate CVSS-inspired score
        severity = f.severity.upper()
        score = 8.5 if severity in ["HIGH", "CRITICAL", "ERROR"] else 5.0 if severity == "MEDIUM" else 2.5
        
        if hasattr(f, 'risk_score'):
            f.risk_score = score
        total_score += score
        
        if score > 7.0:
            top_critical.append({"issue": text_to_check[:100], "score": score, "category": category})

    top_critical = sorted(top_critical, key=lambda x: x["score"], reverse=True)[:5]
    
    mitigations = {
        "Tampering": ["Implement parameterized queries", "Validate input schema"],
        "Information Disclosure": ["Remove hardcoded secrets", "Enforce encryption at rest/transit"],
        "Elevation of Privilege": ["Apply Principle of Least Privilege to IAM/RBAC"]
    }
    
    return ThreatModel(
        total_risk_score=min(10.0, total_score / (len(all_findings) or 1) * 1.5), # Normalized pseudo-score
        findings_by_stride=stride_counts,
        top_critical=top_critical,
        mitigations=mitigations
    )