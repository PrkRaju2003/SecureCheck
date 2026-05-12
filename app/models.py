from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

class Finding(BaseModel):
    file: str
    line: int
    severity: str
    confidence: str
    issue_text: str
    cwe_id: str
    stride_category: str = "Unknown"
    risk_score: float = 0.0

class IaCFinding(BaseModel):
    check_id: str
    check_type: str
    resource: str
    severity: str
    file_path: str
    passed: bool
    stride_category: str = "Unknown"

class CloudFinding(BaseModel):
    resource_id: str
    resource_type: str
    region_or_location: str
    severity: str
    description: str
    stride_category: str = "Unknown"

class ThreatModel(BaseModel):
    total_risk_score: float
    findings_by_stride: Dict[str, int]
    top_critical: List[Dict]
    mitigations: Dict[str, List[str]]

class ScanResult(BaseModel):
    repo_path: str
    timestamp: str
    sast_findings: List[Finding]
    iac_findings: List[IaCFinding]
    cloud_findings: List[CloudFinding]
    threat_model: Optional[ThreatModel] = None