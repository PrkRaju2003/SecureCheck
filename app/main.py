from fastapi import FastAPI
from datetime import datetime
import os
from app.models import ScanResult
from app.scanner.sast import run_sast_scan
from app.scanner.iac_auditor import run_iac_scan
from app.scanner.threat_model import build_threat_model
from app.cloud.aws_audit import run_aws_audit
from app.cloud.azure_audit import run_azure_audit
from app.report.generator import generate_reports

app = FastAPI(title="SecureFlow API")

@app.get("/")
def health_check():
    return {"status": "SecureFlow Core Online"}

@app.post("/scan", response_model=ScanResult)
def trigger_scan(target_path: str = "./sample_repo"):
    sast = run_sast_scan(target_path)
    iac = run_iac_scan(target_path)
    cloud_aws = run_aws_audit()
    cloud_az = run_azure_audit()
    
    threat_model = build_threat_model(sast, iac)
    
    result = ScanResult(
        repo_path=target_path,
        timestamp=datetime.now().isoformat(),
        sast_findings=sast,
        iac_findings=iac,
        cloud_findings=cloud_aws + cloud_az,
        threat_model=threat_model
    )
    
    # Ensure reports directory exists
    os.makedirs("./reports", exist_ok=True)
    generate_reports(result, "./reports")
    
    return result