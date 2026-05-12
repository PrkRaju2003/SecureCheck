import argparse
import sys
import json
import os
from datetime import datetime
from app.scanner.sast import run_sast_scan
from app.scanner.iac_auditor import run_iac_scan
from app.scanner.threat_model import build_threat_model
from app.cloud.aws_audit import run_aws_audit
from app.cloud.azure_audit import run_azure_audit
from app.models import ScanResult

def main():
    parser = argparse.ArgumentParser(description="SecureFlow CLI Scanner")
    parser.add_argument("--path", default=".", help="Path to scan")
    args = parser.parse_args()

    print(f"Starting SecureFlow Scan on {args.path}...")
    
    sast = run_sast_scan(args.path)
    iac = run_iac_scan(args.path)
    # Cloud audit might fail in CI without creds, so we catch errors or use mock if specified
    cloud_aws = []
    cloud_az = []
    if os.environ.get("SECUREFLOW_MOCK") == "true":
        cloud_aws = run_aws_audit()
        cloud_az = run_azure_audit()

    threat_model = build_threat_model(sast, iac)
    
    result = ScanResult(
        repo_path=args.path,
        timestamp=datetime.now().isoformat(),
        sast_findings=sast,
        iac_findings=iac,
        cloud_findings=cloud_aws + cloud_az,
        threat_model=threat_model
    )

    # Check for HIGH/CRITICAL
    high_findings = [f for f in sast + iac if f.severity.upper() in ["HIGH", "CRITICAL"]]
    
    print(f"Scan Complete. Found {len(sast)} SAST, {len(iac)} IaC findings.")
    
    if high_findings:
        print(f"!!! FAILURE: {len(high_findings)} HIGH/CRITICAL vulnerabilities detected !!!")
        for f in high_findings[:5]:
            msg = getattr(f, 'issue_text', getattr(f, 'check_id', 'Unknown'))
            print(f" - [{f.severity}] {msg}")
        sys.exit(1)
    else:
        print("Success: No HIGH/CRITICAL vulnerabilities found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
