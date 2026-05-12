import os
import boto3
from typing import List
from app.models import CloudFinding

def run_aws_audit() -> List[CloudFinding]:
    if os.environ.get("SECUREFLOW_MOCK", "false").lower() == "true":
        return [
            CloudFinding(resource_id="arn:aws:s3:::customer-data-bucket", resource_type="S3", region_or_location="us-east-1", severity="HIGH", description="Public Access Block is disabled", stride_category="Information Disclosure"),
            CloudFinding(resource_id="arn:aws:iam::123456789:policy/admin", resource_type="IAM", region_or_location="global", severity="CRITICAL", description="Policy contains *:* actions", stride_category="Elevation of Privilege")
        ]
    
    findings = []
    try:
        # S3 Audit
        s3 = boto3.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab.get('PublicAccessBlockConfiguration', {})
                if not all(config.values()):
                    findings.append(CloudFinding(
                        resource_id=f"arn:aws:s3:::{name}", resource_type="S3",
                        region_or_location="us-east-1", severity="HIGH",
                        description="S3 Public Access Block not fully enabled",
                        stride_category="Information Disclosure"
                    ))
            except Exception:
                # Often means no configuration exists, which is a finding
                findings.append(CloudFinding(
                    resource_id=f"arn:aws:s3:::{name}", resource_type="S3",
                    region_or_location="us-east-1", severity="HIGH",
                    description="S3 Public Access Block is disabled",
                    stride_category="Information Disclosure"
                ))

        # EC2 Audit
        ec2 = boto3.client('ec2')
        sgs = ec2.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            for perm in sg.get('IpPermissions', []):
                from_port = perm.get('FromPort')
                to_port = perm.get('ToPort')
                if from_port in [22, 3389] or (from_port and from_port <= 22 <= to_port):
                    for range in perm.get('IpRanges', []):
                        if range.get('CidrIp') == '0.0.0.0/0':
                            findings.append(CloudFinding(
                                resource_id=sg['GroupId'], resource_type="EC2 Security Group",
                                region_or_location="us-east-1", severity="CRITICAL",
                                description=f"Port {from_port} open to the world",
                                stride_category="Information Disclosure"
                            ))

        # IAM Audit
        iam = boto3.client('iam')
        policies = iam.list_policies(Scope='Local').get('Policies', [])
        for policy in policies:
            version = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
            statements = version['PolicyVersion']['Document'].get('Statement', [])
            if isinstance(statements, dict): statements = [statements]
            for stmt in statements:
                if stmt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                    findings.append(CloudFinding(
                        resource_id=policy['Arn'], resource_type="IAM Policy",
                        region_or_location="global", severity="CRITICAL",
                        description="Policy contains *:* (Administrator) privileges",
                        stride_category="Elevation of Privilege"
                    ))

    except Exception as e:
        print(f"AWS Audit Error: {e}")
        
    return findings

