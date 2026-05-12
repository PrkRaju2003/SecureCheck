# app/cloud/azure_audit.py
import os
from typing import List
from app.models import CloudFinding
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.authorization import AuthorizationManagementClient
except ImportError:
    pass

def run_azure_audit() -> List[CloudFinding]:
    if os.environ.get("SECUREFLOW_MOCK", "false").lower() == "true":
        return [
            CloudFinding(resource_id="/subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.Storage/storageAccounts/sa1", resource_type="Blob Storage", region_or_location="eastus", severity="HIGH", description="Blob public access enabled", stride_category="Information Disclosure")
        ]
    
    findings = []
    try:
        credential = DefaultAzureCredential()
        subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            return []

        # Storage Audit
        storage_client = StorageManagementClient(credential, subscription_id)
        for account in storage_client.storage_accounts.list():
            if account.allow_blob_public_access is not False:
                findings.append(CloudFinding(
                    resource_id=account.id, resource_type="Blob Storage",
                    region_or_location=account.location, severity="HIGH",
                    description="Blob Storage allows public access",
                    stride_category="Information Disclosure"
                ))

        # AKS Audit
        aks_client = ContainerServiceClient(credential, subscription_id)
        for cluster in aks_client.managed_clusters.list():
            if not cluster.enable_rbac:
                findings.append(CloudFinding(
                    resource_id=cluster.id, resource_type="AKS",
                    region_or_location=cluster.location, severity="CRITICAL",
                    description="AKS RBAC is disabled",
                    stride_category="Elevation of Privilege"
                ))

    except Exception as e:
        print(f"Azure Audit Error: {e}")
        
    return findings