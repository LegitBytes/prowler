# Import the necessary Prowler base classes for GCP checks
from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import (
    iam_client
)

class iam_user_mfa_enabled_console_access(Check):
    """
    Custom Check: Ensure that multi-factor authentication (MFA) is enabled for all
    organizational (non-service) users in GCP.
    
    Note: In GCP, MFA for human users is typically enforced via Google Workspace or Cloud Identity.
    This check returns a MANUAL status and instructs the auditor to verify that MFA is configured
    in the organization’s identity provider.
    """
    
    def execute(self):
        findings = []
        report = Check_Report_GCP(self.metadata())
        
        # For this custom check, we mark the result as MANUAL
        report.region = "global"
        report.resource_id = "GCP-Organization"
        report.resource_arn = "N/A"
        report.status = "MANUAL"
        report.status_extended = (
            "Manual verification required: Confirm in your Google Workspace or Cloud Identity "
            "admin console that multi-factor authentication (MFA) is enabled for all non-service user accounts."
        )
        
        iam_client
        findings.append(report)
        return findings