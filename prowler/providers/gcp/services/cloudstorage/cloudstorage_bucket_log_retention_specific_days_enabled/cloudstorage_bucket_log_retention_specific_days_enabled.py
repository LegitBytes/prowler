# File: prowler/providers/gcp/services/logging/gcp_logging_bucket_retention_policy_enabled.py

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import cloudstorage_client

class cloudstorage_bucket_log_retention_specific_days_enabled(Check):
    """
    Custom Check: Ensure that Cloud Logging buckets have a retention period
    of at least a specified number of days (default 90 days) to satisfy audit record retention requirements.
    
    This check iterates over all log buckets retrieved via the logging client.
    It marks the bucket as PASS if its retention policy (retentionDays) is configured and meets or exceeds
    the required threshold; otherwise, it returns FAIL.
    """

    def execute(self):
        findings = []
        
        # Retrieve the desired retention days from audit configuration; default to 90 days.
        specific_retention_days = logging_client.audit_config.get("log_bucket_retention_days", 90)
        
        # Iterate over each log bucket provided by the logging client
        for bucket in cloudstorage_client.buckets:
            # Create a report for each bucket.
            report = Check_Report_GCP(self.metadata(), resource=bucket)
            
            # Use the bucket's 'region' attribute
            report.region = bucket.region if hasattr(bucket, "region") else "global"
            # Set the resource ID; you can choose between bucket.id or bucket.name.
            report.resource_id = bucket.name  # Using bucket name as identifier.
            report.resource_arn = bucket.name  # GCP does not use ARNs, so we reuse the bucket name.
            
            # Check if a retention policy is configured; if not, report FAIL.
            if bucket.retention_policy:
                # Extract the retention period; default to 0 if the key is missing.
                retention = bucket.retention_policy.get("retentionDays", 0)
                if retention >= specific_retention_days:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Log bucket {bucket.name} retention policy is {retention} days, "
                        f"which meets the required {specific_retention_days} days."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Log bucket {bucket.name} retention policy is {retention} days, "
                        f"below the required {specific_retention_days} days."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = f"Log bucket {bucket.name} has no retention policy configured."
            
            findings.append(report)
        
        return findings
