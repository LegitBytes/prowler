from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import cloudstorage_client

class cloudstorage_bucket_default_encryption(Check):
    def execute(self):
        findings = []
        
        for bucket in cloudstorage_client.buckets:
            # Ensure that the bucket's encryption details are populated.
            cloudstorage_client._get_bucket_encryption(bucket=bucket)
            report = Check_Report_GCP(self.metadata(), resource=bucket)
            
            # In GCP, if 'encryption' is not present, the bucket uses Google-managed encryption by default.
            if not bucket.encryption:
                report.status = "PASS"
                report.status_extended = f"Bucket {bucket.name} uses default Google-managed encryption."
            else:
                # If encryption is configured, verify that 'defaultKmsKeyName' is present and non-empty.
                if "defaultKmsKeyName" in bucket.encryption and bucket.encryption["defaultKmsKeyName"]:
                    report.status = "PASS"
                    report.status_extended = f"Bucket {bucket.name} is encrypted with customer-managed key {bucket.encryption['defaultKmsKeyName']}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Bucket {bucket.name} has an encryption configuration but 'defaultKmsKeyName' is missing."
            
            findings.append(report)
        return findings
