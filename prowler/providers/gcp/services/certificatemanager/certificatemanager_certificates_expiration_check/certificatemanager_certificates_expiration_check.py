import datetime
from prowler.lib.check.models import Check, Check_Report_GCP, Severity
from prowler.providers.gcp.services.certificatemanager.certificatemanager_client import certificatemanager_client

class certificatemanager_certificates_expiration_check(Check):
    """
    Ensure that certificates managed by GCP Certificate Manager have a sufficient expiration period.
    
    For each certificate, calculate the number of days until expiration and compare it against a threshold 
    (default is 7 days, configurable via audit_config). If a certificate has already expired or is about to expire, 
    the check fails.
    
    If expire_time is empty and the certificate is managed (has a 'managed' field), it is considered automatically renewed.
    """

    def execute(self) -> list:
        findings = []
        # Retrieve the threshold from the audit configuration (default: 7 days)
        days_threshold = certificatemanager_client.audit_config.get("days_to_expire_threshold", 7)
        now = datetime.datetime.utcnow()  # Use UTC for consistency with GCP timestamps
        
        # Debug print (can be removed in production)
        print(f"certificates -> {certificatemanager_client.certificates}")
        
        for certificate in certificatemanager_client.certificates:
            report = Check_Report_GCP(self.metadata(), resource=certificate)
            
            # Handle empty expire_time: if the certificate is managed, assume it never expires.
            if not certificate.expire_time or certificate.expire_time.strip() == "":
                if certificate.managed:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Managed certificate {certificate.id} for {certificate.name} is automatically renewed and does not have an expiration time."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Certificate {certificate.id} for {certificate.name} does not have an expiration time configured."
                    )
                    report.check_metadata.Severity = Severity.critical
                findings.append(report)
                continue

            try:
                # Parse the certificate's expire_time (expecting ISO format)
                try:
                    expire_time = datetime.datetime.strptime(certificate.expire_time, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    expire_time = datetime.datetime.strptime(certificate.expire_time, "%Y-%m-%dT%H:%M:%SZ")
                expiration_days = (expire_time - now).days
            except Exception as e:
                # If parsing fails, mark the check as FAIL.
                expiration_days = -1
                report.status_extended = (
                    f"Certificate {certificate.id} for {certificate.name} has an unparseable expiration time."
                )
                report.status = "FAIL"
                report.check_metadata.Severity = Severity.critical
                findings.append(report)
                continue

            if expiration_days > days_threshold:
                report.status = "PASS"
                report.status_extended = (
                    f"Certificate {certificate.id} for {certificate.name} expires in {expiration_days} days."
                )
            else:
                report.status = "FAIL"
                if expiration_days < 0:
                    report.status_extended = (
                        f"Certificate {certificate.id} for {certificate.name} has expired ({abs(expiration_days)} days ago)."
                    )
                    report.check_metadata.Severity = Severity.high
                else:
                    report.status_extended = (
                        f"Certificate {certificate.id} for {certificate.name} is about to expire in {expiration_days} days."
                    )
                    report.check_metadata.Severity = Severity.medium
            findings.append(report)

        return findings
