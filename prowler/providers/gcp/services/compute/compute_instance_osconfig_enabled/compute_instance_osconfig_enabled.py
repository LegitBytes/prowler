from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client

class compute_instance_osconfig_enabled(Check):
    """
    Ensure that Compute Engine instances are managed by OS Config.
    
    OS Config is required for centralized patching, configuration management, and compliance.
    This check iterates over Compute Engine instances and verifies that the instance metadata
    contains the key 'enable-osconfig' set to "true".
    """

    def execute(self):
        findings = []

        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata(), resource=instance)
            report.region = instance.region if hasattr(instance, "region") else "global"
            report.resource_id = instance.name
            report.resource_arn = f"projects/{instance.project_id}/zones/{instance.region}/instances/{instance.name}"
            
            # Check if OS Config is enabled in instance metadata
            # We expect metadata to be a dictionary with key 'enable-osconfig'
            os_config_enabled = instance.metadata.get("enable-osconfig", "false").lower() == "true"

            if os_config_enabled:
                report.status = "PASS"
                report.status_extended = f"Instance {instance.name} has OS Config enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} does not have OS Config enabled."
            
            findings.append(report)

        return findings
