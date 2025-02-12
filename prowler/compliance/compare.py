import json

# Load the FedRAMP AWS and GCP JSON files
with open("aws/fedramp_low_revision_4_aws.json", "r") as f:
    fedramp_aws = json.load(f)

with open("gcp/fedramp_low_revision_4_gcp.json", "r") as f:
    fedramp_gcp = json.load(f)

# Create a dictionary mapping control ID to number of checks
aws_check_counts = {req["Id"]: len(req["Checks"]) for req in fedramp_aws["Requirements"]}
gcp_check_counts = {req["Id"]: len(req["Checks"]) for req in fedramp_gcp["Requirements"]}

# Identify controls with fewer checks in GCP than AWS
missing_checks = {control: aws_check_counts[control] - gcp_check_counts.get(control, 0)
                  for control in aws_check_counts if aws_check_counts[control] > gcp_check_counts.get(control, 0)}

# Print missing check counts
for control, missing_count in missing_checks.items():
    print(f"Control {control} is missing {missing_count} checks in GCP.")
