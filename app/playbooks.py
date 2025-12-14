PLAYBOOKS = {
    "Failed Console Login": {
        "title": "Failed Console Login",
        "risk": "Brute-force attempt or credential stuffing.",
        "actions": [
            "Check if the IP appears in multiple failures across accounts.",
            "Verify MFA status for the user and enforce MFA if missing.",
            "Temporarily block suspicious IPs (WAF / security tooling).",
            "Review CloudTrail for successful ConsoleLogin after failures.",
            "Reset credentials if compromise is suspected."
        ]
    },
    "Root Account Activity": {
        "title": "Root Account Activity",
        "risk": "Root usage should be extremely rare; high impact actions possible.",
        "actions": [
            "Confirm the action was approved and expected (change request).",
            "Check if MFA is enabled on root and validate it was used.",
            "Review the source IP and geolocation, compare to normal admin locations.",
            "Rotate root credentials and access keys if any exist.",
            "Enable alerts/guardrails for root activity and restrict use."
        ]
    },
    "IAM Privilege Change": {
        "title": "IAM Privilege Change",
        "risk": "Privilege escalation / persistence via new admin permissions.",
        "actions": [
            "Identify who performed the change and from where (source IP).",
            "Review the policy attached (AdministratorAccess is critical).",
            "Check for newly created users/keys and disable if suspicious.",
            "Audit recent IAM changes (CreateUser, AttachUserPolicy, PutUserPolicy).",
            "Apply least-privilege and require approval workflows."
        ]
    },
    "Public S3 Bucket Configuration": {
        "title": "Public S3 Bucket Configuration",
        "risk": "Data exposure risk via public ACL/policy.",
        "actions": [
            "Check bucket policy/ACL and remove public grants immediately.",
            "Enable S3 Block Public Access at account and bucket level.",
            "Review access logs / CloudTrail for GetObject requests.",
            "Classify the data and assess breach impact if sensitive.",
            "Add automated policy checks (Config rules / CSPM)."
        ]
    },
    "Security Group Open to World": {
        "title": "Security Group Open to World",
        "risk": "Unrestricted inbound access to ports (e.g., SSH/RDP).",
        "actions": [
            "Identify which port was opened (22/3389 are high risk).",
            "Restrict source CIDR to VPN / office IP ranges.",
            "Check if instance is internet-facing and has public IP.",
            "Review instance access logs (SSH/RDP) for suspicious attempts.",
            "Add guardrails: IaC checks, AWS Config, SCP policies."
        ]
    },
    "CloudTrail Logging Change": {
        "title": "CloudTrail Logging Change",
        "risk": "Defense evasion by disabling auditing.",
        "actions": [
            "Re-enable CloudTrail immediately and lock down permissions.",
            "Identify who stopped/modified logging and investigate source IP.",
            "Check for suspicious actions during logging gap.",
            "Use AWS Organizations SCP to prevent disabling trails.",
            "Enable multi-region trails and log file validation."
        ]
    },
    "KMS Key Deactivated": {
        "title": "KMS Key Deactivated",
        "risk": "Service disruption or data access denial / ransomware pattern.",
        "actions": [
            "Identify impacted resources using the key (EBS, S3, RDS, etc.).",
            "Re-enable key if unauthorized and rotate where appropriate.",
            "Review CloudTrail for DisableKeyScheduleDeleteKey events.",
            "Restrict KMS admin permissions and require approvals.",
            "Investigate for broader compromise indicators."
        ]
    }
}

def get_playbook(rule_name: str):
    return PLAYBOOKS.get(rule_name)
