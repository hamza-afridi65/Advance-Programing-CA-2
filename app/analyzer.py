from datetime import datetime

def _parse_iso_time(ts):
    """Parse ISO time string to datetime, if possible."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def detect_suspicious_events(events):
    """
    Advanced rule-based detection on a list of CloudTrail events.
    Returns a list of alert dictionaries with embedded raw event.
    """
    alerts = []

    for event in events:
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")
        user_identity = event.get("userIdentity", {})
        user_type = user_identity.get("type", "Unknown")
        user_name = user_identity.get("userName", "Unknown")
        event_time = event.get("eventTime")
        aws_region = event.get("awsRegion", "Unknown")
        source_ip = event.get("sourceIPAddress", "Unknown")
        request_params = event.get("requestParameters", {}) or {}
        response_elements = event.get("responseElements", {}) or {}
        event_id = event.get("eventID", None)

        # Common base alert structure
        base_alert = {
            "user": user_name,
            "userType": user_type,
            "sourceIP": source_ip,
            "eventName": event_name,
            "eventSource": event_source,
            "eventTime": event_time,
            "awsRegion": aws_region,
            "eventId": event_id,
            "rawEvent": event,   # embed full event for forensic evidence
        }

        # ---------- RULE 1: Failed Console Login ----------
        if event_name == "ConsoleLogin":
            login_result = response_elements.get("ConsoleLogin")
            if login_result == "Failure":
                alert = {
                    **base_alert,
                    "rule": "Failed Console Login",
                    "description": "Console sign-in failure detected.",
                    "category": "Authentication",
                    "severity": "High",
                    "score": 70,
                }
                alerts.append(alert)

        # ---------- RULE 2: Root Account Activity ----------
        if user_type == "Root":
            alert = {
                **base_alert,
                "rule": "Root Account Activity",
                "description": "AWS root account was used.",
                "category": "Account Management",
                "severity": "Critical",
                "score": 95,
            }
            alerts.append(alert)

        # ---------- RULE 3: CloudTrail Logging Disabled ----------
        if event_source == "cloudtrail.amazonaws.com" and event_name in (
            "StopLogging",
            "DeleteTrail",
        ):
            alert = {
                **base_alert,
                "rule": "CloudTrail Logging Change",
                "description": "CloudTrail logging was stopped or a trail was deleted.",
                "category": "Monitoring Evasion",
                "severity": "Critical",
                "score": 90,
            }
            alerts.append(alert)

        # ---------- RULE 4: IAM Privilege Escalation Operations ----------
        if event_source == "iam.amazonaws.com" and event_name in (
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "PutUserPolicy",
            "AddUserToGroup",
        ):
            alert = {
                **base_alert,
                "rule": "IAM Privilege Change",
                "description": f"IAM operation '{event_name}' may indicate privilege escalation.",
                "category": "Privilege Escalation",
                "severity": "High",
                "score": 80,
            }
            alerts.append(alert)

        # ---------- RULE 5: Security Group Inbound 0.0.0.0/0 ----------
        if event_source == "ec2.amazonaws.com" and event_name in (
            "AuthorizeSecurityGroupIngress",
            "RevokeSecurityGroupIngress",
        ):
            ip_permissions = request_params.get("ipPermissions") or request_params.get(
                "IpPermissions"
            )  # depends on log format
            opened_to_world = False
            if isinstance(ip_permissions, list):
                for perm in ip_permissions:
                    for rng in perm.get("ipRanges", []) + perm.get(
                        "IpRanges", []
                    ):
                        cidr = rng.get("cidrIp") or rng.get("CidrIp")
                        if cidr == "0.0.0.0/0":
                            opened_to_world = True
                            break

            if opened_to_world:
                alert = {
                    **base_alert,
                    "rule": "Security Group Open to World",
                    "description": "Security group rule allows access from 0.0.0.0/0.",
                    "category": "Network Exposure",
                    "severity": "High",
                    "score": 85,
                }
                alerts.append(alert)

        # ---------- RULE 6: S3 Bucket Became Public ----------
        if event_source == "s3.amazonaws.com" and event_name in (
            "PutBucketAcl",
            "PutBucketPolicy",
        ):
            # Very simple heuristic: check for AllUsers / AuthenticatedUsers
            acl = request_params or {}
            acl_text = str(acl)
            if "AllUsers" in acl_text or "AuthenticatedUsers" in acl_text:
                alert = {
                    **base_alert,
                    "rule": "Public S3 Bucket Configuration",
                    "description": "S3 bucket ACL or policy may allow public access.",
                    "category": "Data Exposure",
                    "severity": "High",
                    "score": 85,
                }
                alerts.append(alert)

        # ---------- RULE 7: KMS Key Disabled or Scheduled for Deletion ----------
        if event_source == "kms.amazonaws.com" and event_name in (
            "DisableKey",
            "ScheduleKeyDeletion",
        ):
            alert = {
                **base_alert,
                "rule": "KMS Key Deactivated",
                "description": f"KMS key operation '{event_name}' detected.",
                "category": "Encryption",
                "severity": "Medium",
                "score": 65,
            }
            alerts.append(alert)

        # You can add more rules here: unusual region, high-rate API usage, etc.

    return alerts
