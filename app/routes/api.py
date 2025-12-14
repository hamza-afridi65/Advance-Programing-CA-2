from flask import Blueprint, jsonify, request, session
from datetime import datetime
import uuid

from app.scanner import read_cloudtrail_logs
from app.analyzer import detect_suspicious_events
from app.utils import store_alerts, get_recent_alerts
from app.aws_ingestion import read_cloudtrail_from_s3
from app.playbooks import get_playbook 

api_bp = Blueprint("api", __name__)


def require_login():
    """
    Simple session-based guard for API routes.
    """
    if not session.get("user"):
        return jsonify({"error": "Unauthorized"}), 401
    return None


@api_bp.route("/scan", methods=["POST"])
def scan_logs():
    """
    Trigger scanning of CloudTrail logs in the sample_logs folder,
    analyze them, store alerts in MongoDB, and return count + scanId.
    """
    guard = require_login()
    if guard:
        return guard

    events = read_cloudtrail_logs()
    alerts = detect_suspicious_events(events)

    # Tag this batch with a unique scanId
    scan_id = str(uuid.uuid4())
    for alert in alerts:
        alert["scanId"] = scan_id

    store_alerts(alerts)

    return jsonify({
        "status": "success",
        "alerts_detected": len(alerts),
        "scanId": scan_id
    })


@api_bp.route("/scan_s3", methods=["POST"])
def scan_s3_logs():
    """
    Trigger scanning of CloudTrail logs from S3,
    analyze them, store alerts in MongoDB, and return count + scanId.
    """
    guard = require_login()
    if guard:
        return guard

    events = read_cloudtrail_from_s3()
    alerts = detect_suspicious_events(events)

    # Tag this batch with a unique scanId
    scan_id = str(uuid.uuid4())
    for alert in alerts:
        alert["scanId"] = scan_id

    store_alerts(alerts)

    return jsonify({
        "status": "success",
        "alerts_detected": len(alerts),
        "scanId": scan_id
    })


def _serialize_alert(alert):
    """
    Convert MongoDB document to something JSON-safe:
    - ObjectId -> str
    - datetime -> ISO string
    Also attaches a playbook (if rule matches one).
    """
    data = dict(alert)

    # ObjectId -> string
    if "_id" in data:
        data["_id"] = str(data["_id"])

    # datetime -> ISO string
    ia = data.get("ingestedAt")
    if isinstance(ia, datetime):
        data["ingestedAt"] = ia.isoformat()

    # Attach playbook (derived at view time; not required in DB)
    pb = get_playbook(data.get("rule", ""))
    if pb:
        data["playbook"] = pb

    return data


@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """
    Return recent alerts from MongoDB as JSON.
    Optional query params:
      - severity (e.g. High, Critical)
      - rule (exact rule name)
      - hours_back (int)
      - scan_id (alerts belonging to a specific scan run)
    """
    guard = require_login()
    if guard:
        return guard

    severity = request.args.get("severity")
    rule = request.args.get("rule")
    hours_back = request.args.get("hours_back")
    scan_id = request.args.get("scan_id")

    try:
        hours_back = int(hours_back) if hours_back is not None else None
    except ValueError:
        hours_back = None

    alerts = get_recent_alerts(
        severity=severity,
        rule=rule,
        hours_back=hours_back,
        scan_id=scan_id,
    )

    serialized = [_serialize_alert(a) for a in alerts]
    return jsonify(serialized)
