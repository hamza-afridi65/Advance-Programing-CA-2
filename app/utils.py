from datetime import datetime, timedelta
from app.db import get_db


def store_alerts(alerts):
    """
    Store a list of alert dictionaries in MongoDB.
    Each alert already contains its rawEvent.
    """
    if not alerts:
        return

    db = get_db()

    # Enrich with ingestedAt timestamp
    for alert in alerts:
        if "ingestedAt" not in alert:
            alert["ingestedAt"] = datetime.utcnow()

    db.alerts.insert_many(alerts)


def get_recent_alerts(
    limit=None,          # CHANGED: default None = no limit
    severity=None,
    rule=None,
    hours_back=None,
    scan_id=None,        # supports per-scan filtering
):
    """
    Fetch recent alerts from MongoDB with optional filters:
    - severity: e.g. 'High', 'Critical'
    - rule: rule name string
    - hours_back: only alerts in the last N hours
    - scan_id: only alerts from a particular scan run
    - limit: max number of results (None = no limit)
    """
    db = get_db()
    query = {}

    if severity:
        query["severity"] = severity

    if rule:
        query["rule"] = rule

    if scan_id:
        query["scanId"] = scan_id

    if hours_back is not None:
        since = datetime.utcnow() - timedelta(hours=hours_back)
        query["ingestedAt"] = {"$gte": since}

    cursor = db.alerts.find(query).sort("ingestedAt", -1)

    if limit is not None:
        cursor = cursor.limit(limit)

    return list(cursor)
