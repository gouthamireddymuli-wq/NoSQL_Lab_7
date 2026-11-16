"""
Monitor blueprint – /api/monitor
"""
from flask import Blueprint, jsonify
import datetime
import random

from config import db, reports_col, fix_doc

monitor_bp = Blueprint("monitor", __name__)

# Simulated "external" report titles that might appear on ctidigest.com
_SIMULATED_FEED = [
    {"report_id": "ext-001", "title": "APT29 Spearphishing Campaign Targets NATO Members", "published_date": "2024-11-10"},
    {"report_id": "ext-002", "title": "New IcedID Variant Uses DLL Side-Loading", "published_date": "2024-11-12"},
    {"report_id": "ext-003", "title": "LockBit 3.0 Infrastructure Takedown – Post-Mortem", "published_date": "2024-11-13"},
    {"report_id": "ext-004", "title": "Kimsuky Group Leverages CHM Files in Latest Wave", "published_date": "2024-11-14"},
    {"report_id": "ext-005", "title": "Zero-Day in Ivanti Connect Secure Exploited in Wild", "published_date": "2024-11-15"},
]


@monitor_bp.route("/api/monitor/cache-hit-ratio", methods=["GET"])
def cache_hit_ratio():
    try:
        status = db.command("serverStatus")
        cache = status.get("wiredTiger", {}).get("cache", {})
        pages_requested = cache.get("pages requested from the cache", 0)
        pages_read = cache.get("pages read into cache", 0)

        if pages_requested > 0:
            hit_ratio = round((pages_requested - pages_read) / pages_requested * 100, 4)
        else:
            hit_ratio = 0.0

        return jsonify({
            "cache_hit_ratio_pct": hit_ratio,
            "pages_requested": pages_requested,
            "pages_read_from_disk": pages_read,
            "cache_max_bytes": cache.get("maximum bytes configured", 0),
            "cache_used_bytes": cache.get("bytes currently in the cache", 0),
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@monitor_bp.route("/api/monitor/check-new-reports", methods=["POST"])
def check_new_reports():
    """
    Simulates Lab 7.2 monitoring activity:
    Checks simulated external feed for reports not yet stored in the DB,
    inserts new ones, and returns a summary.
    """
    inserted = []
    already_present = []

    for ext in _SIMULATED_FEED:
        exists = reports_col.find_one({"report_id": ext["report_id"]})
        if exists:
            already_present.append(ext["report_id"])
        else:
            new_doc = {
                "report_id": ext["report_id"],
                "title": ext["title"],
                "published_date": datetime.datetime.fromisoformat(ext["published_date"]),
                "source_url": f"https://ctidigest.com/reports/{ext['report_id']}",
                "author": "CTI Digest Bot",
                "summary": f"Auto-imported: {ext['title']}",
                "severity": random.choice(["medium", "high", "critical"]),
                "related_indicators": [],
                "tags": ["auto-import", "monitoring"],
                "tlp": "white",
                "created_at": datetime.datetime.utcnow()
            }
            reports_col.insert_one(new_doc)
            inserted.append(ext["report_id"])

    return jsonify({
        "checked": len(_SIMULATED_FEED),
        "newly_inserted": inserted,
        "already_present": already_present,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 201
