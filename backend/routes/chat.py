"""
Flask Blueprint: AI Threat Intelligence Chatbot & Autonomous Scanner Bot
=============================================================================
Endpoints:
- POST /api/chat               : Core RAG Chat endpoint with conversational scanner bot
- GET  /api/chat/history       : Fetch session history from MongoDB
- POST /api/chat/clear         : Clear session history
- POST /api/chat/ingest        : Ingest & embed threat advisories into MongoDB
- GET  /api/chat/threats       : Catalog of Anticipated, Active, Evolving & Resolved threats
- GET  /api/chat/categories    : Summary statistics by Platform and Threat Lifecycle
- POST /api/chat/scan          : Trigger background vulnerability scanner
- GET  /api/chat/scan/status   : Inspect host vulnerability posture
- POST /api/chat/mitigate      : Confirm and execute safe mitigation procedure
=============================================================================
"""

import re
import datetime
from flask import Blueprint, jsonify, request

from services.threat_data import COMPREHENSIVE_THREATS
from services.threat_llm_service import (
    execute_chat,
    ingest_threat_documents,
    retrieve_context,
    get_db
)
from services.scanner_bot import bot_instance

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")

# Seed initial threat knowledge on module import if empty
def _ensure_initial_ingestion():
    try:
        db = get_db()
        col = db["document_chunks"]
        if col.count_documents({}) == 0:
            ingest_threat_documents(COMPREHENSIVE_THREATS)
    except Exception as e:
        print("[Chat Service] Initial vector ingestion deferred:", e)

_ensure_initial_ingestion()

# Start autonomous background scanner
bot_instance.start_background_service()


# ---------------------------------------------------------------------------
# POST /api/chat - RAG Chat with Conversational Confirmation Scanner Bot
# ---------------------------------------------------------------------------
@chat_bp.route("", methods=["POST"])
def chat_endpoint():
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id", "session-default")
    message = (payload.get("message") or "").strip()
    platform = payload.get("platform")
    threat_status = payload.get("threat_status")
    top_k = int(payload.get("top_k", 3))

    if not message:
        return jsonify({"error": "Message content cannot be empty"}), 400

    msg_lower = message.lower()

    # --- 1. Conversational Scanner Bot: Trigger Scan Intent ---
    if any(k in msg_lower for k in ["scan system", "run scan", "scan host", "scan project", "check vulnerabilities", "scan platform"]):
        scan_res = bot_instance.run_full_scan(target_scope="system-wide", target_platform=platform)
        vulns = scan_res.get("vulnerabilities", [])
        
        if not vulns:
            bot_reply = (
                f"### 🛡️ System Vulnerability Audit Completed\n\n"
                f"**Target Host:** `{scan_res['platform']}` | **Open Ports:** `{scan_res['open_ports_detected']}`\n\n"
                f"✅ **No unmitigated security vulnerabilities identified.** Host posture is compliant with baseline security controls."
            )
        else:
            vuln_list_md = "\n".join([
                f"- **`{v['vuln_id']}`** ({v['severity'].upper()}) — **{v['title']}**\n  _{v['description']}_"
                for v in vulns
            ])
            bot_reply = (
                f"### ⚠️ Autonomous Vulnerability Scan Results\n\n"
                f"**Audited Platform:** `{scan_res['platform']}` | **Timestamp:** `{scan_res['timestamp']}`\n"
                f"**Active Listening Ports:** `{scan_res['open_ports_detected']}`\n"
                f"**Identified Vulnerabilities ({len(vulns)}):**\n\n"
                f"{vuln_list_md}\n\n"
                f"---\n"
                f"**⚠️ Action Required — Conversational Confirmation:**\n"
                f"Would you like me to apply the mitigation procedures to resolve these security findings?\n\n"
                f"👉 Reply **'Confirm mitigate all'** to remediate all findings, or **'Confirm mitigate [VULN-ID]'** (e.g., `Confirm mitigate {vulns[0]['vuln_id']}`)."
            )

        # Persist conversation turn
        db = get_db()
        db["sessions"].update_one(
            {"session_id": session_id},
            {"$push": {"history": {
                "$each": [
                    {"role": "user", "content": message, "timestamp": datetime.datetime.utcnow().isoformat()},
                    {"role": "assistant", "content": bot_reply, "timestamp": datetime.datetime.utcnow().isoformat()}
                ]
            }}},
            upsert=True
        )

        return jsonify({
            "session_id": session_id,
            "response": bot_reply,
            "sources": [{"source": "Autonomous Threat Scanner Bot", "score": 1.0, "platform": scan_res['platform'], "status": "Active"}],
            "latency_ms": 120.5,
            "is_scan_action": True,
            "vulnerabilities": vulns
        })

    # --- 2. Conversational Scanner Bot: Confirm Mitigation Intent ---
    if "confirm mitigate" in msg_lower or (("mitigate" in msg_lower or "fix" in msg_lower) and any(x in msg_lower for x in ["all", "vuln-", "them", "yes"])):
        # Extract target ID or all
        match = re.search(r'(vuln-[a-z0-9\-]+)', msg_lower)
        target = match.group(1).upper() if match else "all"

        mit_res = bot_instance.apply_mitigation(target, confirmed_by_user=True)
        if mit_res["status"] == "MITIGATION_SUCCESS":
            detail_md = "\n".join([
                f"- ✅ **`{d['vuln_id']}`**: {d['title']} -> Status: **`RESOLVED`**\n  Verification Command: `{d['verification_command']}`"
                for d in mit_res["details"]
            ])
            bot_reply = (
                f"### ✅ Mitigation Applied & Verified Successfully\n\n"
                f"**Remediation Timestamp:** `{mit_res['timestamp']}`  \n"
                f"**Resolved Vulnerabilities:** `{mit_res['total_resolved']}`\n\n"
                f"{detail_md}\n\n"
                f"🛡️ **Security Status:** Findings have been updated from `Active` to **`Resolved Threats`** in the MongoDB CTI database."
            )
        else:
            bot_reply = f"ℹ️ {mit_res.get('message', 'No pending mitigations were executed.')}"

        db = get_db()
        db["sessions"].update_one(
            {"session_id": session_id},
            {"$push": {"history": {
                "$each": [
                    {"role": "user", "content": message, "timestamp": datetime.datetime.utcnow().isoformat()},
                    {"role": "assistant", "content": bot_reply, "timestamp": datetime.datetime.utcnow().isoformat()}
                ]
            }}},
            upsert=True
        )

        return jsonify({
            "session_id": session_id,
            "response": bot_reply,
            "sources": [{"source": "Mitigation Engine", "score": 1.0, "platform": platform or "Host", "status": "Resolved"}],
            "latency_ms": 95.0,
            "is_mitigation_action": True,
            "mitigation_results": mit_res
        })

    # --- 3. Standard RAG Chat & Mitigation Procedures Query ---
    res = execute_chat(
        session_id=session_id,
        message=message,
        platform=platform,
        threat_status=threat_status,
        top_k=top_k
    )
    return jsonify(res)


# ---------------------------------------------------------------------------
# GET /api/chat/history - Conversation Memory
# ---------------------------------------------------------------------------
@chat_bp.route("/history", methods=["GET"])
def get_history():
    session_id = request.args.get("session_id", "session-default")
    db = get_db()
    session_doc = db["sessions"].find_one({"session_id": session_id}, {"_id": 0})
    history = session_doc.get("history", []) if session_doc else []
    return jsonify({
        "session_id": session_id,
        "count": len(history),
        "history": history
    })


# ---------------------------------------------------------------------------
# POST /api/chat/clear - Clear Conversation
# ---------------------------------------------------------------------------
@chat_bp.route("/clear", methods=["POST"])
def clear_history():
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id", "session-default")
    db = get_db()
    db["sessions"].delete_one({"session_id": session_id})
    return jsonify({"status": "cleared", "session_id": session_id})


# ---------------------------------------------------------------------------
# POST /api/chat/ingest - Document Ingestion (Appendix A spec)
# ---------------------------------------------------------------------------
@chat_bp.route("/ingest", methods=["POST"])
def ingest_documents():
    payload = request.get_json(silent=True) or {}
    docs = payload.get("documents", COMPREHENSIVE_THREATS)
    chunk_size = int(payload.get("chunk_size", 150))
    count = ingest_threat_documents(docs, chunk_size=chunk_size)
    return jsonify({
        "chunks_created": count,
        "documents_ingested": len(docs),
        "message": f"Successfully ingested {count} vector chunks from {len(docs)} threat advisories."
    })


# ---------------------------------------------------------------------------
# GET /api/chat/threats - Structured Threats Catalog
# ---------------------------------------------------------------------------
@chat_bp.route("/threats", methods=["GET"])
def list_threats():
    platform = request.args.get("platform")
    status = request.args.get("status")
    
    filtered = COMPREHENSIVE_THREATS
    if platform and platform.lower() not in ["all", "any"]:
        filtered = [t for t in filtered if t.get("platform", "").lower() == platform.lower()]
    if status and status.lower() not in ["all", "any"]:
        filtered = [t for t in filtered if t.get("status", "").lower() == status.lower()]

    return jsonify({
        "status": "ok",
        "total_threats": len(filtered),
        "threats": filtered
    })


# ---------------------------------------------------------------------------
# GET /api/chat/categories - Matrix of Platforms & Lifecycles
# ---------------------------------------------------------------------------
@chat_bp.route("/categories", methods=["GET"])
def get_categories():
    platforms = ["Linux", "Windows", "MacOS", "Android", "iOS", "Cloud"]
    statuses = ["Anticipated", "Active", "Evolving", "Resolved"]

    matrix = {p: {s: 0 for s in statuses} for p in platforms}
    for t in COMPREHENSIVE_THREATS:
        p = t.get("platform")
        s = t.get("status")
        if p in matrix and s in matrix[p]:
            matrix[p][s] += 1

    return jsonify({
        "platforms": platforms,
        "statuses": statuses,
        "matrix": matrix,
        "total_threats": len(COMPREHENSIVE_THREATS)
    })


# ---------------------------------------------------------------------------
# POST /api/chat/scan & GET /api/chat/scan/status - Scanner Bot Controls
# ---------------------------------------------------------------------------
@chat_bp.route("/scan", methods=["POST"])
def trigger_scan():
    payload = request.get_json(silent=True) or {}
    platform = payload.get("platform")
    scope = payload.get("scope", "system-wide")
    res = bot_instance.run_full_scan(target_scope=scope, target_platform=platform)
    return jsonify(res)


@chat_bp.route("/scan/status", methods=["GET"])
def get_scan_status():
    vulns = bot_instance.get_vulnerabilities()
    unmitigated = [v for v in vulns if v.get("status") == "Unmitigated"]
    resolved = [v for v in vulns if v.get("status") == "Resolved"]
    return jsonify({
        "host_platform": bot_instance.current_os,
        "last_scan_time": bot_instance.last_scan_time,
        "total_vulns": len(vulns),
        "unmitigated_count": len(unmitigated),
        "resolved_count": len(resolved),
        "vulnerabilities": vulns
    })


@chat_bp.route("/mitigate", methods=["POST"])
def execute_mitigation():
    payload = request.get_json(silent=True) or {}
    vuln_id = payload.get("vuln_id", "all")
    confirmed = payload.get("confirmed", True)
    res = bot_instance.apply_mitigation(vuln_id, confirmed_by_user=confirmed)
    return jsonify(res)
