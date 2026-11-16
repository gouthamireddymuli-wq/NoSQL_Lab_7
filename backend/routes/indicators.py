"""
Indicators blueprint – /api/indicators
"""
from flask import Blueprint, request, jsonify
from bson import ObjectId
from bson.errors import InvalidId
import datetime

from config import indicators_col, reports_col, fix_doc

indicators_bp = Blueprint("indicators", __name__)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _build_query():
    q = {}
    type_ = request.args.get("type")
    severity = request.args.get("severity")
    status = request.args.get("status")
    search = request.args.get("search")

    if type_:
        q["type"] = type_
    if severity:
        q["severity"] = severity
    if status:
        q["status"] = status
    if search:
        q["$text"] = {"$search": search}
    return q


# ------------------------------------------------------------------
# Stats  (must be registered BEFORE /<id> to avoid route clash)
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators/stats", methods=["GET"])
def indicators_stats():
    by_type = list(indicators_col.aggregate([
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]))
    by_severity = list(indicators_col.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]))
    by_status = list(indicators_col.aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]))

    type_dict = {str(d["_id"]): d["count"] for d in by_type if d["_id"]}
    sev_dict = {str(d["_id"]): d["count"] for d in by_severity if d["_id"]}
    status_dict = {str(d["_id"]): d["count"] for d in by_status if d["_id"]}

    total_ind = indicators_col.count_documents({})
    total_rep = reports_col.count_documents({})

    return jsonify({
        "by_type": type_dict,
        "by_severity": sev_dict,
        "by_status": status_dict,
        "total": total_ind,
        "total_indicators": total_ind,
        "total_reports": total_rep,
        "types_list": [{"type": d["_id"], "count": d["count"]} for d in by_type],
        "severities_list": [{"severity": d["_id"], "count": d["count"]} for d in by_severity],
        "status_list": [{"status": d["_id"], "count": d["count"]} for d in by_status]
    })


# ------------------------------------------------------------------
# List / search
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators", methods=["GET"])
def list_indicators():
    q = _build_query()
    limit = min(int(request.args.get("limit", 100)), 500)
    skip = int(request.args.get("skip", 0))
    docs = list(indicators_col.find(q).skip(skip).limit(limit))
    return jsonify(fix_doc(docs))


# ------------------------------------------------------------------
# Create
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators", methods=["POST"])
def create_indicator():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400
    now = datetime.datetime.utcnow()
    body.setdefault("created_at", now)
    body.setdefault("updated_at", now)
    result = indicators_col.insert_one(body)
    body["_id"] = str(result.inserted_id)
    return jsonify(fix_doc(body)), 201


# ------------------------------------------------------------------
# Read single
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators/<id>", methods=["GET"])
def get_indicator(id):
    try:
        doc = indicators_col.find_one({"_id": ObjectId(id)})
    except InvalidId:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Not found"}), 404
    return jsonify(fix_doc(doc))


# ------------------------------------------------------------------
# Update
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators/<id>", methods=["PUT"])
def update_indicator(id):
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400
    body.pop("_id", None)
    body["updated_at"] = datetime.datetime.utcnow()
    try:
        result = indicators_col.update_one(
            {"_id": ObjectId(id)}, {"$set": body}
        )
    except InvalidId:
        return jsonify({"error": "Invalid id"}), 400
    if result.matched_count == 0:
        return jsonify({"error": "Not found"}), 404
    doc = indicators_col.find_one({"_id": ObjectId(id)})
    return jsonify(fix_doc(doc))


# ------------------------------------------------------------------
# Delete
# ------------------------------------------------------------------
@indicators_bp.route("/api/indicators/<id>", methods=["DELETE"])
def delete_indicator(id):
    try:
        result = indicators_col.delete_one({"_id": ObjectId(id)})
    except InvalidId:
        return jsonify({"error": "Invalid id"}), 400
    if result.deleted_count == 0:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"deleted": id})
