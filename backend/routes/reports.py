"""
Reports blueprint – /api/reports
"""
from flask import Blueprint, request, jsonify
from bson import ObjectId
from bson.errors import InvalidId
import datetime

from config import reports_col, indicators_col, fix_doc

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/api/reports", methods=["GET"])
def list_reports():
    q = {}
    search = request.args.get("search")
    if search:
        q["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tags": {"$regex": search, "$options": "i"}},
        ]
    limit = min(int(request.args.get("limit", 100)), 500)
    skip = int(request.args.get("skip", 0))
    docs = list(reports_col.find(q).sort("published_date", -1).skip(skip).limit(limit))
    return jsonify(fix_doc(docs))


@reports_bp.route("/api/reports/<id>", methods=["GET"])
def get_report(id):
    try:
        doc = reports_col.find_one({"_id": ObjectId(id)})
    except InvalidId:
        return jsonify({"error": "Invalid id"}), 400
    if not doc:
        return jsonify({"error": "Not found"}), 404

    # Populate related indicators (reference resolution)
    related_ids = doc.get("related_indicators", [])
    if related_ids:
        enriched = []
        for ind_id in related_ids:
            try:
                ind = indicators_col.find_one({"indicator_id": ind_id})
                if ind:
                    enriched.append(fix_doc(ind))
                else:
                    enriched.append({"indicator_id": ind_id, "error": "not found"})
            except Exception:
                enriched.append({"indicator_id": ind_id, "error": "lookup error"})
        doc["related_indicators_enriched"] = enriched

    return jsonify(fix_doc(doc))


@reports_bp.route("/api/reports", methods=["POST"])
def create_report():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400
    now = datetime.datetime.utcnow()
    body.setdefault("published_date", now)
    result = reports_col.insert_one(body)
    body["_id"] = str(result.inserted_id)
    return jsonify(fix_doc(body)), 201
