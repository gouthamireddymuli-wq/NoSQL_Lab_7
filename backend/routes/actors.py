"""
Threat Actors blueprint – /api/actors
"""
from flask import Blueprint, jsonify
from bson import ObjectId
from bson.errors import InvalidId

from config import threat_actors_col, fix_doc

actors_bp = Blueprint("actors", __name__)


@actors_bp.route("/api/actors", methods=["GET"])
def list_actors():
    docs = list(threat_actors_col.find())
    return jsonify(fix_doc(docs))


@actors_bp.route("/api/actors/<id>", methods=["GET"])
def get_actor(id):
    # Try ObjectId first, then actor_id string
    doc = None
    try:
        doc = threat_actors_col.find_one({"_id": ObjectId(id)})
    except InvalidId:
        doc = threat_actors_col.find_one({"actor_id": id})
    if not doc:
        return jsonify({"error": "Not found"}), 404
    return jsonify(fix_doc(doc))
