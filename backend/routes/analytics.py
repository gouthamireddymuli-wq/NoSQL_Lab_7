"""
Analytics blueprint – /api/analytics
"""
from flask import Blueprint, jsonify
from config import db, indicators_col, fix_doc

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/api/analytics/bson-sizes", methods=["GET"])
def bson_sizes():
    pipeline = [
        {"$project": {"bsonSize": {"$bsonSize": "$$ROOT"}}},
        {"$group": {
            "_id": None,
            "avg_size": {"$avg": "$bsonSize"},
            "max_size": {"$max": "$bsonSize"},
            "min_size": {"$min": "$bsonSize"},
            "total_docs": {"$sum": 1},
            "total_bytes": {"$sum": "$bsonSize"}
        }}
    ]
    result = list(indicators_col.aggregate(pipeline))
    if not result:
        return jsonify({"error": "No documents found"}), 404

    summary = result[0]
    summary.pop("_id", None)

    # Also get per-document sample (top 10 largest)
    sample_pipeline = [
        {"$project": {
            "indicator_id": 1,
            "type": 1,
            "value": 1,
            "bsonSize": {"$bsonSize": "$$ROOT"}
        }},
        {"$sort": {"bsonSize": -1}},
        {"$limit": 10}
    ]
    samples = list(indicators_col.aggregate(sample_pipeline))

    return jsonify({
        "summary": fix_doc(summary),
        "largest_10": fix_doc(samples)
    })


@analytics_bp.route("/api/analytics/cache-stats", methods=["GET"])
def cache_stats():
    try:
        status = db.command("serverStatus")
        wt = status.get("wiredTiger", {})
        cache = wt.get("cache", {})

        metrics = {
            "cache_max_bytes": cache.get("maximum bytes configured", 0),
            "cache_used_bytes": cache.get("bytes currently in the cache", 0),
            "cache_dirty_bytes": cache.get("tracked dirty bytes in the cache", 0),
            "pages_read_into_cache": cache.get("pages read into cache", 0),
            "pages_evicted": cache.get("pages evicted by application threads", 0),
            "unmodified_pages_evicted": cache.get("unmodified pages evicted", 0),
            "cache_used_pct": round(
                cache.get("bytes currently in the cache", 0) /
                max(cache.get("maximum bytes configured", 1), 1) * 100, 2
            )
        }
        return jsonify(metrics)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/working-set", methods=["GET"])
def working_set():
    try:
        collections_info = []
        for col_name in db.list_collection_names():
            stats = db.command("collStats", col_name)
            collections_info.append({
                "collection": col_name,
                "count": stats.get("count", 0),
                "size_bytes": stats.get("size", 0),
                "storage_size_bytes": stats.get("storageSize", 0),
                "avg_obj_size_bytes": round(stats.get("avgObjSize", 0), 2),
                "index_sizes": fix_doc(stats.get("indexSizes", {}))
            })
        return jsonify({"collections": collections_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
