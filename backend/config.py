"""
MongoDB connection configuration for the CTI Platform.
"""
import os
from pymongo import MongoClient, ASCENDING, TEXT
from bson import ObjectId
import datetime

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["cti_platform"]

# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------
indicators_col = db["indicators"]
threat_actors_col = db["threat_actors"]
reports_col = db["reports"]
feed_sources_col = db["feed_sources"]

# ---------------------------------------------------------------------------
# Indexes (idempotent – safe to call on every startup)
# ---------------------------------------------------------------------------
def ensure_indexes():
    try:
        # Compound: type + value  (frequently filtered together)
        indicators_col.create_index([("type", ASCENDING), ("value", ASCENDING)])
        # Compound: status + severity  (dashboard queries)
        indicators_col.create_index([("status", ASCENDING), ("severity", ASCENDING)])
        # Full-text search on value, tags and threat_types
        indicators_col.create_index(
            [("value", TEXT), ("tags", TEXT), ("threat_types", TEXT)],
            name="indicators_text"
        )
        # Actors by actor_id
        threat_actors_col.create_index([("actor_id", ASCENDING)], unique=True)
        # Reports by report_id
        reports_col.create_index([("report_id", ASCENDING)], unique=True)
    except Exception as e:
        print("Note: ensure_indexes deferred:", e)

# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------
def fix_doc(doc):
    """Recursively convert ObjectId → str and datetime → ISO string."""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [fix_doc(item) for item in doc]
    if isinstance(doc, dict):
        return {k: fix_doc(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime.datetime):
        return doc.isoformat()
    return doc
