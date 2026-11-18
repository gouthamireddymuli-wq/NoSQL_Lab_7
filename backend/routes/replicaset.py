"""
Flask Blueprint: Replica Set API routes for Lab 8.

Exposes endpoints to inspect and interact with a 3-node MongoDB replica set
(rs0) running locally on ports 27017, 27018, and 27019 via Docker.

Endpoints:
  GET  /api/replicaset/status            - Replica set health & member list
  POST /api/replicaset/stepdown          - Force primary step-down (trigger election)
  GET  /api/replicaset/insert-test       - Insert a test doc on the primary
  GET  /api/replicaset/verify-replication - Read latest test doc from every node
  GET  /api/replicaset/failover-log      - Tail the failover_log.txt written by activity_8_2.py
"""

import os
from datetime import datetime, timezone

from flask import Blueprint, jsonify
from pymongo import MongoClient, ReadPreference
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure, OperationFailure

from config import fix_doc

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------
replicaset_bp = Blueprint("replicaset", __name__, url_prefix="/api/replicaset")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RS_URI = (
    "mongodb://localhost:27017,localhost:27018,localhost:27019/"
    "?replicaSet=rs0&serverSelectionTimeoutMS=5000"
)
RS_NAME = "rs0"
LAB8_DB = "lab8db"
TEST_COLLECTION = "replication_test"
FAILOVER_LOG_PATH = r"C:\Users\gouth\OneDrive\Desktop\NoSQL_Lab_8\Activity_8_2\failover_log.txt"
NODE_PORTS = [27017, 27018, 27019]


def _make_rs_client(**kwargs) -> MongoClient:
    """Return a fresh MongoClient connected to the rs0 replica set."""
    return MongoClient(RS_URI, **kwargs)


# ---------------------------------------------------------------------------
# GET /api/replicaset/status
# ---------------------------------------------------------------------------
@replicaset_bp.route("/status", methods=["GET"])
def replicaset_status():
    """
    Returns the current replica set status including member states,
    health, uptime, optime, lag, and priorities from rs.conf().
    """
    try:
        client = _make_rs_client()
        admin_db = client["admin"]

        # Run replSetGetStatus
        status = admin_db.command("replSetGetStatus")

        # Fetch priorities from replSetGetConfig
        priorities: dict[str, float] = {}
        try:
            config = admin_db.command("replSetGetConfig")
            for member_cfg in config.get("config", {}).get("members", []):
                priorities[member_cfg.get("host", "")] = member_cfg.get("priority", None)
        except Exception:
            pass  # priorities will remain empty; non-fatal

        # Determine primary
        primary_host: str | None = None
        members_out = []

        for m in status.get("members", []):
            state_str = m.get("stateStr", "UNKNOWN")
            if state_str == "PRIMARY":
                primary_host = m.get("name")

            # optime date
            optime_date = m.get("optimeDate")
            optime_iso: str | None = None
            if optime_date is not None:
                if isinstance(optime_date, datetime):
                    optime_iso = optime_date.isoformat()
                else:
                    optime_iso = str(optime_date)

            # Replication lag in ms (pingMs field, or 0 for primary/self)
            ping_ms = m.get("pingMs", 0)

            member_name = m.get("name", "")
            members_out.append({
                "id": m.get("_id"),
                "name": member_name,
                "state": state_str,
                "health": int(m.get("health", 0)),
                "uptime": m.get("uptime", 0),
                "optime_date": optime_iso,
                "ping_ms": ping_ms,
                "priority": priorities.get(member_name),
            })

        client.close()

        return jsonify({
            "replica_set": status.get("set", RS_NAME),
            "my_state": status.get("myState", -1),
            "members": members_out,
            "primary": primary_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200

    except (ServerSelectionTimeoutError, ConnectionFailure):
        return jsonify({
            "error": "Replica set not reachable. Start Docker containers first.",
            "members": [],
            "primary": None,
        }), 503
    except Exception as exc:
        return jsonify({
            "error": str(exc),
            "members": [],
            "primary": None,
        }), 503


# ---------------------------------------------------------------------------
# POST /api/replicaset/stepdown
# ---------------------------------------------------------------------------
@replicaset_bp.route("/stepdown", methods=["POST"])
def stepdown():
    """
    Forces the current primary to step down, triggering a new election.
    Uses replSetStepDown with a 30-second timeout.
    """
    try:
        client = _make_rs_client()
        admin_db = client["admin"]

        # replSetStepDown takes the step-down timeout in seconds as the first arg
        admin_db.command("replSetStepDown", 30)
        client.close()

        return jsonify({
            "success": True,
            "message": "Step down initiated. Election in progress.",
        }), 200

    except OperationFailure as exc:
        # replSetStepDown often throws even on success (connection drops)
        err_msg = str(exc)
        # Code 189 = "No electable secondaries caught up" etc., treat as real error
        # A dropped connection usually means the step-down worked
        if "connection" in err_msg.lower() or "reset" in err_msg.lower():
            return jsonify({
                "success": True,
                "message": "Step down initiated. Election in progress.",
            }), 200
        return jsonify({"success": False, "error": err_msg}), 500

    except (ServerSelectionTimeoutError, ConnectionFailure) as exc:
        # Connection drop right after stepDown often means it succeeded
        return jsonify({
            "success": True,
            "message": "Step down initiated. Election in progress.",
        }), 200

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# GET /api/replicaset/insert-test
# ---------------------------------------------------------------------------
@replicaset_bp.route("/insert-test", methods=["GET"])
def insert_test():
    """
    Inserts a test document into the primary's lab8db.replication_test
    collection to verify write path and trigger replication.
    """
    try:
        client = _make_rs_client()

        # Identify primary before insert
        status = client["admin"].command("replSetGetStatus")
        primary_host: str | None = None
        for m in status.get("members", []):
            if m.get("stateStr") == "PRIMARY":
                primary_host = m.get("name")
                break

        collection = client[LAB8_DB][TEST_COLLECTION]
        doc = {
            "source": "CTI Platform Lab 8",
            "timestamp": datetime.utcnow(),
            "message": "Test replication document",
        }
        result = collection.insert_one(doc)
        inserted_id = str(result.inserted_id)
        client.close()

        return jsonify({
            "inserted_id": inserted_id,
            "primary": primary_host,
        }), 200

    except (ServerSelectionTimeoutError, ConnectionFailure) as exc:
        return jsonify({"error": "Replica set not reachable. " + str(exc)}), 503
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# GET /api/replicaset/verify-replication
# ---------------------------------------------------------------------------
@replicaset_bp.route("/verify-replication", methods=["GET"])
def verify_replication():
    """
    Directly connects to each of the three nodes and reads the most recent
    document from lab8db.replication_test, using SECONDARY_PREFERRED so that
    secondaries can serve the read.
    """
    nodes_out = []

    for port in NODE_PORTS:
        host_label = f"localhost:{port}"
        direct_uri = (
            f"mongodb://localhost:{port}/"
            f"?directConnection=true&serverSelectionTimeoutMS=3000"
        )
        node_client: MongoClient | None = None
        try:
            node_client = MongoClient(
                direct_uri,
                read_preference=ReadPreference.SECONDARY_PREFERRED,
            )
            admin_db = node_client["admin"]

            # Determine state of this node
            try:
                hello = admin_db.command("hello")
                if hello.get("isWritablePrimary") or hello.get("ismaster"):
                    node_state = "PRIMARY"
                elif hello.get("secondary"):
                    node_state = "SECONDARY"
                elif hello.get("arbiterOnly"):
                    node_state = "ARBITER"
                else:
                    node_state = "UNKNOWN"
            except Exception:
                node_state = "UNKNOWN"

            collection = node_client[LAB8_DB][TEST_COLLECTION]
            doc = collection.find_one(
                {},
                sort=[("timestamp", -1)],
            )
            nodes_out.append({
                "host": host_label,
                "found": doc is not None,
                "doc": fix_doc(doc),
                "state": node_state,
            })

        except (ServerSelectionTimeoutError, ConnectionFailure):
            nodes_out.append({
                "host": host_label,
                "found": False,
                "doc": None,
                "state": "UNREACHABLE",
            })
        except Exception as exc:
            nodes_out.append({
                "host": host_label,
                "found": False,
                "doc": None,
                "state": f"ERROR: {exc}",
            })
        finally:
            if node_client is not None:
                try:
                    node_client.close()
                except Exception:
                    pass

    return jsonify({"nodes": nodes_out}), 200


# ---------------------------------------------------------------------------
# GET /api/replicaset/failover-log
# ---------------------------------------------------------------------------
@replicaset_bp.route("/failover-log", methods=["GET"])
def failover_log():
    """
    Returns the last 50 lines of the failover_log.txt written by
    activity_8_2.py during the failover observation exercise.
    """
    if not os.path.exists(FAILOVER_LOG_PATH):
        return jsonify({
            "lines": [],
            "message": "No failover log yet. Run activity_8_2.py first.",
        }), 200

    try:
        with open(FAILOVER_LOG_PATH, "r", encoding="utf-8") as fh:
            all_lines = fh.readlines()

        last_50 = [line.rstrip("\n") for line in all_lines[-50:]]
        return jsonify({"lines": last_50}), 200

    except Exception as exc:
        return jsonify({"error": str(exc), "lines": []}), 500
