"""
Main Flask application – registers all blueprints, enables CORS, and serves frontend static assets.
"""
import os
import sys

# Ensure backend directory is in sys.path for Vercel serverless environment
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS

from config import ensure_indexes
from routes.indicators import indicators_bp
from routes.reports import reports_bp
from routes.actors import actors_bp
from routes.analytics import analytics_bp
from routes.monitor import monitor_bp
from routes.replicaset import replicaset_bp
from routes.lab9 import lab9_bp
from routes.labs import labs_bp
from routes.chat import chat_bp

# Auto-detect frontend directory whether running from root, backend/, or Vercel
local_frontend = os.path.abspath(os.path.join(os.path.dirname(__file__), "frontend"))
parent_frontend = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(local_frontend):
    FRONTEND_DIR = local_frontend
elif os.path.exists(parent_frontend):
    FRONTEND_DIR = parent_frontend
else:
    FRONTEND_DIR = os.path.dirname(__file__)

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)  # allow all origins (dev-friendly)

# Ensure MongoDB indexes exist on startup
ensure_indexes()

# Register blueprints
app.register_blueprint(indicators_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(actors_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(monitor_bp)
app.register_blueprint(replicaset_bp)
app.register_blueprint(lab9_bp)
app.register_blueprint(labs_bp)
app.register_blueprint(chat_bp)


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    return {"status": "ok", "service": "CTI Platform API"}, 200


@app.route("/<path:path>")
def serve_static(path):
    if os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
