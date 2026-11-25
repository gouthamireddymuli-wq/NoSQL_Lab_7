# =============================================================================
# Dockerfile: NoSQL Lab 7 - CTI AI Threat Intelligence Chatbot & Remediation Platform
# Repository: https://hub.docker.com/r/gouthudocker/nosql-lab-7
# Student:    M Gouthami (24BTRCL130)
# =============================================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    MONGO_URI="mongodb://localhost:27017/" \
    MONGO_DB="cti_platform" \
    LLM_BACKEND="ollama" \
    OLLAMA_BASE_URL="http://host.docker.internal:11434" \
    OLLAMA_MODEL="llama3.2:1b"

# Install curl for container health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency requirements and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy platform source code
COPY backend /app/backend
COPY frontend /app/frontend
COPY README.md /app/README.md

WORKDIR /app/backend

# Expose web server port
EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Launch production WSGI / Flask application
CMD ["python", "app.py"]
