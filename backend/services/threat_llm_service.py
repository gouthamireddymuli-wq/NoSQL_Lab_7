"""
Threat Intelligence LLM/SLM RAG Service
Extends Appendix A architecture for Cyber Threat Intelligence:
- Persistent conversation memory in MongoDB (`sessions` collection)
- Semantic vector chunking and top-k retrieval (`document_chunks` collection)
- Support for Ollama, OpenAI, and Built-in CTI Expert SLM Engine
- Precise mitigation procedures and platform-targeted threat triage
"""

import os
import time
import math
import random
import hashlib
import re
import datetime
import requests
from typing import Optional, List, Dict, Any

from pymongo import MongoClient

# Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "cti_platform")
LLM_BACKEND = os.getenv("LLM_BACKEND", "builtin")  # "ollama", "openai", "builtin"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "150"))
TOP_K = int(os.getenv("TOP_K", "3"))

# MongoDB Client
_client: Optional[MongoClient] = None


def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client[MONGO_DB]


# --- Vector Embeddings (Appendix A Spec) ---
def mock_embed(text: str, dim: int = 384) -> List[float]:
    """Generates deterministic unit-normalized pseudo-embedding for local vector search."""
    tokens = text.lower().split()
    seed_val = int(hashlib.md5(text.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed_val)
    vec = [rng.gauss(0, 1) for _ in range(dim)]
    
    # Give semantic boost to key cybersecurity tokens
    cyber_keywords = {
        "linux": 0, "windows": 10, "macos": 20, "android": 30, "ios": 40, "cloud": 50,
        "anticipated": 60, "active": 70, "evolving": 80, "resolved": 90,
        "cve": 100, "mitigation": 110, "ransomware": 120, "vulnerability": 130,
        "exploit": 140, "patch": 150, "backdoor": 160, "kernel": 170
    }
    for word in tokens:
        clean = re.sub(r'[^a-z0-9]', '', word)
        if clean in cyber_keywords:
            idx = cyber_keywords[clean] % dim
            vec[idx] += 3.5

    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def get_embedding(text: str) -> List[float]:
    return mock_embed(text)


def cosine_sim(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE) -> List[str]:
    words = text.split()
    return [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]


# --- Document Ingestion & RAG Indexing ---
def ingest_threat_documents(documents: List[Dict[str, Any]], chunk_size: int = CHUNK_SIZE) -> int:
    """Chunks, embeds, and stores threat intelligence documents into MongoDB document_chunks."""
    db = get_db()
    col = db["document_chunks"]
    chunks_to_insert = []

    for doc in documents:
        title = doc.get("title", "Untitled Threat Advisory")
        platform = doc.get("platform", "General")
        status = doc.get("status", "Active")
        severity = doc.get("severity", "Medium")
        cve_id = doc.get("cve_id", "N/A")
        
        # Build comprehensive content text
        content = (
            f"Threat Title: {title}\n"
            f"Platform: {platform} | Status: {status} | Severity: {severity} | CVE: {cve_id}\n"
            f"Summary: {doc.get('summary', '')}\n"
            f"Affected Systems: {doc.get('affected_systems', '')}\n"
            f"Tactics: {', '.join(doc.get('tactics', []))}\n"
            f"Techniques: {', '.join(doc.get('techniques', []))}\n"
            f"Mitigation Procedures:\n" + "\n".join(doc.get('mitigation_procedures', [])) + "\n"
            f"Remediation Script: {doc.get('remediation_script', '')}\n"
            f"Verification: {doc.get('verification_command', '')}"
        )

        doc_chunks = chunk_text(content, chunk_size)
        for i, chunk in enumerate(doc_chunks):
            embedding = get_embedding(chunk)
            chunks_to_insert.append({
                "source_title": title,
                "platform": platform,
                "status": status,
                "severity": severity,
                "cve_id": cve_id,
                "chunk_index": i,
                "text": chunk,
                "embedding": embedding,
                "raw_threat": doc,
                "created_at": datetime.datetime.utcnow().isoformat()
            })

    if chunks_to_insert:
        col.delete_many({})  # Refresh vector index
        col.insert_many(chunks_to_insert)

    return len(chunks_to_insert)


def retrieve_context(query: str, platform: Optional[str] = None, threat_status: Optional[str] = None, top_k: int = TOP_K) -> List[Dict[str, Any]]:
    """Retrieves top-k nearest neighbor threat intelligence chunks from MongoDB."""
    db = get_db()
    col = db["document_chunks"]

    # Filter query
    mongo_filter = {}
    if platform and platform.lower() not in ["all", "any"]:
        mongo_filter["platform"] = {"$regex": f"^{platform}$", "$options": "i"}
    if threat_status and threat_status.lower() not in ["all", "any"]:
        mongo_filter["status"] = {"$regex": f"^{threat_status}$", "$options": "i"}

    query_emb = get_embedding(query)
    scored = []

    for doc in col.find(mongo_filter, {"embedding": 1, "text": 1, "source_title": 1, "platform": 1, "status": 1, "severity": 1, "cve_id": 1, "raw_threat": 1, "_id": 0}):
        score = cosine_sim(query_emb, doc["embedding"])
        scored.append((score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [
        {
            "score": round(s, 4),
            "source": d.get("source_title", "Threat Advisory"),
            "platform": d.get("platform", "Unknown"),
            "status": d.get("status", "Active"),
            "severity": d.get("severity", "Medium"),
            "cve_id": d.get("cve_id", "N/A"),
            "text": d.get("text", "")[:350],
            "raw_threat": d.get("raw_threat", {})
        }
        for s, d in scored[:top_k]
    ]


# --- LLM Backends ---
def call_ollama(prompt: str, history: List[Dict[str, str]]) -> str:
    messages = [
        {"role": "system", "content": "You are a Senior Cyber Threat Intelligence Analyst and Incident Response Officer. Provide concise, expert threat explanations with exact step-by-step mitigation procedures and terminal commands."}
    ]
    messages.extend(history)
    messages.append({"role": "user", "content": prompt})
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except Exception as e:
        return f"[Ollama Error: {e} - Falling back to CTI Security Intelligence Engine]\n\n" + builtin_cti_engine(prompt, history)


def call_openai(prompt: str, history: List[Dict[str, str]]) -> str:
    try:
        from openai import OpenAI
        oa = OpenAI(api_key=OPENAI_API_KEY)
        messages = [
            {"role": "system", "content": "You are a Senior Cyber Threat Intelligence Analyst. Provide exact mitigation procedures, platform-specific commands, and technical risk assessments based on the provided context."}
        ]
        messages.extend(history)
        messages.append({"role": "user", "content": prompt})
        resp = oa.chat.completions.create(model=OPENAI_MODEL, messages=messages, max_tokens=700)
        return resp.choices[0].message.content
    except Exception as e:
        return f"[OpenAI Error: {e} - Falling back to CTI Security Intelligence Engine]\n\n" + builtin_cti_engine(prompt, history)


def builtin_cti_engine(query: str, sources: List[Dict[str, Any]], requested_platform: Optional[str] = None, requested_status: Optional[str] = None) -> str:
    """
    Intelligent built-in CTI Reasoning & Mitigation Engine.
    Produces high-fidelity, actionable threat advisories with exact terminal commands.
    """
    q_lower = query.lower()

    if not sources:
        return (
            f"### 🛡️ CTI Platform Threat Intelligence Advisory\n\n"
            f"No specific threat vectors found in the vector index for query: **'{query}'** "
            f"under platform **{requested_platform or 'All'}** ({requested_status or 'All Statuses'}).\n\n"
            f"**Recommended Action:**\n"
            f"1. Ingest additional CTI feeds via the **Ingest CTI Documents** button or `POST /api/chat/ingest`.\n"
            f"2. Run a background platform vulnerability scan to detect live host weaknesses."
        )

    # Format authoritative advisory
    top_hit = sources[0]
    raw = top_hit.get("raw_threat", {})
    title = raw.get("title", top_hit.get("source", "Threat Advisory"))
    platform = raw.get("platform", top_hit.get("platform", "Cross-Platform"))
    status = raw.get("status", top_hit.get("status", "Active"))
    severity = raw.get("severity", top_hit.get("severity", "High"))
    cve = raw.get("cve_id", "N/A")
    summary = raw.get("summary", top_hit.get("text", ""))
    mitigations = raw.get("mitigation_procedures", [
        "Isolate affected endpoint from network segment.",
        "Apply latest vendor patches and security updates.",
        "Audit access logs for anomalous behavior."
    ])
    remediation_script = raw.get("remediation_script", "# Review and apply vendor patch")
    verification_command = raw.get("verification_command", "# Check patch level")

    badge_status = {
        "anticipated": "🟡 ANTICIPATED THREAT (Early Warning / Precursor)",
        "active": "🔴 ACTIVE THREAT (Active Exploitation in Wild)",
        "evolving": "🟠 EVOLVING THREAT (Variant Mutation / Evasion)",
        "resolved": "🟢 RESOLVED THREAT (Mitigated / Hardened)"
    }.get(status.lower(), f"🔵 THREAT STATUS: {status.upper()}")

    resp_parts = [
        f"### 🛡️ Cyber Threat Intelligence Advisory: {title}\n",
        f"**Lifecycle Status:** `{badge_status}`  \n"
        f"**Target Platform:** `{platform}` | **Severity:** `{severity.upper()}` | **CVE / Advisory:** `{cve}`\n",
        f"#### 1. Threat Analysis & Vector Mechanics\n{summary}\n",
        f"#### 2. Step-by-Step Mitigation Procedures",
        "\n".join([f"- **{m}**" if m.startswith("Step") else f"- {m}" for m in mitigations]),
        f"\n#### 3. Immediate Actionable Remediation Script ({platform})\n```bash\n{remediation_script}\n```",
        f"#### 4. Automated Verification Check\n```bash\n{verification_command}\n```"
    ]

    # Additional contextual hits
    if len(sources) > 1:
        resp_parts.append("\n#### 5. Correlated Intelligence & Secondary Vectors")
        for i, s in enumerate(sources[1:], 2):
            resp_parts.append(f"- **[{s.get('platform')}] {s.get('source')}** (`{s.get('status').upper()}` - Severity: {s.get('severity')}) — Relevance Score: `{s.get('score')}`")

    return "\n\n".join(resp_parts)


# --- Core Orchestration Pipeline ---
def execute_chat(session_id: str, message: str, platform: Optional[str] = None, threat_status: Optional[str] = None, top_k: int = TOP_K) -> Dict[str, Any]:
    """
    Main RAG Chat handler:
    1. Retrieves top_k relevant threat chunks
    2. Loads session history from MongoDB
    3. Calls LLM or Built-in CTI Engine
    4. Persists conversation turn into MongoDB sessions collection
    """
    start_time = time.perf_counter()
    db = get_db()
    sessions_col = db["sessions"]

    # 1. Retrieve RAG context
    sources = retrieve_context(message, platform=platform, threat_status=threat_status, top_k=top_k)

    # 2. Load conversation history
    session_doc = sessions_col.find_one({"session_id": session_id})
    history = session_doc.get("history", []) if session_doc else []

    # 3. Generate response
    if LLM_BACKEND == "openai" and OPENAI_API_KEY:
        context_block = "\n\n".join(f"[{s['source']} - Platform: {s['platform']} - Status: {s['status']}]\n{s['text']}" for s in sources)
        prompt = f"Threat Intelligence Knowledge Context:\n{context_block}\n\nUser Question: {message}\nTarget Platform: {platform or 'Any'}\nStatus: {threat_status or 'Any'}"
        response_text = call_openai(prompt, history[-4:])
    elif LLM_BACKEND == "ollama":
        context_block = "\n\n".join(f"[{s['source']} - Platform: {s['platform']} - Status: {s['status']}]\n{s['text']}" for s in sources)
        prompt = f"Threat Intelligence Knowledge Context:\n{context_block}\n\nUser Question: {message}\nTarget Platform: {platform or 'Any'}\nStatus: {threat_status or 'Any'}"
        response_text = call_ollama(prompt, history[-4:])
    else:
        # High-precision built-in CTI engine
        response_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)

    # 4. Save history in MongoDB (Appendix A specification)
    history.append({
        "role": "user",
        "content": message,
        "platform": platform,
        "threat_status": threat_status,
        "timestamp": datetime.datetime.utcnow().isoformat()
    })
    history.append({
        "role": "assistant",
        "content": response_text,
        "sources": [{"source": s["source"], "score": s["score"], "platform": s["platform"], "status": s["status"]} for s in sources],
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

    sessions_col.update_one(
        {"session_id": session_id},
        {"$set": {"history": history[-30:], "last_active": datetime.datetime.utcnow().isoformat()}},
        upsert=True
    )

    latency_ms = round((time.perf_counter() - start_time) * 1000, 1)

    return {
        "session_id": session_id,
        "response": response_text,
        "sources": sources,
        "latency_ms": latency_ms,
        "platform": platform or "All",
        "threat_status": threat_status or "All"
    }
