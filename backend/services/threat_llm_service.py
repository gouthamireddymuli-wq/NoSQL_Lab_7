"""
Threat Intelligence LLM/SLM RAG Service with Full Ollama Integration
=============================================================================
Extends Appendix A architecture for Cyber Threat Intelligence:
- Seamless Ollama local SLM/LLM integration with auto-model discovery
- Support for custom Ollama remote endpoints / tunnels for cloud deployments (Vercel)
- Semantic vector chunking and top-k retrieval (document_chunks collection)
- Persistent conversation memory in MongoDB (sessions collection)
- Graceful intelligent fallback to Built-in CTI Expert Reasoning Engine
=============================================================================
"""

import os
import time
import math
import random
import hashlib
import re
import datetime
import requests
from typing import Optional, List, Dict, Any, Tuple

from pymongo import MongoClient

# --- Configuration ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "cti_platform")
LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama")  # "ollama", "builtin", "openai", "auto"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
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


# --- Dynamic Ollama Status & Model Discovery ---
def check_ollama(url: Optional[str] = None) -> Dict[str, Any]:
    """Checks Ollama server connectivity and lists installed models."""
    base_url = (url or os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL)).rstrip("/")
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            raw_models = data.get("models", [])
            model_names = [m.get("name") for m in raw_models if m.get("name")]
            active = model_names[0] if model_names else OLLAMA_MODEL
            return {
                "status": "connected",
                "base_url": base_url,
                "models": model_names,
                "active_model": active,
                "count": len(model_names),
                "is_local": "localhost" in base_url or "127.0.0.1" in base_url
            }
    except Exception as e:
        is_local_target = "localhost" in base_url or "127.0.0.1" in base_url
        is_cloud = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
        
        if is_local_target and is_cloud:
            err_msg = (
                "Vercel Cloud is hosted remotely and cannot connect to your personal PC's 'localhost:11434'. "
                "To use local Ollama: (1) Run this app locally at http://localhost:5000/chatbot.html, or "
                "(2) Provide a public tunnel URL (e.g. ngrok or Cloudflare tunnel), or (3) Select 'Built-in CTI Engine' for native cloud operation."
            )
        else:
            err_msg = f"Unable to reach Ollama at {base_url}. Ensure Ollama is running ('ollama serve'). Details: {str(e)[:180]}"

        return {
            "status": "offline",
            "base_url": base_url,
            "models": [],
            "error": err_msg,
            "is_local": is_local_target,
            "is_cloud_env": is_cloud
        }
    return {"status": "offline", "base_url": base_url, "models": []}


# --- Vector Embeddings (Appendix A Spec) ---
def mock_embed(text: str, dim: int = 384) -> List[float]:
    tokens = text.lower().split()
    seed_val = int(hashlib.md5(text.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed_val)
    vec = [rng.gauss(0, 1) for _ in range(dim)]
    
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
    db = get_db()
    col = db["document_chunks"]
    chunks_to_insert = []

    for doc in documents:
        title = doc.get("title", "Untitled Threat Advisory")
        platform = doc.get("platform", "General")
        status = doc.get("status", "Active")
        severity = doc.get("severity", "Medium")
        cve_id = doc.get("cve_id", "N/A")
        
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
        col.delete_many({})
        col.insert_many(chunks_to_insert)

    return len(chunks_to_insert)


def retrieve_context(query: str, platform: Optional[str] = None, threat_status: Optional[str] = None, top_k: int = TOP_K) -> List[Dict[str, Any]]:
    db = get_db()
    col = db["document_chunks"]

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


# --- Ollama Caller with Dynamic Model & URL Support ---
def call_ollama(
    prompt: str,
    history: List[Dict[str, str]],
    model: Optional[str] = None,
    base_url: Optional[str] = None
) -> Tuple[str, str]:
    """
    Queries local or remote Ollama SLM/LLM instance.
    Returns (response_text, engine_label).
    """
    target_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
    target_model = model or OLLAMA_MODEL

    # Dynamic check: auto-pick available model if requested model isn't installed
    st = check_ollama(target_url)
    if st.get("status") == "connected" and st.get("models"):
        if target_model not in st["models"]:
            target_model = st["models"][0]

    system_instruction = (
        "You are an authoritative Cyber Threat Intelligence (CTI) Defensive Security Officer and Systems Hardening Specialist.\n"
        "Your role is exclusively DEFENSIVE: explaining threats, guiding administrators in patching vulnerabilities, and providing remediation commands.\n"
        "Analyze the provided CTI knowledge context and user query.\n"
        "Format your response cleanly in Markdown:\n"
        "### 🛡️ Threat Analysis & Risk\n"
        "State the threat name, affected platform, CVE, and severity.\n\n"
        "### 🔧 Step-by-Step Mitigation Procedures\n"
        "Detail safe administrative remediation steps with exact command snippets for the target platform.\n\n"
        "### 🔍 Verification Command\n"
        "Provide a safe inspection command (e.g. package version check, firewall check) to verify the fix."
    )

    messages = [{"role": "system", "content": system_instruction}]
    for h in history:
        if h.get("role") in ["user", "assistant"] and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": prompt})

    try:
        resp = requests.post(
            f"{target_url}/api/chat",
            json={
                "model": target_model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9
                }
            },
            timeout=60
        )
        resp.raise_for_status()
        res_json = resp.json()
        content = res_json.get("message", {}).get("content", "")
        return content, f"Ollama ({target_model})"
    except Exception as e:
        raise RuntimeError(f"Ollama connection error ({target_url} / {target_model}): {e}")


def call_openai(prompt: str, history: List[Dict[str, str]]) -> Tuple[str, str]:
    try:
        from openai import OpenAI
        oa = OpenAI(api_key=OPENAI_API_KEY)
        messages = [
            {"role": "system", "content": "You are a Senior Cyber Threat Intelligence Analyst. Provide exact mitigation procedures, platform-specific commands, and technical risk assessments based on the provided context."}
        ]
        for h in history:
            if h.get("role") in ["user", "assistant"]:
                messages.append({"role": h["role"], "content": h["content"]})
        messages.append({"role": "user", "content": prompt})
        resp = oa.chat.completions.create(model=OPENAI_MODEL, messages=messages, max_tokens=700)
        return resp.choices[0].message.content, f"OpenAI ({OPENAI_MODEL})"
    except Exception as e:
        raise RuntimeError(f"OpenAI error: {e}")


def builtin_cti_engine(query: str, sources: List[Dict[str, Any]], requested_platform: Optional[str] = None, requested_status: Optional[str] = None) -> str:
    """Intelligent built-in CTI reasoning engine for instant deterministic threat mitigation."""
    if not sources:
        return (
            f"### 🛡️ CTI Platform Threat Intelligence Advisory\n\n"
            f"No specific threat vectors found in vector index for query: **'{query}'** "
            f"under platform **{requested_platform or 'All'}** ({requested_status or 'All Statuses'}).\n\n"
            f"**Recommended Action:**\n"
            f"1. Ingest CTI vectors via `POST /api/chat/ingest`.\n"
            f"2. Run a background platform vulnerability scan (`Scan system`)."
        )

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
        "Apply latest vendor security updates.",
        "Audit access logs for anomalous behavior."
    ])
    remediation_script = raw.get("remediation_script", "# Review and apply patch")
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

    if len(sources) > 1:
        resp_parts.append("\n#### 5. Correlated Intelligence & Secondary Vectors")
        for s in sources[1:]:
            resp_parts.append(f"- **[{s.get('platform')}] {s.get('source')}** (`{s.get('status').upper()}` - Severity: {s.get('severity')}) — Relevance Score: `{s.get('score')}`")

    return "\n\n".join(resp_parts)


# --- Core Orchestration Pipeline ---
def execute_chat(
    session_id: str,
    message: str,
    platform: Optional[str] = None,
    threat_status: Optional[str] = None,
    top_k: int = TOP_K,
    backend: Optional[str] = None,
    model: Optional[str] = None,
    ollama_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main RAG Chat orchestrator:
    1. Retrieves top_k relevant threat chunks
    2. Formats CTI context block
    3. Tries Ollama (or OpenAI / Built-in)
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

    # 3. Determine Execution Engine
    selected_backend = (backend or LLM_BACKEND).lower()
    response_text = ""
    engine_used = "Built-in CTI Engine"

    # Context block for LLM prompt
    context_block = "\n\n".join(
        f"[{s['source']} - Platform: {s['platform']} - Status: {s['status']} - Severity: {s['severity']}]\n{s['text']}"
        for s in sources
    )
    llm_prompt = (
        f"CTI Knowledge Context:\n{context_block}\n\n"
        f"User Inquiry: {message}\n"
        f"Target Platform Filter: {platform or 'Any'}\n"
        f"Lifecycle Status Filter: {threat_status or 'Any'}"
    )

    # Attempt Ollama if requested or if in auto/ollama mode
    if selected_backend in ["ollama", "auto"]:
        try:
            response_text, engine_used = call_ollama(
                llm_prompt,
                history[-4:],
                model=model,
                base_url=ollama_url
            )
        except Exception as e:
            # Fallback to Built-in CTI Engine with notice
            fallback_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
            response_text = fallback_text
            engine_used = f"Built-in CTI Engine (Ollama Offline: {str(e)[:60]}...)"
    elif selected_backend == "openai" and OPENAI_API_KEY:
        try:
            response_text, engine_used = call_openai(llm_prompt, history[-4:])
        except Exception as e:
            response_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
            engine_used = f"Built-in CTI Engine (OpenAI fallback: {e})"
    else:
        response_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
        engine_used = "Built-in CTI Engine"

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
        "engine": engine_used,
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
        "threat_status": threat_status or "All",
        "engine_used": engine_used
    }
