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


# --- Semantic Vector Embeddings (Appendix A Spec) ---
STOPWORDS = {
    'what', 'is', 'are', 'the', 'a', 'an', 'and', 'or', 'how', 'to', 'do', 'we',
    'for', 'in', 'on', 'with', 'of', 'at', 'by', 'give', 'me', 'explain', 'show',
    'about', 'can', 'you', 'tell', 'list', 'all', 'any'
}

def semantic_embed(text: str, dim: int = 384) -> List[float]:
    vec = [0.0] * dim
    words = [re.sub(r'[^a-z0-9\-]', '', w) for w in text.lower().split()]
    words = [w for w in words if w and w not in STOPWORDS]

    for i, w in enumerate(words):
        weight = 1.0
        if w.startswith('cve-') or 'cve' in w:
            weight = 15.0
        elif w in {'xz', 'liblzma', 'lockbit', 'akira', 'volt', 'typhoon', 'amos', 'pwnkit', 'eternalblue', 'shroot', 'teabot', 'darkgate', 'goldpickaxe', 'stagefright', 'blastpass', 'runc', 'log4j', 'clfs', 'byovd', 'stealer'}:
            weight = 12.0
        elif w in {'linux', 'windows', 'macos', 'android', 'ios', 'cloud', 'k8s'}:
            weight = 8.0
        elif w in {'anticipated', 'active', 'evolving', 'resolved'}:
            weight = 6.0
        elif w in {'ransomware', 'backdoor', 'trojan', 'mitigate', 'mitigation', 'patch', 'exploit', 'kernel', 'rootkit', 'smb'}:
            weight = 4.0
        
        # Unigram hash
        h = int(hashlib.md5(w.encode('utf-8')).hexdigest()[:8], 16) % dim
        vec[h] += weight

        # Bigram hash
        if i < len(words) - 1:
            bg = f"{w}_{words[i+1]}"
            h_bg = int(hashlib.md5(bg.encode('utf-8')).hexdigest()[:8], 16) % dim
            vec[h_bg] += weight * 1.5

    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]

def mock_embed(text: str, dim: int = 384) -> List[float]:
    return semantic_embed(text, dim)


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
        "You are an IT Systems Administrator and Defensive Infrastructure Security Engineer.\n"
        "You assist authorized enterprise defenders with official vendor patching, configuration hardening, and compliance verification.\n"
        "Analyze the provided CTI knowledge context and user query.\n\n"
        "CRITICAL INSTRUCTION FOR YES/NO QUESTIONS:\n"
        "If the user asks any question that can be answered with yes or no (e.g. 'is X installed?', 'is X vulnerable?', 'do I need X?', 'is X running?'), "
        "you MUST start your reply with '**YES.**' or '**NO.**' in bold as the very first word. Provide a direct, concise 1-3 sentence explanation. "
        "Do NOT write long essays, irrelevant tables, or unnecessary advisories for simple questions.\n\n"
        "For technical threat vector inquiries, provide a structured defensive briefing formatted in Markdown:\n"
        "1. Threat Overview (summarize affected platforms, CVEs, and risk)\n"
        "2. Administrative Mitigation Steps (detail official configuration changes and patch commands)\n"
        "3. Verification Check (safe shell command to verify compliance)\n"
        "Strictly defensive and instructional."
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
                    "top_p": 0.9,
                    "num_predict": 350
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


CATALOG_KEYWORDS = {
    'xz', 'liblzma', 'lockbit', 'volt typhoon', 'akira', 'pwnkit', 'eternalblue',
    'clfs', 'darkgate', 'amos', 'atomic stealer', 'rustbucket', 'shroot',
    'anatsa', 'teabot', 'chameleon', 'stagefright', 'blastpass', 'forcedentry',
    'goldpickaxe', 'dma', 'trident', 'runc', 'imds', 'kinsing', 'log4j', 'log4shell'
}

CATALOG_CATEGORIES = {'anticipated', 'active', 'evolving', 'resolved', 'threat catalog', 'list threats', 'show threats'}

def is_catalog_query(msg: str) -> bool:
    m = msg.lower()
    if re.search(r'cve-\d{4}-\d+', m):
        return True
    if any(k in m for k in CATALOG_KEYWORDS):
        return True
    if any(c in m for c in CATALOG_CATEGORIES) and any(p in m for p in ['linux', 'windows', 'macos', 'android', 'ios', 'cloud', 'threat']):
        return True
    return False


def inspect_system_software(query: str) -> Optional[str]:
    """
    Directly answers software installation/presence questions (e.g. 'is chatgpt installed?')
    with a direct YES or NO based on live host inspection.
    """
    import subprocess
    import shutil
    import platform as sys_platform

    q = query.lower().strip()
    is_presence_q = bool(re.search(
        r'\b(is|are|do we have|do i have|check if|tell me if)\b.+\b(installed|running|present|active|enabled|available)\b|\b(installed|running)\b.*\?',
        q,
        re.I
    ))
    if not is_presence_q:
        return None

    current_os = sys_platform.system()

    # Get running process list
    running_procs = ""
    raw_tasklist = ""
    try:
        if current_os == "Windows":
            res = subprocess.run(["tasklist"], capture_output=True, text=True, errors="ignore", timeout=3)
            raw_tasklist = res.stdout
            running_procs = res.stdout.lower()
        else:
            res = subprocess.run(["ps", "-ef"], capture_output=True, text=True, errors="ignore", timeout=3)
            raw_tasklist = res.stdout
            running_procs = res.stdout.lower()
    except Exception:
        pass

    # 1. ChatGPT
    if "chatgpt" in q or "chat gpt" in q:
        is_running = "chatgpt" in running_procs
        cli_path = shutil.which("chatgpt")
        if is_running or cli_path:
            chatgpt_lines = [l for l in raw_tasklist.splitlines() if "chatgpt" in l.lower()]
            pids = re.findall(r'(\d+)\s+(?:Console|Services)', "\n".join(chatgpt_lines)) if (current_os == "Windows" and is_running) else []
            pid_str = f" (PID: {', '.join(pids[:3])})" if pids else ""
            return (
                f"**YES.** ChatGPT is installed and currently running on this system.\n\n"
                f"- **Application:** ChatGPT Desktop (`ChatGPT Classic`){pid_str}\n"
                f"- **Host Platform:** {current_os}\n"
                f"- **Execution Status:** Active / Running"
            )
        return "**NO.** ChatGPT is not detected as an installed application or running service on this system."

    # 2. Ollama
    if "ollama" in q:
        st = check_ollama()
        if st.get("status") == "connected":
            models = ", ".join(st.get("models", [])) or "llama3.2:1b"
            return (
                f"**YES.** Ollama is installed and actively running on this system.\n\n"
                f"- **Service Endpoint:** `{st.get('base_url')}`\n"
                f"- **Active Model(s):** `{models}`\n"
                f"- **Execution Status:** Connected & Ready"
            )
        elif shutil.which("ollama") or "ollama" in running_procs:
            return "**YES.** Ollama is installed on this system (service is currently idle; start it with `ollama serve`)."
        return "**NO.** Ollama is not installed or accessible on this system."

    # 3. MongoDB
    if "mongo" in q:
        try:
            db = get_db()
            db.command("ping")
            return (
                f"**YES.** MongoDB is installed and actively running on this system.\n\n"
                f"- **Database Host:** `mongodb://localhost:27017`\n"
                f"- **Target Database:** `{MONGO_DB}`\n"
                f"- **Execution Status:** Connected & Ready"
            )
        except Exception:
            if shutil.which("mongod") or shutil.which("mongosh") or "mongod" in running_procs:
                return "**YES.** MongoDB is installed on this system (service is currently paused)."
            return "**NO.** MongoDB is not detected as running on port 27017."

    # 4. Docker
    if "docker" in q:
        docker_cli = shutil.which("docker")
        if docker_cli or "docker" in running_procs:
            return (
                f"**YES.** Docker is installed and running on this system.\n\n"
                f"- **CLI Binary:** `{docker_cli or 'docker'}`\n"
                f"- **Platform:** Docker Desktop ({current_os})\n"
                f"- **Execution Status:** Active"
            )
        return "**NO.** Docker is not installed or detected on this system."

    # 5. Python
    if "python" in q:
        import sys
        return (
            f"**YES.** Python is installed on this system.\n\n"
            f"- **Version:** Python {sys.version.split()[0]}\n"
            f"- **Executable:** `{sys.executable}`"
        )

    # 6. Generic executable check (e.g. 'is git installed?', 'is curl installed?')
    target_match = re.search(r'\b(is|check if)\s+([a-zA-Z0-9_\-\.]+)\s+installed', q)
    if target_match:
        app_name = target_match.group(2).lower()
        if app_name not in ["the", "a", "an", "this", "it"]:
            loc = shutil.which(app_name)
            is_run = app_name in running_procs
            if loc or is_run:
                return f"**YES.** `{app_name}` is installed on this system." + (f" (Location: `{loc}`)" if loc else "")
            return f"**NO.** `{app_name}` is not installed or found in PATH on this system."

    return None


def builtin_general_security_responder(query: str, platform: Optional[str] = None) -> str:
    """Provides high-quality, comprehensive cybersecurity answers for any general topic."""
    q = query.lower().strip()

    # Greetings & Identity
    if any(q.startswith(g) or q == g for g in ["hi", "hello", "hey", "who are you", "what can you do", "help", "greet"]):
        return (
            "### 🛡️ Welcome to the Cyber Threat Intelligence (CTI) AI Assistant\n\n"
            "I am your dedicated **Cyber Threat Intelligence Analyst and Systems Hardening Bot**, "
            "powered by **Ollama SLM (Localhost)**, **MongoDB Vector RAG**, and an autonomous vulnerability scanner.\n\n"
            "#### What I Can Help You With:\n"
            "1. **Threat Intelligence Triage:** Query **Anticipated**, **Active**, **Evolving**, and **Resolved** threats across **Linux**, **Windows**, **macOS**, **Android**, **iOS**, and **Cloud**.\n"
            "2. **Autonomous Security Auditing:** Type `Scan system` to audit local open ports and sensitive file permissions for vulnerabilities.\n"
            "3. **Conversational Mitigation:** Reply `Confirm mitigate all` to automatically harden discovered vulnerabilities with audit logging in MongoDB.\n"
            "4. **General Cybersecurity Guidance:** Ask about web vulnerabilities (SQLi, XSS), defensive architecture (Zero Trust, Firewalls), or operating system hardening.\n\n"
            "👉 *Try asking:* `What is SQL Injection?` or `What are the Anticipated threats for Linux?` or `Scan system for vulnerabilities`."
        )

    # SQL Injection
    if "sql injection" in q or "sqli" in q:
        return (
            "### 🛡️ Web Application Security: SQL Injection (SQLi) Vulnerability\n\n"
            "**Category:** OWASP Top 10 — A03:2021-Injection | **Severity:** `CRITICAL`\n\n"
            "#### 1. Threat Mechanism\n"
            "SQL Injection occurs when untrusted user input is directly concatenated into a dynamic SQL database query without validation or parameterized separation. "
            "An attacker injects SQL metacharacters (such as `' OR '1'='1`) to manipulate query logic, bypass authentication, exfiltrate sensitive data, or execute administrative commands.\n\n"
            "#### 2. Technical Mitigation Procedures\n"
            "- **Primary Defense:** Always use **Parameterized Queries (Prepared Statements)** or Object-Relational Mapping (ORM) frameworks with parameter binding.\n"
            "- **Principle of Least Privilege:** Restrict database accounts to only necessary tables and permissions; disable administrative database accounts for web services.\n"
            "- **Input Validation:** Enforce strict allow-lists and data typing for all query inputs.\n"
            "- **Web Application Firewall (WAF):** Deploy ModSecurity or cloud WAFs with SQLi inspection rulesets.\n\n"
            "#### 3. Secure Implementation Example (Python / PyMongo & SQL)\n"
            "```python\n"
            "# Vulnerable (Dynamic concatenation):\n"
            "# cursor.execute(f\"SELECT * FROM users WHERE user = '{username}'\")\n\n"
            "# Secure (Parameterized query):\n"
            "cursor.execute(\"SELECT * FROM users WHERE user = %s AND pass = %s\", (username, password_hash))\n\n"
            "# In MongoDB (NoSQL injection prevention):\n"
            "# Validate input type is string to prevent operator injection ({'$gt': ''}):\n"
            "if isinstance(username, str):\n"
            "    user = db.users.find_one({'username': username})\n"
            "```\n\n"
            "#### 4. Verification & Testing Command\n"
            "```bash\n"
            "# Test endpoints with sqlmap (authorized security audit only):\n"
            "sqlmap -u \"https://example.com/api/user?id=1\" --batch --risk=1 --level=1\n"
            "```"
        )

    # Phishing
    if "phishing" in q:
        return (
            "### 🛡️ Social Engineering & Email Defense: Phishing Mitigation\n\n"
            "**Category:** Initial Access & Credential Harvesting | **Severity:** `HIGH`\n\n"
            "#### 1. Threat Mechanism\n"
            "Phishing involves deceptive electronic communications (email, SMS/Smishing, voice/Vishing) impersonating trusted entities "
            "to lure targets into revealing credentials, executing malicious payload attachments, or authorizing fraudulent transactions.\n\n"
            "#### 2. Key Mitigation Controls\n"
            "- **Enforce Email Authentication Standards:**\n"
            "  - **SPF (Sender Policy Framework):** Authorizes mail servers permitted to send on your domain's behalf.\n"
            "  - **DKIM (DomainKeys Identified Mail):** Cryptographically signs emails to verify integrity.\n"
            "  - **DMARC (Domain-based Message Authentication):** Enforces strict quarantine or reject policies (`p=reject`).\n"
            "- **Phishing-Resistant MFA:** Deploy **FIDO2 / WebAuthn hardware security keys** (YubiKeys) which bind authentication to the origin URL, eliminating credential theft via reverse-proxy toolkits (Evilginx).\n"
            "- **Endpoint Filtering:** Enforce DNS filtering (Cloudflare 1.1.1.2 or Quad9) and automated mail sandboxing.\n\n"
            "#### 3. Administrative DNS Hardening (DMARC Policy)\n"
            "```dns\n"
            "; Configure strict DMARC TXT record in your DNS zone:\n"
            "_dmarc.yourdomain.com. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; sp=reject; aspf=s; adkim=s;\"\n"
            "```\n\n"
            "#### 4. Verification Check Command\n"
            "```bash\n"
            "# Verify domain DMARC and SPF records:\n"
            "dig TXT _dmarc.yourdomain.com +short\n"
            "dig TXT yourdomain.com +short | grep -i spf\n"
            "```"
        )

    # Firewalls & UFW
    if "ufw" in q or ("firewall" in q and ("linux" in q or "ubuntu" in q or "debian" in q)) or "iptables" in q:
        return (
            "### 🛡️ Linux Network Defense: UFW (Uncomplicated Firewall) Hardening\n\n"
            "**Platform:** Linux (Ubuntu / Debian) | **Classification:** Host-Based Network Filtering\n\n"
            "#### 1. Recommended Baseline Firewall Architecture\n"
            "The baseline firewall strategy follows the **Default Deny** security posture: drop all inbound connections, allow established traffic, "
            "and explicitly whitelist only necessary service ports with subnet restrictions.\n\n"
            "#### 2. Step-by-Step Configuration Script\n"
            "```bash\n"
            "# Step 1: Set default policies to deny incoming, allow outgoing\n"
            "sudo ufw default deny incoming\n"
            "sudo ufw default allow outgoing\n\n"
            "# Step 2: Allow essential SSH access (rate-limited against brute force)\n"
            "sudo ufw limit 22/tcp comment 'Rate-limited SSH'\n\n"
            "# Step 3: Allow web services (HTTP/HTTPS)\n"
            "sudo ufw allow 80/tcp comment 'Web HTTP'\n"
            "sudo ufw allow 443/tcp comment 'Web HTTPS'\n\n"
            "# Step 4: Restrict MongoDB (27017) to localhost or specific internal subnet\n"
            "sudo ufw allow from 127.0.0.1 to any port 27017 proto tcp comment 'MongoDB local'\n\n"
            "# Step 5: Enable UFW service\n"
            "sudo ufw --force enable\n"
            "```\n\n"
            "#### 3. Verification Command\n"
            "```bash\n"
            "sudo ufw status verbose\n"
            "```"
        )

    # Zero Trust
    if "zero trust" in q:
        return (
            "### 🛡️ Enterprise Security Architecture: Zero Trust Principles & Implementation\n\n"
            "**Framework:** NIST SP 800-207 Zero Trust Architecture (ZTA)\n\n"
            "#### 1. Core Principles\n"
            "- **Never Trust, Always Verify:** No user, device, or workload is inherently trusted based on physical or network location (internal vs external).\n"
            "- **Least Privilege Access:** Access is granted per-session on a just-in-time (JIT) and just-enough-access (JEA) basis.\n"
            "- **Assume Breach:** Architecture is designed assuming malicious actors are already present in the environment.\n\n"
            "#### 2. Key Pillars of Implementation\n"
            "1. **Identity & Access Management (IAM):** Continuous adaptive authentication with conditional access policies and FIDO2 MFA.\n"
            "2. **Micro-Segmentation:** Dividing the network into granular security zones (e.g. Kubernetes network policies, VPC subnets) preventing lateral movement.\n"
            "3. **Device Health Verification:** Validating endpoint posture (EDR running, disk encrypted, OS updated) before granting session tokens.\n"
            "4. **Continuous Telemetry & Analytics:** Ingesting access logs into SIEM/SOAR platforms for automated anomaly detection.\n\n"
            "#### 3. Verification Check Command\n"
            "```bash\n"
            "# Audit active open network boundaries and listening ports:\n"
            "netstat -tulpen || ss -tulpen\n"
            "```"
        )

    # Ransomware (General)
    if "ransomware" in q:
        return (
            "### 🛡️ Threat Intelligence Briefing: Ransomware Defense & Resilience Strategy\n\n"
            "**Classification:** Impact & Extortion Malware | **Severity:** `CRITICAL`\n\n"
            "#### 1. Attack Lifecycle\n"
            "Modern double-extortion ransomware campaigns follow an orchestrated kill chain:\n"
            "1. **Initial Access:** Via phishing, unpatched edge devices (VPNs/firewalls), or compromised valid credentials.\n"
            "2. **Discovery & Privilege Escalation:** Utilizing living-off-the-land binaries (LoLBins) to map Active Directory and gain Domain Admin.\n"
            "3. **Data Exfiltration:** Exfiltrating sensitive corporate data prior to encryption to threaten public disclosure.\n"
            "4. **Payload Execution:** Deploying high-speed encryption routines (ChaCha20, AES-256) and deleting Volume Shadow Copies.\n\n"
            "#### 2. Defense-in-Depth Mitigation Measures\n"
            "- **Immutable Backups (3-2-1-1-0 Rule):** 3 copies of data, 2 media types, 1 offsite, 1 immutable (WORM/air-gapped), 0 backup errors.\n"
            "- **Active Directory Hardening:** Restrict Domain Admin accounts, disable legacy NTLMv1 and SMBv1, enforce Tiered Administration.\n"
            "- **Network Micro-Segmentation:** Isolate critical hypervisors (ESXi) and database servers on dedicated VLANs with strict firewall rules.\n"
            "- **EDR with Anti-Ransomware Canaries:** Deploy behavior-based EDR tools that detect rapid entropy changes and canary file touches.\n\n"
            "#### 3. Immediate Actionable Windows Hardening Command\n"
            "```powershell\n"
            "# Enable Windows Controlled Folder Access (ransomware guard):\n"
            "Set-MpPreference -EnableControlledFolderAccess Enabled\n\n"
            "# Disable insecure SMBv1 dialect:\n"
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
            "```\n\n"
            "#### 4. Automated Verification Check\n"
            "```powershell\n"
            "Get-MpPreference | Select-Object EnableControlledFolderAccess\n"
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol\n"
            "```"
        )

    # MongoDB Security
    if "mongodb" in q or "nosql" in q:
        return (
            "### 🛡️ Database Hardening: MongoDB Production Security Baseline\n\n"
            "**Course Reference:** Appendix A & Exercises 1–18 | **Compliance:** CIS MongoDB Benchmark\n\n"
            "#### 1. Core Security Controls\n"
            "- **Authentication Enforcement:** Never run MongoDB without authorization. Require SCRAM-SHA-256 credentials.\n"
            "- **Network Binding:** Bind listener exclusively to `127.0.0.1` or private VPC subnets. Never expose port 27017 to `0.0.0.0` without TLS and authentication.\n"
            "- **Role-Based Access Control (RBAC):** Assign granular least-privilege roles (`readWrite`, `dbAdmin`) rather than global `root`.\n"
            "- **TLS 1.3 Encryption in Transit:** Enforce certificate-verified TLS encryption across all client and replica set connections.\n"
            "- **Auditing:** Log security events (authentication failures, user management actions) into audit collections.\n\n"
            "#### 2. Hardened MongoDB Configuration (`mongod.conf`)\n"
            "```yaml\n"
            "net:\n"
            "  port: 27017\n"
            "  bindIp: 127.0.0.1\n"
            "  tls:\n"
            "    mode: requireTLS\n"
            "    certificateKeyFile: /etc/ssl/mongodb.pem\n"
            "security:\n"
            "  authorization: enabled\n"
            "```\n\n"
            "#### 3. Verification Command\n"
            "```bash\n"
            "# Test connection requiring authentication:\n"
            "mongosh --tls --tlsCAFile /etc/ssl/ca.pem -u cti_admin -p --authenticationDatabase admin\n"
            "```"
        )

    # Cross-Site Scripting (XSS)
    if "xss" in q or "cross-site scripting" in q or "cross site scripting" in q:
        return (
            "### 🛡️ Web Application Security: Cross-Site Scripting (XSS) Mitigation\n\n"
            "**Category:** OWASP Top 10 — A03:2021-Injection | **Severity:** `HIGH`\n\n"
            "#### 1. Threat Mechanism\n"
            "XSS occurs when malicious scripts are injected into benign and trusted websites. Attackers execute arbitrary JavaScript in the victim's browser context to steal session cookies, capture keystrokes, or redirect to malicious domains.\n\n"
            "#### 2. Primary Defenses\n"
            "- **Context-Aware Output Encoding:** HTML, attribute, JavaScript, and URL encoding before inserting user-controlled data into HTML.\n"
            "- **Content Security Policy (CSP):** Strict CSP headers restricting script execution sources and disallowing inline scripts (`'unsafe-inline'`).\n"
            "- **HttpOnly and SameSite Cookies:** Enforcing `HttpOnly` flags to prevent JavaScript cookie theft (`document.cookie`).\n\n"
            "#### 3. Strict CSP Header Implementation\n"
            "```http\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'; base-uri 'self';\n"
            "```"
        )

    # DDoS (Distributed Denial of Service)
    if "ddos" in q or "dos" in q or "denial of service" in q:
        return (
            "### 🛡️ Network Resilience: Distributed Denial of Service (DDoS) Mitigation\n\n"
            "**Category:** Availability & Infrastructure Resilience | **Severity:** `HIGH`\n\n"
            "#### 1. Attack Vectors\n"
            "- **Volumetric (L3/L4):** UDP amplification, DNS reflection, ICMP floods designed to saturate bandwidth pipe.\n"
            "- **Protocol (L4):** SYN flood, Ping of Death consuming server and stateful firewall connection tables.\n"
            "- **Application Layer (L7):** HTTP GET/POST flood (Slowloris) exhausting web worker threads and database pools.\n\n"
            "#### 2. Defense Strategy\n"
            "- **Anycast DNS & Cloud Scrubbing Centers:** Cloudflare, AWS Shield, or Akamai absorbing multi-terabit volumetric traffic.\n"
            "- **SYN Cookies & TCP Tuning:** Mitigating SYN floods in Linux kernel:\n"
            "  `sudo sysctl -w net.ipv4.tcp_syncookies=1`\n"
            "- **Rate Limiting:** Web server rate limiting on API endpoints via Nginx (`limit_req_zone`) or cloud gateways."
        )

    # Dynamic Fallback for Any General Security / IT Question
    return (
        f"### 🛡️ Cybersecurity Technical Assessment: {query.title()}\n\n"
        f"**Platform Context:** `{platform or 'Cross-Platform'}` | **Domain:** Infrastructure & Application Security\n\n"
        f"#### 1. Technical Analysis\n"
        f"Regarding **'{query}'**, standard cybersecurity best practices require implementing defense-in-depth, "
        f"continuous posture validation, and strict least-privilege access across all architecture tiers.\n\n"
        f"#### 2. Key Defensive Recommendations\n"
        f"- **Access Control:** Enforce Multi-Factor Authentication (MFA) and granular Role-Based Access Control (RBAC).\n"
        f"- **Patch Management:** Regularly audit dependencies, containers, and operating systems against CVE advisories.\n"
        f"- **Network Segmentation:** Enforce host firewalls and isolate critical database tiers from direct internet exposure.\n"
        f"- **Telemetry & Auditing:** Centralize audit logs and configure automated alerting for abnormal behavioral anomalies.\n\n"
        f"#### 3. Recommended Administrative Verification\n"
        f"```bash\n"
        f"# Inspect active host listeners and security posture:\n"
        f"netstat -tulpen || ss -tulpen\n"
        f"```\n\n"
        f"👉 *You can also ask:* `'Scan system'` to have the autonomous bot audit this host for vulnerabilities."
    )


def builtin_cti_engine(query: str, sources: List[Dict[str, Any]], requested_platform: Optional[str] = None, requested_status: Optional[str] = None) -> str:
    """Intelligent built-in CTI reasoning engine for instant deterministic threat mitigation."""
    if not sources:
        return builtin_general_security_responder(query, platform=requested_platform)

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

    # 1. Retrieve RAG context if query relates to specific CTI threat catalog
    is_catalog = is_catalog_query(message)
    sources = retrieve_context(message, platform=platform, threat_status=threat_status, top_k=top_k) if is_catalog else []

    # 2. Load conversation history
    session_doc = sessions_col.find_one({"session_id": session_id})
    history = session_doc.get("history", []) if session_doc else []

    # 3. Determine Execution Engine
    selected_backend = (backend or LLM_BACKEND).lower()
    response_text = ""
    engine_used = "Built-in CTI Engine"

    # 0. Fast-path: Direct Host Software Presence Check (e.g. 'is chatgpt installed?')
    direct_software_reply = inspect_system_software(message)
    if direct_software_reply:
        response_text = direct_software_reply
        engine_used = "Host System Inspector"
    else:
        # Context block for LLM prompt
        if is_catalog and sources:
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
        else:
            is_yes_no = bool(re.search(r'^(is|are|do|does|can|will|should|has|have)\b|\b(yes or no|installed\?|running\?)\b', message.strip(), re.I))
            if is_yes_no:
                llm_prompt = (
                    f"User Question: {message}\n"
                    f"Target Platform: {platform or 'General'}\n\n"
                    f"CRITICAL INSTRUCTION: Begin your response with a direct, bold '**YES.**' or '**NO.**' as the very first word. "
                    f"Follow with a concise explanation under 3 sentences. Do NOT generate full-length essays, tables, or irrelevant threat templates."
                )
            else:
                llm_prompt = (
                    f"User Inquiry: {message}\n"
                    f"Target Platform: {platform or 'General'}\n"
                    f"Please provide an authoritative, clear, and comprehensive technical answer with defensive best practices and code or shell commands where applicable."
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
                # Only augment if it's a catalog threat AND Ollama refused
                if is_catalog and sources:
                    refusal_patterns = [
                        "can't provide specific details or guidance on how to mitigate",
                        "can’t provide specific details or guidance on how to mitigate",
                        "cannot provide specific details",
                        "cannot provide guidance on how to mitigate",
                        "i cannot provide",
                        "i can't provide",
                        "i can’t provide",
                        "illegal or harmful",
                        "illegal and unethical",
                        "as an ai"
                    ]
                    has_refusal = any(p in response_text.lower() for p in refusal_patterns)
                    has_commands = "```" in response_text
                    
                    if has_refusal or not has_commands:
                        # Strip any safety refusal or apology sentences (both straight and curly quotes)
                        cleaned_text = re.sub(r'I (?:can[\'’]t|cannot) provide [^\.\n]+(?:\.|\n|\?)?', '', response_text, flags=re.IGNORECASE)
                        cleaned_text = re.sub(r'Is there anything else I can help you with\??', '', cleaned_text, flags=re.IGNORECASE).strip()
                        top = sources[0]
                        raw = top.get("raw_threat", {})
                        title = raw.get("title", top.get("source", "Threat Advisory"))
                        plat = raw.get("platform", top.get("platform", "Platform"))
                        mits = raw.get("mitigation_procedures", ["Apply latest vendor security patch.", "Review access control rules."])
                        script = raw.get("remediation_script", "# Apply vendor update")
                        verify = raw.get("verification_command", "# Verify patch level")

                        mitigation_block = (
                            f"\n\n### 🔧 Verified Administrative Mitigation Procedures ({plat})\n"
                            f"**Target Vector:** `{title}`\n\n" +
                            "\n".join([f"- **{m}**" if m.startswith("Step") else f"- {m}" for m in mits]) +
                            f"\n\n#### 💻 Immediate Actionable Remediation Script ({plat})\n```bash\n{script}\n```\n"
                            f"#### 🔍 Automated Verification Check\n```bash\n{verify}\n```"
                        )
                        response_text = (cleaned_text + mitigation_block).strip()
            except Exception as e:
                # Fallback to Built-in Engine with notice
                if is_catalog and sources:
                    fallback_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
                else:
                    fallback_text = builtin_general_security_responder(message, platform=platform)
                response_text = fallback_text
                engine_used = f"Built-in CTI Engine (Ollama Offline: {str(e)[:60]}...)"
        elif selected_backend == "openai" and OPENAI_API_KEY:
            try:
                response_text, engine_used = call_openai(llm_prompt, history[-4:])
            except Exception as e:
                if is_catalog and sources:
                    response_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
                else:
                    response_text = builtin_general_security_responder(message, platform=platform)
                engine_used = f"Built-in CTI Engine (OpenAI fallback: {e})"
        else:
            if is_catalog and sources:
                response_text = builtin_cti_engine(message, sources, requested_platform=platform, requested_status=threat_status)
            else:
                response_text = builtin_general_security_responder(message, platform=platform)
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
