# NoSQL Lab 7 — Cyber Threat Intelligence Platform (Labs 1–18 & Appendix A)

**Student:** M Gouthami (`24BTRCL130`)  
**Course:** NoSQL Databases using MongoDB

---

## 🌐 Live Access for Faculty (Click to Open)

- **Live Labs Portal (All 18 Labs + Appendix A):** https://no-sql-lab-7.vercel.app/labs.html
- **AI Threat Intelligence Chatbot (Appendix A):** https://no-sql-lab-7.vercel.app/chatbot.html
- **Official Full Lab Report (Chapters 1–18 PDF):** [Lab_Experiments_Report_Chapters_1_18.pdf](frontend/reports/Lab_Experiments_Report_Chapters_1_18.pdf)
- **Mini-Project LLM Chatbot Report (PDF):** [Mini_Project_Report_LLM_Chatbot.pdf](frontend/reports/Mini_Project_Report_LLM_Chatbot.pdf)
- **Docker Hub Image:** https://hub.docker.com/r/gouthudocker/nosql-lab-7

### Direct Links to Every Lab (Interactive Report + Simulator)

| Chapter | Lab Title | Live Web Page (Vercel) |
| :--- | :--- | :--- |
| Lab 1 | NoSQL Database Families & Application Mapping | https://no-sql-lab-7.vercel.app/lab1_reports.html |
| Lab 2 | Environment Setup & PyMongo CRUD Essentials | https://no-sql-lab-7.vercel.app/lab2_reports.html |
| Lab 3 | Document Modeling: Embedding vs Referencing | https://no-sql-lab-7.vercel.app/lab3_reports.html |
| Lab 4 | Advanced CRUD Operations, Filters & Bulk Upserts | https://no-sql-lab-7.vercel.app/lab4_reports.html |
| Lab 5 | Aggregation Framework & Threat Analytics | https://no-sql-lab-7.vercel.app/lab5_reports.html |
| Lab 6 | Indexing Design, ESR Rule & Explain Plans | https://no-sql-lab-7.vercel.app/lab6_reports.html |
| Lab 7 | Production Schema & Working Set Analysis | https://no-sql-lab-7.vercel.app/lab_reports.html |
| Lab 8 | Replica Sets & High Availability Failover | https://no-sql-lab-7.vercel.app/lab8_reports.html |
| Lab 9 | CAP Theorem & Write Concerns | https://no-sql-lab-7.vercel.app/lab9_reports.html |
| Lab 10 | Multi-Document ACID Transactions | https://no-sql-lab-7.vercel.app/lab10_reports.html |
| Lab 11 | Sharding & Horizontal Scalability | https://no-sql-lab-7.vercel.app/lab11_reports.html |
| Lab 12 | Security, RBAC, TLS & Encryption | https://no-sql-lab-7.vercel.app/lab12_reports.html |
| Lab 13 | Cloud & Containers (Docker / K8s) | https://no-sql-lab-7.vercel.app/lab13_reports.html |
| Lab 14 | Managing Services in Production & PITR | https://no-sql-lab-7.vercel.app/lab14_reports.html |
| Lab 15 | Multi-Tenant Architecture & Tenant Isolation | https://no-sql-lab-7.vercel.app/lab15_reports.html |
| Lab 16 | Polyglot Persistence (MongoDB, Cassandra, Neo4j) | https://no-sql-lab-7.vercel.app/lab16_reports.html |
| Lab 17 | AI Vector Search, Embeddings & RAG | https://no-sql-lab-7.vercel.app/lab17_reports.html |
| Lab 18 | Comparative Capstone Benchmark | https://no-sql-lab-7.vercel.app/lab18_reports.html |
| Appendix A | LLM/SLM Threat Intelligence Chatbot & Bot | https://no-sql-lab-7.vercel.app/chatbot.html |

### Run via Docker Hub
```bash
docker pull gouthudocker/nosql-lab-7:latest
docker run -d -p 5000:5000 --name nosql_cti_app gouthudocker/nosql-lab-7:latest
```
Then open `http://localhost:5000/labs.html`.

---

## Project Structure

```
NoSQL_Lab_7/
├── README.md
├── lab_01_production_schema.py      # Original Lab 7.1 starter (blog example)
├── lab_02_working_set_analysis.py   # Original Lab 7.2 starter
├── MongoDB_Use-Cases.png
├── backend/
│   ├── app.py                       # Flask application entry point
│   ├── config.py                    # MongoDB connection
│   ├── run.py                       # Start server
│   ├── requirements.txt
│   ├── seed_data.py                 # Seed CTI data into MongoDB
│   ├── lab_01_cti_schema.py         # Lab 7.1 — CTI schema analysis
│   ├── lab_02_working_set.py        # Lab 7.2 — Working set + monitoring
│   └── routes/
│       ├── indicators.py            # /api/indicators
│       ├── reports.py               # /api/reports
│       ├── actors.py                # /api/actors
│       ├── analytics.py             # /api/analytics (bsonSize, cache)
│       └── monitor.py               # /api/monitor (cache-hit-ratio)
└── frontend/
    ├── index.html                   # Dashboard
    ├── indicators.html              # Threat Indicators (search + classify)
    ├── reports.html                 # Threat Reports
    ├── actors.html                  # Threat Actors
    ├── analytics.html               # Lab 7.1 & 7.2 analytics
    ├── lab_reports.html             # Lab write-up page
    ├── css/styles.css
    └── js/
        ├── api.js                   # API client
        ├── utils.js                 # Shared utilities
        └── dashboard.js             # Dashboard charts
```

## Setup & Run

### 1. Prerequisites
- MongoDB 9.x running on `localhost:27017` (already installed)
- Python 3.13 installed at `C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe`

### 2. Install dependencies
```powershell
cd backend
C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe -m pip install -r requirements.txt
```

### 3. Seed the database
```powershell
C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe backend/seed_data.py
```

### 4. Start the backend
```powershell
C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe backend/run.py
```
Backend will be available at: **http://localhost:5000**

### 5. Open the frontend
Open `frontend/index.html` directly in your browser.

---

## Lab Activities

### Lab 7.1 — Analyze a Production Schema
```powershell
C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe backend/lab_01_cti_schema.py
```

**Embedding vs Referencing decisions in CTI platform:**

| Relationship | Pattern | Reason |
|---|---|---|
| `indicators.sources[]` | **EMBEDDED** | Always read with indicator; bounded ~10 items; no independent updates |
| `indicators.attribution.mitre_attack` | **EMBEDDED** | Small, static MITRE tactic/technique codes |
| `reports.related_indicators[]` | **REFERENCED** | Indicators shared across reports; update independently |
| `indicators → threat_actors` | **REFERENCED** | Actor profiles are large; shared across 100s of indicators |

**Activity:** Embedding threat_actor summary into attribution makes actor-name lookups faster but makes actor profile updates require touching every indicator.

### Lab 7.2 — Working Set Analysis
```powershell
C:\Users\gouth\AppData\Local\Programs\Python\Python313\python.exe backend/lab_02_working_set.py
```

Inserts 100,000 ~2KB documents and monitors WiredTiger cache hit ratio every 10 seconds.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/indicators` | List/search indicators |
| GET | `/api/indicators/stats` | Dashboard stats |
| GET | `/api/indicators/<id>` | Single indicator |
| POST | `/api/indicators` | Create indicator |
| PUT | `/api/indicators/<id>` | Update indicator |
| DELETE | `/api/indicators/<id>` | Delete indicator |
| GET | `/api/reports` | List reports |
| GET | `/api/reports/<id>` | Single report |
| GET | `/api/actors` | List threat actors |
| GET | `/api/analytics/bson-sizes` | BSON size analysis |
| GET | `/api/analytics/cache-stats` | WiredTiger cache stats |
| GET | `/api/monitor/cache-hit-ratio` | Live cache hit ratio |
| POST | `/api/monitor/check-new-reports` | Simulate new report check |
