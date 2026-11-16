# NoSQL Lab 7 — Cyber Threat Intelligence Platform

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
