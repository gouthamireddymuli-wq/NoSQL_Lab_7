"""
seed_data.py – Seeds the cti_platform MongoDB database with realistic CTI data.

Run with:
    C:\\Users\\gouth\\AppData\\Local\\Programs\\Python\\Python313\\python.exe seed_data.py
"""
import sys
import os
import datetime
import random
from pymongo import MongoClient, ASCENDING, TEXT

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["cti_platform"]

indicators_col = db["indicators"]
threat_actors_col = db["threat_actors"]
reports_col = db["reports"]
feed_sources_col = db["feed_sources"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def dt(year, month, day, hour=0, minute=0):
    return datetime.datetime(year, month, day, hour, minute)

def rand_dt(start_year=2022, end_year=2024):
    year = random.randint(start_year, end_year)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return datetime.datetime(year, month, day)

# ---------------------------------------------------------------------------
# 1. Feed Sources (5)
# ---------------------------------------------------------------------------
FEED_SOURCES = [
    {
        "feed_id": "fs-001",
        "name": "AlienVault OTX",
        "url": "https://otx.alienvault.com/api/v1/indicators",
        "type": "OSINT",
        "reliability_score": 85,
        "last_synced": dt(2024, 11, 14, 6, 0),
        "indicators_count": 12400
    },
    {
        "feed_id": "fs-002",
        "name": "Abuse.ch URLhaus",
        "url": "https://urlhaus-api.abuse.ch/v1/",
        "type": "OSINT",
        "reliability_score": 92,
        "last_synced": dt(2024, 11, 14, 8, 30),
        "indicators_count": 8700
    },
    {
        "feed_id": "fs-003",
        "name": "MISP Community Feed",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "type": "Community",
        "reliability_score": 78,
        "last_synced": dt(2024, 11, 13, 22, 0),
        "indicators_count": 34500
    },
    {
        "feed_id": "fs-004",
        "name": "Recorded Future Intel",
        "url": "https://api.recordedfuture.com/v2/",
        "type": "Commercial",
        "reliability_score": 97,
        "last_synced": dt(2024, 11, 14, 10, 0),
        "indicators_count": 5200
    },
    {
        "feed_id": "fs-005",
        "name": "Emerging Threats Ruleset",
        "url": "https://rules.emergingthreats.net/open/",
        "type": "OSINT",
        "reliability_score": 88,
        "last_synced": dt(2024, 11, 14, 4, 0),
        "indicators_count": 19800
    },
]

# ---------------------------------------------------------------------------
# 2. Threat Actors (10)
# ---------------------------------------------------------------------------
THREAT_ACTORS = [
    {
        "actor_id": "ta-001",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
        "country": "Russia",
        "motivation": "Espionage",
        "sophistication": "Expert",
        "description": "APT29 is a threat group attributed to the Russian Foreign Intelligence Service (SVR). They target governments, diplomatic entities, NGOs and IT service providers.",
        "ttps": ["Spearphishing", "Supply-chain compromise", "Living off the land"],
        "tools_used": ["SUNBURST", "WellMess", "BEATDROP", "PowerDuke"],
        "targets": ["Government", "Defense", "Healthcare", "Think Tanks"]
    },
    {
        "actor_id": "ta-002",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard"],
        "country": "Russia",
        "motivation": "Espionage",
        "sophistication": "Expert",
        "description": "APT28 is associated with Russian military intelligence (GRU). Known for election interference and attacks on NATO member states.",
        "ttps": ["Credential harvesting", "Watering hole attacks", "Spearphishing"],
        "tools_used": ["X-Agent", "Komplex", "Zebrocy", "LOOBACK"],
        "targets": ["Government", "Military", "Media", "Political Parties"]
    },
    {
        "actor_id": "ta-003",
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Diamond Sleet"],
        "country": "North Korea",
        "motivation": "Financial Gain / Espionage",
        "sophistication": "Expert",
        "description": "North Korean state-sponsored group responsible for WannaCry, Sony Pictures hack, and numerous cryptocurrency heists.",
        "ttps": ["Custom malware", "Supply-chain compromise", "Cryptocurrency theft"],
        "tools_used": ["BLINDINGCAN", "COPPERHEDGE", "TAINTEDSCRIBE"],
        "targets": ["Financial", "Cryptocurrency", "Defense", "Energy"]
    },
    {
        "actor_id": "ta-004",
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "BlackEnergy Group", "Seashell Blizzard"],
        "country": "Russia",
        "motivation": "Sabotage / Espionage",
        "sophistication": "Expert",
        "description": "GRU-linked group responsible for attacks on Ukrainian infrastructure, NotPetya, and Olympic Destroyer.",
        "ttps": ["ICS/SCADA attacks", "Destructive wiper malware", "Spearphishing"],
        "tools_used": ["NotPetya", "Industroyer", "Olympic Destroyer", "Exaramel"],
        "targets": ["Energy", "Critical Infrastructure", "Government", "Media"]
    },
    {
        "actor_id": "ta-005",
        "name": "Kimsuky",
        "aliases": ["Velvet Chollima", "Black Banshee", "Thallium"],
        "country": "North Korea",
        "motivation": "Espionage",
        "sophistication": "Advanced",
        "description": "North Korean APT focused on intelligence collection targeting South Korea, US think tanks and government entities.",
        "ttps": ["Spearphishing", "BEC", "Watering hole"],
        "tools_used": ["BabyShark", "AppleSeed", "Gh0st RAT"],
        "targets": ["Government", "Defense", "Think Tanks", "Education"]
    },
    {
        "actor_id": "ta-006",
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "Gold Mystic"],
        "country": "Unknown",
        "motivation": "Financial Gain",
        "sophistication": "Advanced",
        "description": "Prolific ransomware-as-a-service (RaaS) operation responsible for thousands of attacks globally.",
        "ttps": ["RaaS model", "Double extortion", "Affiliate program"],
        "tools_used": ["LockBit ransomware", "StealBit exfiltration tool"],
        "targets": ["Healthcare", "Legal", "Financial", "Manufacturing"]
    },
    {
        "actor_id": "ta-007",
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Muddled Libra", "Oktapus"],
        "country": "USA/UK",
        "motivation": "Financial Gain",
        "sophistication": "Intermediate",
        "description": "English-speaking cybercriminal group known for social engineering and SIM swapping targeting telecom and casino industries.",
        "ttps": ["Social engineering", "SIM swapping", "MFA bypass"],
        "tools_used": ["SpecterRAT", "ALPHV/BlackCat ransomware"],
        "targets": ["Telecommunications", "Hospitality", "Retail"]
    },
    {
        "actor_id": "ta-008",
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "country": "China",
        "motivation": "Espionage / Pre-positioning",
        "sophistication": "Expert",
        "description": "Chinese state-sponsored group targeting US critical infrastructure with living-off-the-land techniques.",
        "ttps": ["Living off the land", "SOHO router compromise", "Lateral movement"],
        "tools_used": ["Custom web shells", "Impacket", "FRP tunneler"],
        "targets": ["Critical Infrastructure", "Military", "Communications", "Energy"]
    },
    {
        "actor_id": "ta-009",
        "name": "FIN7",
        "aliases": ["Carbanak", "Carbon Spider", "Navigator Group"],
        "country": "Russia/Ukraine",
        "motivation": "Financial Gain",
        "sophistication": "Expert",
        "description": "Sophisticated financially motivated group targeting retail, restaurant, and hospitality sectors with POS malware.",
        "ttps": ["Spearphishing", "POS malware", "Supply-chain attacks"],
        "tools_used": ["CARBANAK", "GRIFFON", "LOADOUT", "PILLOWMINT"],
        "targets": ["Retail", "Restaurant", "Hospitality", "Financial"]
    },
    {
        "actor_id": "ta-010",
        "name": "Cl0p",
        "aliases": ["TA505", "Gold Tahoe"],
        "country": "Russia",
        "motivation": "Financial Gain",
        "sophistication": "Advanced",
        "description": "Ransomware group responsible for mass exploitation of zero-day vulnerabilities in file transfer solutions (MOVEit, GoAnywhere).",
        "ttps": ["Zero-day exploitation", "Mass data theft", "Extortion"],
        "tools_used": ["Cl0p ransomware", "SDBOT", "FlawedAmmyy"],
        "targets": ["Healthcare", "Financial", "Education", "Legal"]
    },
]

# ---------------------------------------------------------------------------
# 3. Indicators (50+)
# ---------------------------------------------------------------------------
def make_sources(count=2):
    feeds = random.sample(FEED_SOURCES, min(count, len(FEED_SOURCES)))
    return [
        {
            "feed_name": f["name"],
            "source_id": f["feed_id"],
            "first_reported": rand_dt(2022, 2024),
            "reliability": f["reliability_score"],
            "original_tags": random.sample(["malware", "c2", "phishing", "scanner", "botnet", "exploit"], 2)
        }
        for f in feeds
    ]

def make_attribution(actor_ids, campaign, malware_names, tactics, techniques):
    actors_summary = [
        {"actor_id": a["actor_id"], "name": a["name"], "aliases": a["aliases"][:2]}
        for a in THREAT_ACTORS if a["actor_id"] in actor_ids
    ]
    malware = [{"malware_id": f"mw-{i+1:03d}", "name": n} for i, n in enumerate(malware_names)]
    return {
        "threat_actors": actors_summary,
        "campaigns": [campaign],
        "malware_families": malware,
        "mitre_attack": {
            "tactics": tactics,
            "techniques": techniques
        }
    }

STATUSES = ["active", "active", "active", "expired", "revoked"]
SEVERITIES = ["low", "medium", "high", "critical"]
THREAT_TYPES_POOL = [
    "malicious-activity", "phishing", "ransomware", "command-and-control",
    "exploit", "ddos", "data-exfiltration", "credential-theft", "malware-distribution"
]

RAW_INDICATORS = [
    # IPv4
    ("ipv4-addr", "192.168.1.200",   "high",     ["ta-001"], "Operation Ghost", ["WellMess"],       ["TA0011"],            ["T1071.001"]),
    ("ipv4-addr", "45.33.32.156",    "critical",  ["ta-004"], "ShadowGrid",      ["Industroyer"],    ["TA0040", "TA0011"],  ["T1486", "T1041"]),
    ("ipv4-addr", "185.220.101.47",  "high",     ["ta-006"], "LockBit Wave 3",  ["LockBit"],        ["TA0010"],            ["T1041"]),
    ("ipv4-addr", "103.75.190.100",  "medium",   ["ta-003"], "BlueNoroff",      ["BLINDINGCAN"],    ["TA0043"],            ["T1595"]),
    ("ipv4-addr", "91.195.240.117",  "critical",  ["ta-002"], "FancyBear 2024",  ["X-Agent"],        ["TA0001", "TA0011"],  ["T1566", "T1071"]),
    ("ipv4-addr", "194.165.16.78",   "high",     ["ta-009"], "Carbanak",        ["CARBANAK"],       ["TA0006"],            ["T1056"]),
    ("ipv4-addr", "23.106.122.254",  "medium",   ["ta-007"], "OktaPhish",       ["SpecterRAT"],     ["TA0001"],            ["T1566.002"]),
    ("ipv4-addr", "5.188.206.19",    "high",     ["ta-010"], "MOVEit Blast",    ["Cl0p"],           ["TA0001", "TA0010"],  ["T1190", "T1041"]),
    ("ipv4-addr", "185.141.62.123",  "critical",  ["ta-004"], "Industroyer2",    ["Industroyer"],    ["TA0040"],            ["T1489"]),
    ("ipv4-addr", "109.70.100.33",   "low",      ["ta-005"], "Operation Kimchi","AppleSeed",        ["TA0043"],            ["T1598"]),
    ("ipv4-addr", "77.83.249.19",    "high",     ["ta-001"], "Cozy Bear APT",   ["BEATDROP"],       ["TA0011"],            ["T1071.004"]),
    ("ipv4-addr", "185.56.89.211",   "medium",   ["ta-002"], "Zebrocy Ops",     ["Zebrocy"],        ["TA0001"],            ["T1566.001"]),
    ("ipv4-addr", "192.0.2.1",       "low",      [],         "Unknown",         [],                 ["TA0043"],            ["T1595"]),
    ("ipv4-addr", "10.10.0.5",       "medium",   ["ta-008"], "Volt Typhoon",    [],                 ["TA0011"],            ["T1090"]),
    ("ipv4-addr", "198.51.100.42",   "high",     ["ta-003"], "LAZARUS C2",      ["COPPERHEDGE"],    ["TA0011"],            ["T1095"]),
    # Domains
    ("domain-name", "malware-c2.ru",             "critical",  ["ta-001"], "Operation Ghost",  ["WellMess"],    ["TA0011"], ["T1071.001"]),
    ("domain-name", "update-service.xyz",         "high",     ["ta-006"], "LockBit Wave 3",   ["LockBit"],     ["TA0011"], ["T1071"]),
    ("domain-name", "cdn-analytics.pw",           "high",     ["ta-004"], "ShadowGrid",       ["Exaramel"],    ["TA0011"], ["T1071"]),
    ("domain-name", "microsofts-update.com",      "medium",   ["ta-002"], "FancyBear 2024",   ["X-Agent"],     ["TA0001"], ["T1566"]),
    ("domain-name", "secure-login.bank-auth.net", "critical",  ["ta-009"], "Carbanak",         ["CARBANAK"],    ["TA0006"], ["T1056"]),
    ("domain-name", "support.kimsuky-apt.tk",     "high",     ["ta-005"], "Operation Kimchi", ["BabyShark"],   ["TA0043"], ["T1598"]),
    ("domain-name", "lazarusc2.onion.link",       "critical",  ["ta-003"], "BlueNoroff",       ["BLINDINGCAN"], ["TA0011"], ["T1095"]),
    ("domain-name", "lockbit3-data.site",         "high",     ["ta-006"], "LockBit Wave 3",   ["LockBit"],     ["TA0010"], ["T1041"]),
    ("domain-name", "volt-typhoon-proxy.cn",      "critical",  ["ta-008"], "Volt Typhoon",     [],              ["TA0011"], ["T1090"]),
    ("domain-name", "clop-leak.ws",               "high",     ["ta-010"], "MOVEit Blast",     ["Cl0p"],        ["TA0010"], ["T1537"]),
    ("domain-name", "scatter-okta-spoof.com",     "medium",   ["ta-007"], "OktaPhish",        ["SpecterRAT"],  ["TA0001"], ["T1566.002"]),
    ("domain-name", "fin7-payload-cdn.net",       "high",     ["ta-009"], "Carbanak",         ["GRIFFON"],     ["TA0011"], ["T1105"]),
    ("domain-name", "apt28-spear.info",           "medium",   ["ta-002"], "FancyBear 2024",   ["Komplex"],     ["TA0001"], ["T1566.001"]),
    ("domain-name", "sandworm-dropper.cloud",     "critical",  ["ta-004"], "Industroyer2",     ["Exaramel"],    ["TA0040"], ["T1489"]),
    ("domain-name", "kimsuky-chm-host.com",       "high",     ["ta-005"], "Operation Kimchi", ["Gh0st RAT"],   ["TA0001"], ["T1566"]),
    # File Hashes (SHA-256)
    ("file:sha256", "44d88612fea8a8f36de82e1278abb02f5b573b31cb7e3e8c06e1f83f2cc2ee0c", "critical", ["ta-004"], "ShadowGrid",   ["NotPetya"],    ["TA0040"], ["T1486"]),
    ("file:sha256", "a09ac66c82a2de44e8e5edcd14bf680cf18a5e98f47ae1b48b4e2e01a41daf5f", "high",     ["ta-001"], "Operation Ghost", ["WellMess"], ["TA0011"], ["T1071"]),
    ("file:sha256", "f6f8179ac71eaabff12b8c024342109406aac269d6aeabc4bebb6e6abe12f5c0", "critical", ["ta-003"], "BlueNoroff",    ["BLINDINGCAN"], ["TA0011"], ["T1095"]),
    ("file:sha256", "d09d573db8a4714b7df5745e4bdf7ce4e0b8bf96d9e9e0cff5e78a3d14d5cb5b", "high",     ["ta-006"], "LockBit Wave 3",["LockBit"],     ["TA0040"], ["T1486"]),
    ("file:sha256", "5b5de2cca97aae8cfcb0c2de2e9f3ae0bdd9b3b9ca85f45dad93a3ed851f9d13", "medium",   ["ta-002"], "FancyBear 2024",["X-Agent"],     ["TA0011"], ["T1071"]),
    ("file:sha256", "7c4b2a94ac3f89d8a4af1f0dab1e523c462e1ae32eabcbd9a4c8e0b2df78a901", "high",     ["ta-009"], "Carbanak",      ["CARBANAK"],    ["TA0006"], ["T1056"]),
    ("file:sha256", "9b8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c", "critical", ["ta-010"], "MOVEit Blast",  ["Cl0p"],        ["TA0010"], ["T1041"]),
    ("file:sha256", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", "high",     ["ta-005"], "Operation Kimchi",["AppleSeed"],  ["TA0001"], ["T1566"]),
    ("file:sha256", "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",    "medium",   ["ta-007"], "OktaPhish",     [],             ["TA0006"], ["T1557"]),
    ("file:sha256", "cafebabe9876543210fedcba9876543210fedcba9876543210fedcba98765432",    "high",     ["ta-008"], "Volt Typhoon",  [],             ["TA0011"], ["T1090"]),
    # URLs
    ("url", "http://malware-c2.ru/stage2/payload.exe",                      "critical", ["ta-001"], "Operation Ghost",  ["WellMess"],    ["TA0011"], ["T1105"]),
    ("url", "https://update-service.xyz/update?id=lockbit",                  "high",     ["ta-006"], "LockBit Wave 3",   ["LockBit"],     ["TA0011"], ["T1071"]),
    ("url", "http://cdn-analytics.pw/js/analytics.js",                       "high",     ["ta-004"], "ShadowGrid",       ["Exaramel"],    ["TA0011"], ["T1071"]),
    ("url", "http://secure-login.bank-auth.net/oauth/token",                 "critical", ["ta-009"], "Carbanak",         ["CARBANAK"],    ["TA0006"], ["T1539"]),
    ("url", "https://lazarusc2.onion.link/api/check",                        "critical", ["ta-003"], "BlueNoroff",       ["BLINDINGCAN"], ["TA0011"], ["T1071"]),
    ("url", "http://clop-leak.ws/download/moveit-data-nov2024.zip",          "high",     ["ta-010"], "MOVEit Blast",     ["Cl0p"],        ["TA0010"], ["T1537"]),
    ("url", "https://scatter-okta-spoof.com/app/UserHome",                   "medium",   ["ta-007"], "OktaPhish",        ["SpecterRAT"],  ["TA0001"], ["T1566.002"]),
    ("url", "http://volt-typhoon-proxy.cn/tunnel/connect",                   "critical", ["ta-008"], "Volt Typhoon",     [],             ["TA0011"], ["T1090"]),
    ("url", "https://sandworm-dropper.cloud/v2/get?module=industroyer2",     "critical", ["ta-004"], "Industroyer2",     ["Industroyer"], ["TA0040"], ["T1489"]),
    ("url", "http://apt28-spear.info/attachments/invoice_12.doc",            "medium",   ["ta-002"], "FancyBear 2024",   ["Zebrocy"],     ["TA0001"], ["T1566.001"]),
    # Email addresses
    ("email-addr", "noreply@microsofts-update.com",   "medium", ["ta-002"], "FancyBear 2024",  ["X-Agent"],   ["TA0001"], ["T1566"]),
    ("email-addr", "support@bank-auth.net",           "high",   ["ta-009"], "Carbanak",        ["CARBANAK"],  ["TA0006"], ["T1566"]),
    ("email-addr", "helpdesk@scatter-okta-spoof.com", "medium", ["ta-007"], "OktaPhish",       ["SpecterRAT"],["TA0001"], ["T1566.002"]),
    ("email-addr", "cio@kimsuky-apt.tk",              "high",   ["ta-005"], "Operation Kimchi",["BabyShark"], ["TA0001"], ["T1566"]),
    ("email-addr", "bounces@lockbit3-data.site",      "high",   ["ta-006"], "LockBit Wave 3",  ["LockBit"],   ["TA0001"], ["T1566"]),
]

def build_indicator(idx, itype, value, severity, actor_ids, campaign, malware_names, tactics, techniques):
    now = datetime.datetime.utcnow()
    first_seen = rand_dt(2022, 2023)
    last_seen = rand_dt(2023, 2024)
    valid_until = last_seen + datetime.timedelta(days=random.randint(30, 365))
    status = random.choice(STATUSES)
    confidence = random.randint(55, 99)
    threat_types = random.sample(THREAT_TYPES_POOL, random.randint(1, 3))

    return {
        "indicator_id": f"ind-{idx+1:03d}",
        "type": itype,
        "value": value,
        "status": status,
        "confidence": confidence,
        "severity": severity,
        "threat_types": threat_types,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "valid_until": valid_until,
        "created_at": now,
        "updated_at": now,
        # EMBEDDED: sources are always needed alongside the indicator; bounded set (~2-10)
        "sources": make_sources(random.randint(1, 3)),
        # REFERENCED: threat_actors are large shared profiles; actor_id links to threat_actors collection
        "attribution": make_attribution(actor_ids, campaign, malware_names, tactics, techniques),
        "context_data": {
            "description": f"Threat indicator associated with {campaign}. Type: {itype}.",
            "kill_chain_phase": random.choice(["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "c2", "actions-on-objectives"]),
            "country_of_origin": random.choice(["RU", "CN", "KP", "IR", "UNKNOWN"])
        },
        "enrichment": {
            "virustotal": {
                "positives": random.randint(0, 72),
                "total_engines": 72,
                "last_analyzed": rand_dt(2023, 2024)
            }
        },
        "metrics": {
            "sightings_count": random.randint(1, 500),
            "last_sighting": last_seen
        },
        "tags": random.sample(["apt", "ransomware", "c2", "phishing", "malware", "exploit", "ics", "finance", "healthcare", "government"], random.randint(2, 5))
    }

INDICATORS = [
    build_indicator(i, itype, value, sev, actors, camp, mal, tact, tech)
    for i, (itype, value, sev, actors, camp, mal, tact, tech) in enumerate(RAW_INDICATORS)
]

# ---------------------------------------------------------------------------
# 4. Reports (20)
# ---------------------------------------------------------------------------
REPORT_INDICATOR_IDS = [ind["indicator_id"] for ind in INDICATORS]

REPORTS = [
    {
        "report_id": "rpt-001",
        "title": "APT29 WellMess Campaign – Targeting COVID-19 Vaccine Research",
        "published_date": dt(2024, 1, 15),
        "source_url": "https://ctidigest.com/reports/apt29-wellmess-2024",
        "author": "CTI Digest Research Team",
        "summary": "APT29 (Cozy Bear) leveraged WellMess malware to infiltrate pharmaceutical research institutions. Infrastructure includes C2 at malware-c2.ru.",
        "severity": "critical",
        "related_indicators": ["ind-001", "ind-016", "ind-032", "ind-041"],
        "tags": ["APT29", "WellMess", "espionage", "healthcare"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-002",
        "title": "Sandworm Industroyer2 Targeting Ukrainian Power Grid",
        "published_date": dt(2024, 2, 20),
        "source_url": "https://ctidigest.com/reports/sandworm-industroyer2-ukraine",
        "author": "CERT-UA / CTI Digest",
        "summary": "Sandworm APT deployed Industroyer2, an evolution of the original ICS attack framework, against Ukrainian electricity providers.",
        "severity": "critical",
        "related_indicators": ["ind-002", "ind-018", "ind-031", "ind-029"],
        "tags": ["Sandworm", "Industroyer", "ICS", "Ukraine", "critical-infrastructure"],
        "tlp": "red"
    },
    {
        "report_id": "rpt-003",
        "title": "LockBit 3.0 Ransomware-as-a-Service Operations Update",
        "published_date": dt(2024, 3, 5),
        "source_url": "https://ctidigest.com/reports/lockbit3-raas-2024",
        "author": "CTI Digest Ransomware Tracker",
        "summary": "LockBit 3.0 affiliate network continues double-extortion attacks. New infrastructure identified across multiple regions.",
        "severity": "high",
        "related_indicators": ["ind-003", "ind-017", "ind-034", "ind-042", "ind-050"],
        "tags": ["LockBit", "ransomware", "RaaS", "double-extortion"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-004",
        "title": "Lazarus Group BlueNoroff Cryptocurrency Exchange Heists",
        "published_date": dt(2024, 3, 18),
        "source_url": "https://ctidigest.com/reports/lazarus-bluenoroff-crypto",
        "author": "Financial ISAC / CTI Digest",
        "summary": "BlueNoroff sub-cluster of Lazarus Group actively targeting cryptocurrency exchanges with custom backdoors.",
        "severity": "critical",
        "related_indicators": ["ind-004", "ind-022", "ind-033", "ind-044"],
        "tags": ["Lazarus", "BlueNoroff", "cryptocurrency", "financial"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-005",
        "title": "APT28 Spearphishing Campaign Against NATO Members",
        "published_date": dt(2024, 4, 2),
        "source_url": "https://ctidigest.com/reports/apt28-nato-spearphishing",
        "author": "NATO CCDCOE / CTI Digest",
        "summary": "APT28 (Fancy Bear) spearphishing campaign uses document lures mimicking official NATO communications.",
        "severity": "high",
        "related_indicators": ["ind-005", "ind-012", "ind-019", "ind-035", "ind-051"],
        "tags": ["APT28", "spearphishing", "NATO", "espionage"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-006",
        "title": "FIN7 / Carbanak Point-of-Sale Attacks on Retail Chains",
        "published_date": dt(2024, 4, 22),
        "source_url": "https://ctidigest.com/reports/fin7-carbanak-pos-2024",
        "author": "CTI Digest Financial Crime Unit",
        "summary": "FIN7 continues POS intrusion campaigns targeting large retail and restaurant chains. CARBANAK backdoor updated with new C2 protocol.",
        "severity": "high",
        "related_indicators": ["ind-006", "ind-020", "ind-036", "ind-043"],
        "tags": ["FIN7", "Carbanak", "POS", "financial"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-007",
        "title": "Scattered Spider Social Engineering Attacks on Telecoms",
        "published_date": dt(2024, 5, 10),
        "source_url": "https://ctidigest.com/reports/scattered-spider-telecom",
        "author": "CTI Digest",
        "summary": "UNC3944/Scattered Spider conducting aggressive social engineering against telecom help desks to gain initial access.",
        "severity": "high",
        "related_indicators": ["ind-007", "ind-023", "ind-039", "ind-047", "ind-052"],
        "tags": ["Scattered Spider", "social engineering", "telecom", "SIM swapping"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-008",
        "title": "Cl0p MOVEit Zero-Day Mass Exploitation Campaign",
        "published_date": dt(2024, 5, 28),
        "source_url": "https://ctidigest.com/reports/clop-moveit-zerodayl",
        "author": "CISA / CTI Digest",
        "summary": "Cl0p (TA505) exploited CVE-2023-34362 in MOVEit Transfer to steal data from hundreds of organizations globally.",
        "severity": "critical",
        "related_indicators": ["ind-008", "ind-025", "ind-037", "ind-045"],
        "tags": ["Cl0p", "MOVEit", "zero-day", "data-theft"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-009",
        "title": "Volt Typhoon Pre-positioning in US Critical Infrastructure",
        "published_date": dt(2024, 6, 15),
        "source_url": "https://ctidigest.com/reports/volt-typhoon-critical-infra",
        "author": "CISA / NSA / CTI Digest",
        "summary": "Chinese state-sponsored Volt Typhoon identified in US energy, water and communications infrastructure using living-off-the-land techniques.",
        "severity": "critical",
        "related_indicators": ["ind-014", "ind-024", "ind-040", "ind-048"],
        "tags": ["Volt Typhoon", "China", "critical infrastructure", "LOTL"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-010",
        "title": "Kimsuky CHM Lure Campaign Targeting South Korean Think Tanks",
        "published_date": dt(2024, 6, 30),
        "source_url": "https://ctidigest.com/reports/kimsuky-chm-thinktanks",
        "author": "AhnLab / CTI Digest",
        "summary": "Kimsuky distributing malicious CHM help files as lures against South Korean policy research institutes.",
        "severity": "medium",
        "related_indicators": ["ind-010", "ind-021", "ind-038"],
        "tags": ["Kimsuky", "CHM", "North Korea", "espionage"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-011",
        "title": "Q2 2024 Ransomware Landscape Report",
        "published_date": dt(2024, 7, 5),
        "source_url": "https://ctidigest.com/reports/q2-2024-ransomware-landscape",
        "author": "CTI Digest Research",
        "summary": "Comprehensive review of ransomware activity in Q2 2024: LockBit remains top threat, Cl0p surges, new RaaS groups emerge.",
        "severity": "high",
        "related_indicators": ["ind-003", "ind-008", "ind-034", "ind-037"],
        "tags": ["ransomware", "quarterly-report", "LockBit", "Cl0p"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-012",
        "title": "State-Sponsored Threat Actors H1 2024 Summary",
        "published_date": dt(2024, 7, 20),
        "source_url": "https://ctidigest.com/reports/state-sponsored-h1-2024",
        "author": "CTI Digest Intelligence Team",
        "summary": "Analysis of APT activity in H1 2024, focusing on Russian, Chinese and North Korean campaigns.",
        "severity": "high",
        "related_indicators": ["ind-001", "ind-002", "ind-004", "ind-005", "ind-014"],
        "tags": ["state-sponsored", "APT", "semi-annual-report"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-013",
        "title": "New WellMess C2 Infrastructure Cluster Discovered",
        "published_date": dt(2024, 8, 8),
        "source_url": "https://ctidigest.com/reports/wellmess-c2-cluster-aug24",
        "author": "CTI Digest",
        "summary": "Passive DNS analysis reveals a new cluster of C2 domains used by APT29 WellMess implants.",
        "severity": "critical",
        "related_indicators": ["ind-001", "ind-011", "ind-016"],
        "tags": ["APT29", "WellMess", "C2", "infrastructure"],
        "tlp": "amber"
    },
    {
        "report_id": "rpt-014",
        "title": "Financial Sector Threat Brief – August 2024",
        "published_date": dt(2024, 8, 25),
        "source_url": "https://ctidigest.com/reports/financial-threat-brief-aug24",
        "author": "FS-ISAC / CTI Digest",
        "summary": "Threat brief covering FIN7, Lazarus, and Cl0p activity targeting financial institutions.",
        "severity": "high",
        "related_indicators": ["ind-004", "ind-006", "ind-008", "ind-033", "ind-036"],
        "tags": ["financial", "threat-brief", "FIN7", "Lazarus"],
        "tlp": "green"
    },
    {
        "report_id": "rpt-015",
        "title": "Healthcare Sector Under Siege: Ransomware Trends 2024",
        "published_date": dt(2024, 9, 12),
        "source_url": "https://ctidigest.com/reports/healthcare-ransomware-2024",
        "author": "HHS / CTI Digest",
        "summary": "LockBit and Cl0p dominate ransomware attacks on healthcare, with patient data theft driving extortion.",
        "severity": "critical",
        "related_indicators": ["ind-003", "ind-008", "ind-017", "ind-025"],
        "tags": ["healthcare", "ransomware", "LockBit", "Cl0p"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-016",
        "title": "MITRE ATT&CK Coverage Gaps in Enterprise Defenses",
        "published_date": dt(2024, 9, 28),
        "source_url": "https://ctidigest.com/reports/attck-coverage-gaps-2024",
        "author": "CTI Digest Purple Team",
        "summary": "Analysis of common ATT&CK technique blind spots seen across enterprise IR engagements in 2024.",
        "severity": "medium",
        "related_indicators": [],
        "tags": ["MITRE", "ATT&CK", "defense", "purple-team"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-017",
        "title": "Supply Chain Attack Vectors: Lessons from SolarWinds to XZ Utils",
        "published_date": dt(2024, 10, 10),
        "source_url": "https://ctidigest.com/reports/supply-chain-lessons-2024",
        "author": "CTI Digest",
        "summary": "Review of supply-chain intrusion techniques from SUNBURST through the 2024 XZ Utils backdoor, with indicators and mitigations.",
        "severity": "high",
        "related_indicators": ["ind-001", "ind-032"],
        "tags": ["supply-chain", "SUNBURST", "XZ Utils", "defense"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-018",
        "title": "APT Activity Report: October 2024",
        "published_date": dt(2024, 10, 31),
        "source_url": "https://ctidigest.com/reports/apt-oct-2024",
        "author": "CTI Digest Intelligence Team",
        "summary": "Monthly round-up of attributed APT campaigns in October 2024 with IOC lists.",
        "severity": "high",
        "related_indicators": ["ind-001", "ind-002", "ind-005", "ind-010", "ind-014"],
        "tags": ["APT", "monthly-report", "IOC"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-019",
        "title": "Zero-Day Exploitation Trends Q3 2024",
        "published_date": dt(2024, 11, 5),
        "source_url": "https://ctidigest.com/reports/zero-day-trends-q3-2024",
        "author": "CTI Digest Vulnerability Intelligence",
        "summary": "Analysis of zero-day vulnerabilities actively exploited in Q3 2024 across VPN, file-transfer, and email gateway products.",
        "severity": "critical",
        "related_indicators": ["ind-008", "ind-009"],
        "tags": ["zero-day", "vulnerability", "exploitation"],
        "tlp": "white"
    },
    {
        "report_id": "rpt-020",
        "title": "Threat Intelligence Sharing: TLP Framework Update 2024",
        "published_date": dt(2024, 11, 10),
        "source_url": "https://ctidigest.com/reports/tlp-framework-2024",
        "author": "FIRST / CTI Digest",
        "summary": "Overview of the updated Traffic Light Protocol (TLP) framework and best practices for sharing CTI data.",
        "severity": "low",
        "related_indicators": [],
        "tags": ["TLP", "sharing", "framework", "best-practices"],
        "tlp": "white"
    },
]

# ---------------------------------------------------------------------------
# Main seeding function
# ---------------------------------------------------------------------------
def seed():
    print("🌱 Seeding cti_platform database...")

    # Drop existing data
    for col in [indicators_col, threat_actors_col, reports_col, feed_sources_col]:
        col.drop()
    print("  ✓ Cleared existing collections")

    # Feed sources
    feed_sources_col.insert_many(FEED_SOURCES)
    print(f"  ✓ Inserted {len(FEED_SOURCES)} feed sources")

    # Threat actors
    threat_actors_col.insert_many(THREAT_ACTORS)
    threat_actors_col.create_index([("actor_id", ASCENDING)], unique=True)
    print(f"  ✓ Inserted {len(THREAT_ACTORS)} threat actors")

    # Indicators
    indicators_col.insert_many(INDICATORS)
    # Indexes
    indicators_col.create_index([("type", ASCENDING), ("value", ASCENDING)])
    indicators_col.create_index([("status", ASCENDING), ("severity", ASCENDING)])
    indicators_col.create_index(
        [("value", TEXT), ("tags", TEXT), ("threat_types", TEXT)],
        name="indicators_text"
    )
    print(f"  ✓ Inserted {len(INDICATORS)} indicators")

    # Reports
    reports_col.insert_many(REPORTS)
    reports_col.create_index([("report_id", ASCENDING)], unique=True)
    print(f"  ✓ Inserted {len(REPORTS)} threat reports")

    print("\n✅ Seeding complete!")
    print(f"   Database: cti_platform")
    print(f"   Collections: indicators({len(INDICATORS)}), threat_actors({len(THREAT_ACTORS)}), reports({len(REPORTS)}), feed_sources({len(FEED_SOURCES)})")


if __name__ == "__main__":
    seed()
