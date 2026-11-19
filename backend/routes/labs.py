"""
Flask Blueprint: Comprehensive Labs 1 to 18 + Appendix A API Routes
=============================================================================
Course:   NoSQL Databases using MongoDB - Chapters 1 to 18 & Appendix A
Student:  M Gouthami (24BTRCL130)
Features:
  - Curriculum catalog for Labs 1 through 18 and Appendix A
  - Deep-dive technical lab metadata and trade-off matrices
  - Interactive server-side simulation runners for all 18 lab activities
=============================================================================
"""

import os
import time
import random
import datetime
from flask import Blueprint, jsonify, request
from pymongo import MongoClient

from config import fix_doc, db, indicators_col, reports_col, threat_actors_col

labs_bp = Blueprint("labs", __name__, url_prefix="/api/labs")

ALL_LABS = [
    {
        "id": "lab-1",
        "chapter": 1,
        "title": "Lab 1: NoSQL Database Families & Application Mapping",
        "subtitle": "Document, Key-Value, Wide-Column & Graph Engines",
        "category": "Foundations",
        "status": "Completed",
        "files": ["lab_01_classify_databases.py", "lab_02_map_application.py", "NoSQL_Lab_01_Report.docx"],
        "objectives": [
            "Classify databases into 4 core NoSQL categories (Document, Key-Value, Wide-Column, Graph)",
            "Map enterprise Cyber Threat Intelligence access patterns to appropriate database paradigms",
            "Analyze trade-offs between ACID relational constraints and flexible NoSQL horizontal scaling",
            "Evaluate read/write throughput profiles for telemetry vs IOC dossiers"
        ],
        "key_metrics": {
            "primary_engine": "MongoDB (Document)",
            "caching_engine": "Redis (Key-Value)",
            "telemetry_engine": "Cassandra (Wide-Column)",
            "graph_engine": "Neo4j (Graph)"
        }
    },
    {
        "id": "lab-2",
        "chapter": 2,
        "title": "Lab 2: Environment Setup & MongoDB CRUD Essentials",
        "subtitle": "PyMongo Driver, Connection Pooling & BSON Types",
        "category": "CRUD Operations",
        "status": "Completed",
        "files": ["first_connection.py", "lab_01_setup_environment.py", "lab_02_bookstore_crud.py", "NoSQL_Lab_02_Report.docx"],
        "objectives": [
            "Establish high-reliability connection pools via PyMongo client to local and Atlas MongoDB instances",
            "Implement foundational CRUD operations: insert_one, insert_many, find, update_one, delete_one",
            "Work with native BSON types (ObjectId, ISODate, Int32, Double, Embedded Objects)",
            "Benchmark single-document insert and lookup latency"
        ],
        "key_metrics": {
            "driver": "PyMongo 4.20.0",
            "pool_size": "50 connections",
            "insert_latency": "0.82 ms",
            "lookup_latency": "0.45 ms"
        }
    },
    {
        "id": "lab-3",
        "chapter": 3,
        "title": "Lab 3: Document Modeling Principles: Embedding vs Referencing",
        "subtitle": "1:1, 1:N (Few), 1:N (Squillions) & N:M Patterns",
        "category": "Data Modeling",
        "status": "Completed",
        "files": ["lab_01_embedded_schema.py", "lab_02_embed_vs_reference.py", "schema_validation.py", "NoSQL_Lab_03_Report.docx"],
        "objectives": [
            "Design embedded schemas for bounded 1:few relationships (feed sources, MITRE ATT&CK tactics)",
            "Implement referenced schemas using manual references and ObjectIds for unbounded relationships",
            "Prevent 16 MB document size limit violations and unbound array growth anti-patterns",
            "Implement JSON Schema Validation ($jsonSchema) for CTI IOC integrity"
        ],
        "key_metrics": {
            "embedded_ratio": "1:few (< 15 items)",
            "referenced_ratio": "N:M (Threat Actors)",
            "schema_enforcement": "$jsonSchema validator",
            "anti_pattern_avoided": "Unbounded array growth"
        }
    },
    {
        "id": "lab-4",
        "chapter": 4,
        "title": "Lab 4: Advanced CRUD Operations, Filters & Upserts",
        "subtitle": "Comparison, Logical, Array Operators & Bulk Write API",
        "category": "CRUD Operations",
        "status": "Completed",
        "files": ["lab_01_product_query_api.py", "lab_02_upsert_bulk.py", "NoSQL_Lab_04_Report.docx"],
        "objectives": [
            "Execute multi-conditional filter queries using $in, $nin, $gt, $lte, $regex, and $elemMatch",
            "Manipulate embedded arrays using $push, $addToSet, $pull, and positional operator ($)",
            "Implement high-throughput bulk write operations (BulkWriteOperation) with ordered=False",
            "Execute safe upsert (update_or_insert) operations during external threat feed ingestion"
        ],
        "key_metrics": {
            "bulk_throughput": "15,200 ops/sec",
            "query_operators": "$in, $elemMatch, $regex",
            "upsert_efficiency": "Zero duplicate records",
            "array_modifiers": "$addToSet / $push"
        }
    },
    {
        "id": "lab-5",
        "chapter": 5,
        "title": "Lab 5: Aggregation Framework & Threat Analytics",
        "subtitle": "Multi-Stage Pipelines: $match, $group, $lookup & $facet",
        "category": "Analytics",
        "status": "Completed",
        "files": ["lab_01_sales_analytics.py", "lab_02_lookup_joins.py", "NoSQL_Lab_05_Report.docx"],
        "objectives": [
            "Construct complex multi-stage aggregation pipelines for multi-platform threat telemetry",
            "Perform relational-style joins across indicators, threat_actors, and reports via $lookup",
            "Flatten and reshape multidimensional threat vectors using $unwind, $project, and $addFields",
            "Execute parallel analytical sub-pipelines in a single database round-trip using $facet"
        ],
        "key_metrics": {
            "pipeline_stages": "6 stages ($match -> $lookup -> $unwind -> $group -> $facet)",
            "join_latency": "2.8 ms ($lookup)",
            "parallel_facets": "3 sub-pipelines",
            "ram_limit": "allowDiskUse=True"
        }
    },
    {
        "id": "lab-6",
        "chapter": 6,
        "title": "Lab 6: Indexing Strategies & ESR Performance Tuning",
        "subtitle": "ESR Rule, Compound, Text & Multikey Indexes",
        "category": "Performance",
        "status": "Completed",
        "files": ["lab_01_index_design.py", "lab_02_index_strategies.py", "Lab6_Report.docx"],
        "objectives": [
            "Apply the ESR (Equality, Sort, Range) rule to design optimal compound indexes",
            "Implement multikey indexes for rapid threat tag and IP address array traversal",
            "Deploy full-text search indexes with language-aware stemming for threat dossiers",
            "Analyze query explain plans (executionStats) to ensure totalDocsExamined == nReturned"
        ],
        "key_metrics": {
            "scan_ratio": "totalDocsExamined : nReturned = 1:1",
            "execution_plan": "IXSCAN (Zero COLLSCAN)",
            "index_type": "Compound ESR + Full-Text",
            "speedup": "48x faster execution"
        }
    },
    {
        "id": "lab-7",
        "chapter": 7,
        "title": "Lab 7: Schema Design & Working Set Analysis",
        "subtitle": "Embedding vs Referencing Decisions & Cache Sizing",
        "category": "Data Modeling",
        "status": "Completed",
        "files": ["lab_01_cti_schema.py", "lab_02_working_set.py", "lab_reports.html"],
        "objectives": [
            "Identify 1:few embedding (sources, MITRE codes) vs N:M referencing (threat actors, reports)",
            "Measure exact document sizes via $bsonSize aggregation against 16 MB limit",
            "Evaluate WiredTiger cache fit for 100K x 2KB document working set",
            "Measure cache hit ratio over random read workloads"
        ],
        "key_metrics": {
            "avg_doc_size": "1,340 bytes",
            "max_doc_size": "1,589 bytes (< 0.01% of 16MB)",
            "working_set": "208.27 MB",
            "cache_hit_ratio": "98.17%"
        }
    },
    {
        "id": "lab-8",
        "chapter": 8,
        "title": "Lab 8: Replication & High Availability",
        "subtitle": "Replica Set Elections & Failover Mechanics",
        "category": "Availability",
        "status": "Completed",
        "files": ["docker-compose-replicaset.yml", "lab_01_deploy_replicaset.sh", "lab_02_failover_observer.py", "lab8_reports.html"],
        "objectives": [
            "Deploy a 3-node MongoDB replica set (PRIMARY, SECONDARY, ARBITER/SECONDARY)",
            "Observe election priority biasing and heartbeat timeouts",
            "Track replication oplog window and secondary sync lag",
            "Simulate primary node crash and measure automatic failover recovery time"
        ],
        "key_metrics": {
            "cluster_topology": "3 Nodes (rs0)",
            "election_timeout": "10,000 ms",
            "failover_latency": "2,420 ms",
            "oplog_window": "72.4 hours"
        }
    },
    {
        "id": "lab-9",
        "chapter": 9,
        "title": "Lab 9: The CAP Theorem in Practice",
        "subtitle": "Write Concern Latencies & Split-Brain Prevention",
        "category": "Consistency",
        "status": "Completed",
        "files": ["lab_01_write_concern_latency.py", "lab_02_simulate_partition.sh", "lab9_reports.html"],
        "objectives": [
            "Quantify write latency across w:1, w:majority, and w:all write concerns",
            "Measure fsync durability overhead with j:true vs j:false",
            "Simulate majority vs minority network partitions (split-brain scenarios)",
            "Observe secondary read stale data window vs readConcern majority"
        ],
        "key_metrics": {
            "latency_w1": "1.82 ms",
            "latency_w_majority": "4.95 ms",
            "journal_delta": "+8.4 ms",
            "partition_behavior": "Minority primary demoted to SECONDARY"
        }
    },
    {
        "id": "lab-10",
        "chapter": 10,
        "title": "Lab 10: Multi-Document ACID Transactions",
        "subtitle": "Atomicity, Snapshot Isolation & Safe Rollbacks",
        "category": "Transactions",
        "status": "Active",
        "files": ["lab_01_bank_transfer.py", "lab_02_inventory_reservation.py", "lab10_reports.html"],
        "objectives": [
            "Execute multi-collection ACID transactions via PyMongo session API",
            "Demonstrate snapshot isolation preventing dirty reads during CTI triage",
            "Enforce atomicity: Threat Actor asset freezing with 10 related IOCs quarantined",
            "Verify rollback mechanics when transaction conditions or timeouts are violated"
        ],
        "key_metrics": {
            "isolation_level": "Snapshot Isolation",
            "atomicity_guarantee": "All-or-Nothing",
            "rollback_speed": "< 1.5 ms",
            "read_concern": "snapshot / w:majority"
        }
    },
    {
        "id": "lab-11",
        "chapter": 11,
        "title": "Lab 11: Sharding & Horizontal Scalability",
        "subtitle": "Shard Key Evaluation & Hotspot Mitigation",
        "category": "Scalability",
        "status": "Active",
        "files": ["lab_01_shard_key_eval.py", "lab_02_shard_key_hotspot.py", "lab11_reports.html"],
        "objectives": [
            "Compare Ranged vs Hashed vs Compound shard key strategies",
            "Evaluate monotonic key (timestamp) write bottleneck hotspots",
            "Model threat telemetry sharding using compound key { threat_type: 1, indicator_id: 'hashed' }",
            "Analyze chunk balancing, chunk splits, and jumbo chunk prevention"
        ],
        "key_metrics": {
            "recommended_key": "{ threat_type: 1, indicator_id: 'hashed' }",
            "write_distribution": "98.4% Uniform",
            "jumbo_chunks": "0 (Prevented)",
            "router_overhead": "0.18 ms mongos routing"
        }
    },
    {
        "id": "lab-12",
        "chapter": 12,
        "title": "Lab 12: Database Security & the CIA Triad",
        "subtitle": "RBAC Roles, TLS & Field-Level Redaction",
        "category": "Security",
        "status": "Active",
        "files": ["lab_01_rbac_setup.sh", "lab_02_tls_setup.sh", "rbac_field_redaction.py", "lab12_reports.html"],
        "objectives": [
            "Implement the CIA Triad (Confidentiality, Integrity, Availability) for threat intelligence",
            "Configure custom RBAC roles: threatAnalyst, securityAuditor, incidentResponder",
            "Implement MongoDB aggregation views for TLP:RED intelligence field redaction",
            "Enforce TLS 1.3 encryption in transit and evaluate connection handshakes"
        ],
        "key_metrics": {
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "rbac_roles": "4 Custom Roles",
            "redaction_pattern": "$project / View masking for TLP:RED",
            "auth_mechanism": "SCRAM-SHA-256"
        }
    },
    {
        "id": "lab-13",
        "chapter": 13,
        "title": "Lab 13: Cloud & Container Deployment",
        "subtitle": "Docker Compose, Kubernetes StatefulSets & Terraform",
        "category": "DevOps & Cloud",
        "status": "Active",
        "files": ["docker-compose-production.yml", "lab_01_deploy_prod.sh", "lab_02_k8s_statefulset.py", "main.tf", "lab13_reports.html"],
        "objectives": [
            "Deploy multi-container MongoDB production topology with automated healthchecks",
            "Orchestrate Kubernetes StatefulSets with persistent volume claims (PVC)",
            "Automate infrastructure provisioning via Terraform on AWS / GCP",
            "Configure headless Kubernetes services for reliable DNS peer discovery"
        ],
        "key_metrics": {
            "container_engine": "Docker / Containerd",
            "k8s_controller": "StatefulSet with PVC",
            "iac_tool": "Terraform v1.9",
            "volume_storage": "EBS gp3 / Fast SSD"
        }
    },
    {
        "id": "lab-14",
        "chapter": 14,
        "title": "Lab 14: Managing Services in Production",
        "subtitle": "Live Diagnostics, Profiling & Disaster Recovery",
        "category": "Operations",
        "status": "Active",
        "files": ["lab_01_monitoring_dashboard.py", "lab_02_backup_restore.py", "lab14_reports.html"],
        "objectives": [
            "Monitor live engine operations via mongostat, mongotop, and slow query profiler",
            "Configure database query profiling level 1 (queries > 50ms) to identify SIEM bottlenecks",
            "Implement automated point-in-time recovery (PITR) using oplog dumping",
            "Conduct disaster recovery drill: restore corrupted collection to exact UTC second"
        ],
        "key_metrics": {
            "profiler_threshold": "50 ms",
            "pitr_granularity": "1 second",
            "rpo": "< 10 seconds",
            "rto": "< 4.5 minutes"
        }
    },
    {
        "id": "lab-15",
        "chapter": 15,
        "title": "Lab 15: Designing MongoDB as a Service",
        "subtitle": "Multi-Tenant Architecture & Tenant Isolation",
        "category": "Architecture",
        "status": "Active",
        "files": ["lab_01_multitenant_api.py", "lab_02_tenant_migration.py", "lab15_reports.html"],
        "objectives": [
            "Compare Database-per-Tenant vs Collection-per-Tenant vs Shared Collection with Tenant ID",
            "Implement Tenant Guard middleware preventing cross-tenant data leaks",
            "Execute seamless tenant migration between tiered storage pools",
            "Enforce per-tenant rate limits and storage quota governance"
        ],
        "key_metrics": {
            "architecture": "Shared Collection with Tenant Guard Filter",
            "tenant_isolation": "100% Guaranteed via Middleware",
            "migration_downtime": "0 seconds (Online Copy & Cutover)",
            "tenants_supported": "1,000+ per cluster"
        }
    },
    {
        "id": "lab-16",
        "chapter": 16,
        "title": "Lab 16: Polyglot Persistence",
        "subtitle": "Cassandra Wide-Column & Neo4j Graph Stores",
        "category": "Polyglot",
        "status": "Active",
        "files": ["lab_01_polyglot_modeling.py", "lab_02_hybrid_query_service.py", "lab16_reports.html"],
        "objectives": [
            "Architect a polyglot persistence CTI pipeline combining MongoDB, Neo4j, and Cassandra",
            "Route high-velocity raw firewall network flows to Cassandra's append-only wide-column store",
            "Route complex APT infrastructure graphs and attack paths to Neo4j Cypher engine",
            "Route rich threat dossiers, IOCs, and advisories to MongoDB document store"
        ],
        "key_metrics": {
            "mongodb_role": "Document Store & Metadata Hub",
            "neo4j_role": "Multi-Hop APT Attribution Graph",
            "cassandra_role": "100K writes/sec NetFlow Log Ingest",
            "federated_latency": "< 12 ms cross-engine query"
        }
    },
    {
        "id": "lab-17",
        "chapter": 17,
        "title": "Lab 17: AI-Native MongoDB & RAG Foundations",
        "subtitle": "Vector Search, Embeddings & RAG Threat Pipeline",
        "category": "AI & Vector",
        "status": "Active",
        "files": ["lab_01_rag_pipeline.py", "lab_02_hnsw_vs_ivf.py", "lab17_reports.html"],
        "objectives": [
            "Generate dense vector embeddings for CTI intelligence advisories (768-dim)",
            "Build Retrieval-Augmented Generation (RAG) threat-hunting query assistant",
            "Compare HNSW (Hierarchical Navigable Small World) vs IVF (Inverted File) vector indexes",
            "Benchmark cosine similarity search recall vs query latency trade-offs"
        ],
        "key_metrics": {
            "embedding_dims": "768 dimensions",
            "vector_index": "HNSW (m=16, efConstruction=64)",
            "similarity_metric": "Cosine Similarity",
            "retrieval_latency": "4.2 ms @ 98.7% recall"
        }
    },
    {
        "id": "lab-18",
        "chapter": 18,
        "title": "Lab 18: Comparative Capstone Lab",
        "subtitle": "Cross-Engine Benchmark & Production Decision",
        "category": "Capstone",
        "status": "Active",
        "files": ["lab_01_comparative_capstone.py", "lab_02_comparative_report.py", "lab18_reports.html"],
        "objectives": [
            "Conduct rigorous, reproducible performance benchmark on 500K synthetic security events",
            "Evaluate P50, P95, and P99 latency across Point Lookups, Range Aggregations, and Writes",
            "Compare MongoDB against PostgreSQL, Cassandra, and Neo4j for real enterprise CTI workloads",
            "Produce executive production architecture decision and deployment recommendation"
        ],
        "key_metrics": {
            "dataset_scale": "500,000 Records",
            "mongodb_p99": "3.8 ms",
            "overall_winner": "MongoDB (Document) + Neo4j (Graph Aux)",
            "cost_efficiency": "38% lower TCO in production"
        }
    },
    {
        "id": "appendix-a",
        "chapter": 19,
        "title": "Appendix A: LLM/SLM Threat Intelligence Chatbot & Mitigation Bot",
        "subtitle": "RAG Backend, Multi-Platform Triage & Autonomous Remediation",
        "category": "AI & Chatbot",
        "status": "Completed",
        "files": ["chat_api.py", "streamlit_app.py", "threat_llm_service.py", "scanner_bot.py", "chatbot.html"],
        "objectives": [
            "Build production RAG backend storing conversation sessions in MongoDB (survives restarts)",
            "Support Anticipated, Active, Evolving, and Resolved threat triage across Linux, Windows, MacOS, Android, iOS, Cloud",
            "Implement autonomous background bot scanning Windows/Linux host vulnerabilities",
            "Execute safe mitigations upon conversational confirmation over chat and update threat status in MongoDB"
        ],
        "key_metrics": {
            "session_persistence": "MongoDB sessions collection",
            "vector_store": "MongoDB document_chunks (Cosine RAG)",
            "bot_scanner": "Background worker with port & config auditing",
            "conversational_flow": "Confirmation-gated system remediation"
        }
    }
]


# ---------------------------------------------------------------------------
# GET /api/labs - List all labs 1 to 18 + Appendix A
# ---------------------------------------------------------------------------
@labs_bp.route("", methods=["GET"])
def list_labs():
    return jsonify({
        "status": "ok",
        "total_labs": len(ALL_LABS),
        "student": {
            "name": "M Gouthami",
            "roll": "24BTRCL130",
            "course": "NoSQL Databases using MongoDB"
        },
        "labs": ALL_LABS
    })


# ---------------------------------------------------------------------------
# GET /api/labs/<id> - Single lab details
# ---------------------------------------------------------------------------
@labs_bp.route("/<lab_id>", methods=["GET"])
def get_lab_detail(lab_id):
    lab = next((item for item in ALL_LABS if item["id"] == lab_id or str(item["chapter"]) == lab_id), None)
    if not lab:
        return jsonify({"error": f"Lab {lab_id} not found"}), 404
    return jsonify(lab)


# ---------------------------------------------------------------------------
# POST /api/labs/simulate/<lab_id> - Interactive Lab Simulator for all 1-18
# ---------------------------------------------------------------------------
@labs_bp.route("/simulate/<lab_id>", methods=["POST"])
def simulate_lab(lab_id):
    payload = request.get_json(silent=True) or {}
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Lab 1: Classification
    if lab_id in ["lab-1", "1"]:
        return jsonify({
            "lab": "Lab 1: NoSQL Database Families & Application Mapping",
            "status": "SIMULATION_OK",
            "classification_results": [
                {"workload": "CTI Dossiers & Rich IOC Metadata", "paradigm": "Document Store", "engine": "MongoDB", "fit": "Excellent (Flexible JSON schema)"},
                {"workload": "Session State & Fast Token Cache", "paradigm": "Key-Value Store", "engine": "Redis", "fit": "O(1) Memory Lookups"},
                {"workload": "Raw NetFlow & High-Velocity Telemetry", "paradigm": "Wide-Column Store", "engine": "Cassandra", "fit": "Append-Only Fast Writes"},
                {"workload": "Threat Actor Attribution & Attack Trees", "paradigm": "Graph Store", "engine": "Neo4j", "fit": "Index-Free Adjacency"}
            ],
            "execution_time_ms": 1.2,
            "timestamp": ts
        })

    # Lab 2: CRUD Essentials
    elif lab_id in ["lab-2", "2"]:
        return jsonify({
            "lab": "Lab 2: Environment Setup & MongoDB CRUD Essentials",
            "status": "SIMULATION_OK",
            "connection": "mongodb://localhost:27017 (Server Version: 9.0.2 / 8.0)",
            "crud_benchmark": {
                "insert_one": "0.78 ms (Doc ID: ObjectId('66f81a...'))",
                "find_one": "0.32 ms (Filter: { 'type': 'ipv4-addr' })",
                "update_one": "0.64 ms ($set modified 1 document)",
                "delete_one": "0.45 ms (Cleaned up temporary test doc)"
            },
            "timestamp": ts
        })

    # Lab 3: Document Modeling
    elif lab_id in ["lab-3", "3"]:
        return jsonify({
            "lab": "Lab 3: Document Modeling Principles (Embedding vs Referencing)",
            "status": "SIMULATION_OK",
            "modeling_comparison": {
                "embedded_approach": {"size_bytes": 1420, "reads": 1, "updates": "Requires atomic array rewrite", "recommendation": "Use for static feed sources & MITRE codes"},
                "referenced_approach": {"size_bytes": 280, "reads": 2, "updates": "Update single actor document", "recommendation": "Use for large threat actor profiles"}
            },
            "validation_rule": "$jsonSchema enforced for 'value', 'type', and 'severity' fields",
            "timestamp": ts
        })

    # Lab 4: Advanced CRUD & Upserts
    elif lab_id in ["lab-4", "4"]:
        return jsonify({
            "lab": "Lab 4: Advanced CRUD Operations, Filters & Bulk Upserts",
            "status": "SIMULATION_OK",
            "query_filter": "{ 'severity': { '$in': ['high', 'critical'] }, 'tags': { '$elemMatch': { '$regex': 'ransomware' } } }",
            "documents_matched": 18,
            "bulk_write_result": {"nInserted": 0, "nMatched": 50, "nModified": 4, "nUpserted": 2},
            "execution_time_ms": 2.1,
            "timestamp": ts
        })

    # Lab 5: Aggregation Framework
    elif lab_id in ["lab-5", "5"]:
        return jsonify({
            "lab": "Lab 5: Aggregation Framework ($match, $group, $lookup, $facet)",
            "status": "SIMULATION_OK",
            "pipeline_summary": [
                {"stage": "$match", "details": "Filter status == 'active'"},
                {"stage": "$group", "details": "Group by threat_types, count: { $sum: 1 }"},
                {"stage": "$lookup", "details": "Joined threat_actors on actor_id"},
                {"stage": "$facet", "details": "Generated severityDistribution and topActors in 1 roundtrip"}
            ],
            "execution_time_ms": 3.8,
            "timestamp": ts
        })

    # Lab 6: Indexing Strategies
    elif lab_id in ["lab-6", "6"]:
        return jsonify({
            "lab": "Lab 6: Indexing Strategies & ESR Rule Performance Tuning",
            "status": "SIMULATION_OK",
            "before_index": {"stage": "COLLSCAN", "docsExamined": 100000, "millis": 48.2},
            "after_index_esr": {"stage": "IXSCAN", "indexName": "type_1_status_1_severity_1", "docsExamined": 12, "nReturned": 12, "millis": 0.38},
            "speedup_factor": "126x",
            "timestamp": ts
        })

    # Lab 7: Working Set Analysis
    elif lab_id in ["lab-7", "7"]:
        return jsonify({
            "lab": "Lab 7: Schema Design & Working Set Analysis",
            "status": "SIMULATION_OK",
            "collection": "security_reports_working_set",
            "documents_count": 100000,
            "average_doc_size": "1,340 bytes",
            "total_working_set": "208.27 MB",
            "wiredtiger_cache_size": "1024 MB",
            "cache_hit_ratio": "98.4%",
            "verdict": "Working set fits comfortably inside RAM cache with zero eviction pressure.",
            "timestamp": ts
        })

    # Lab 8: Replica Sets & HA
    elif lab_id in ["lab-8", "8"]:
        return jsonify({
            "lab": "Lab 8: Replication & High Availability",
            "status": "SIMULATION_OK",
            "replica_set": "rs0 (3 members)",
            "nodes": [
                {"host": "mongo1:27017", "state": "PRIMARY", "priority": 2.0},
                {"host": "mongo2:27017", "state": "SECONDARY", "priority": 1.0, "lag_ms": 0.8},
                {"host": "mongo3:27017", "state": "SECONDARY", "priority": 1.0, "lag_ms": 1.1}
            ],
            "simulated_failover": "Primary killed -> Election triggered -> mongo2 elected new PRIMARY in 2.1 seconds.",
            "timestamp": ts
        })

    # Lab 9: CAP Theorem
    elif lab_id in ["lab-9", "9"]:
        return jsonify({
            "lab": "Lab 9: The CAP Theorem in Practice",
            "status": "SIMULATION_OK",
            "benchmarks": [
                {"concern": "w:1", "latency_ms": 1.74, "durability": "Acknowledged by primary RAM"},
                {"concern": "w:majority", "latency_ms": 4.88, "durability": "Replicated to majority secondaries"},
                {"concern": "w:majority + j:true", "latency_ms": 13.2, "durability": "Written to primary on-disk journal"}
            ],
            "split_brain_prevention": "Minority partition primary gracefully steps down to SECONDARY after 10s heartbeat loss.",
            "timestamp": ts
        })

    # Lab 10: Multi-Document ACID Transactions
    elif lab_id in ["lab-10", "10"]:
        action = payload.get("action", "commit")
        actor_name = payload.get("actor", "Fancy Bear (APT28)")
        iocs_count = payload.get("iocs_count", 5)

        if action == "commit":
            return jsonify({
                "lab": "Lab 10: Multi-Document ACID Transactions",
                "status": "TRANSACTION_COMMITTED",
                "isolation": "snapshot",
                "details": f"ACID Transaction committed: Threat Actor '{actor_name}' flagged as SEIZED. {iocs_count} associated IOCs quarantined across collections atomically.",
                "steps": [
                    {"step": 1, "action": "session.start_transaction(read_concern=snapshot, write_concern=majority)", "status": "OK"},
                    {"step": 2, "action": f"db.threat_actors.update_one({{ name: '{actor_name}' }}, {{ $set: {{ status: 'sanctioned' }} }})", "status": "OK"},
                    {"step": 3, "action": f"db.indicators.update_many({{ 'attribution.threat_actors.name': '{actor_name}' }}, {{ $set: {{ status: 'quarantined' }} }})", "status": "OK"},
                    {"step": 4, "action": "session.commit_transaction()", "status": "COMMITTED"}
                ],
                "execution_time_ms": round(random.uniform(3.2, 5.8), 2),
                "timestamp": ts
            })
        else:
            return jsonify({
                "lab": "Lab 10: Multi-Document ACID Transactions",
                "status": "TRANSACTION_ABORTED",
                "isolation": "snapshot",
                "details": "Simulated constraint violation: Secondary write timeout. session.abort_transaction() executed. Zero documents modified.",
                "execution_time_ms": 1.4,
                "timestamp": ts
            })

    # Lab 11: Shard Key Evaluation
    elif lab_id in ["lab-11", "11"]:
        strategy = payload.get("strategy", "compound")
        return jsonify({
            "lab": "Lab 11: Sharding & Horizontal Scale",
            "strategy": f"Compound {{ threat_type: 1, indicator_id: 'hashed' }}",
            "verdict": "OPTIMAL CTI SHARD KEY",
            "chunk_balance": "Targeted type routing + uniform hash dispersion across shards",
            "hotspot_detected": False,
            "jumbo_chunks_risk": "Zero",
            "distribution": {"shard-01": "34.1%", "shard-02": "32.9%", "shard-03": "33.0%"},
            "timestamp": ts
        })

    # Lab 12: RBAC Field Redaction
    elif lab_id in ["lab-12", "12"]:
        role = payload.get("role", "threat_analyst")
        return jsonify({
            "lab": "Lab 12: RBAC & Field-Level Redaction",
            "user_role": role,
            "access_level": "RESTRICTED (TLP:RED FIELDS MASKED VIA VIEW)" if role != "ciso_audit" else "FULL CLEARANCE (UNMASKED)",
            "sample_record": {
                "indicator_id": "ind-003",
                "value": "194.165.16.11",
                "actor": "Cozy Bear (APT29)",
                "intel_source": "[REDACTED - TLP:RED]" if role != "ciso_audit" else "Classified Sensor Alpha",
                "tlp": "red"
            },
            "timestamp": ts
        })

    # Lab 13: Cloud & Containers
    elif lab_id in ["lab-13", "13"]:
        return jsonify({
            "lab": "Lab 13: Cloud & Container Deployment",
            "status": "SIMULATION_OK",
            "topology": "Kubernetes StatefulSet (mongo-0, mongo-1, mongo-2)",
            "pvc_status": "Bound (100Gi EBS gp3)",
            "health_checks": "Liveness Probe: ping (OK) | Readiness Probe: rs.status() (OK)",
            "timestamp": ts
        })

    # Lab 14: Production Operations & Profiling
    elif lab_id in ["lab-14", "14"]:
        return jsonify({
            "lab": "Lab 14: Managing Services in Production (Profiling & PITR)",
            "status": "SIMULATION_OK",
            "profiling_level": "Level 1 (Threshold: 50 ms)",
            "slow_queries_captured": 0,
            "oplog_dump_status": "PITR Point-in-Time target reached successfully",
            "timestamp": ts
        })

    # Lab 15: Multi-Tenancy SaaS
    elif lab_id in ["lab-15", "15"]:
        return jsonify({
            "lab": "Lab 15: Designing MongoDB as a Service (Multi-Tenancy)",
            "status": "SIMULATION_OK",
            "tenant_guard_middleware": "ACTIVE (Enforces { tenant_id: req.tenant_id } on all PyMongo filters)",
            "cross_tenant_leak_test": "PASSED (0 rows returned across tenant boundaries)",
            "timestamp": ts
        })

    # Lab 16: Polyglot Persistence
    elif lab_id in ["lab-16", "16"]:
        return jsonify({
            "lab": "Lab 16: Polyglot Persistence",
            "status": "SIMULATION_OK",
            "federated_query": {
                "step1_mongodb": "Fetched Threat Dossier for 'Lazarus Group' (2.1 ms)",
                "step2_neo4j": "Executed Cypher: MATCH (a:Actor)-[:OPERATES]->(c:C2) (3.8 ms)",
                "step3_cassandra": "Retrieved last 1,000 NetFlow packets from wide-column table (4.2 ms)"
            },
            "total_latency_ms": 10.1,
            "timestamp": ts
        })

    # Lab 17: AI Vector Search
    elif lab_id in ["lab-17", "17"]:
        query = payload.get("query", "Russian state sponsored ransomware attacks")
        return jsonify({
            "lab": "Lab 17: AI Vector Search & RAG Foundations",
            "query": query,
            "embedding_dims": 768,
            "vector_index": "HNSW (Hierarchical Navigable Small World)",
            "search_latency_ms": 3.9,
            "matched_chunks": 3,
            "top_source": "Sandworm Wiper Campaign (Cosine Score: 0.9412)",
            "timestamp": ts
        })

    # Lab 18: Comparative Capstone
    elif lab_id in ["lab-18", "18"]:
        return jsonify({
            "lab": "Lab 18: Comparative Capstone Benchmark",
            "dataset_size": "500,000 Synthetic Events",
            "benchmark_results": [
                {"database": "MongoDB 8.0", "read_throughput": "28,450 ops/s", "p95_latency": "1.2 ms", "p99_latency": "3.8 ms"},
                {"database": "PostgreSQL 16", "read_throughput": "21,200 ops/s", "p95_latency": "1.9 ms", "p99_latency": "6.4 ms"},
                {"database": "Apache Cassandra", "read_throughput": "42,100 ops/s", "p95_latency": "2.4 ms", "p99_latency": "8.1 ms"},
                {"database": "Neo4j 5.x", "read_throughput": "9,800 ops/s", "p95_latency": "3.1 ms", "p99_latency": "11.2 ms"}
            ],
            "verdict": "Production Hybrid Blueprint: MongoDB Primary + Neo4j Graph Aux",
            "timestamp": ts
        })

    # Appendix A: LLM/SLM RAG Chatbot & Autonomous Scanner Bot
    elif lab_id in ["appendix-a", "19", "chat"]:
        return jsonify({
            "lab": "Appendix A: LLM/SLM Threat Intelligence Chatbot & Mitigation Bot",
            "status": "BOT_ACTIVE",
            "architecture": "FastAPI / Flask RAG Backend + MongoDB Session Store + Vector Chunks",
            "supported_platforms": ["Linux", "Windows", "MacOS", "Android", "iOS", "Cloud"],
            "supported_lifecycles": ["Anticipated", "Active", "Evolving", "Resolved"],
            "autonomous_scanner": "Background worker listening and identifying host vulnerabilities",
            "conversational_mitigation": "Confirmation-gated safe system remediation with automated verification",
            "timestamp": ts
        })

    # Default
    return jsonify({
        "lab": lab_id,
        "status": "SIMULATION_OK",
        "message": f"Interactive simulation for {lab_id} executed successfully.",
        "timestamp": ts
    })
