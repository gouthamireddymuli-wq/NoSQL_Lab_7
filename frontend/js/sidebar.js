/**
 * CTI Platform — Shared Sidebar Component (Labs 1 to 18 + Appendix A)
 * Dynamically injects and manages the interactive sidebar across all platform pages.
 */

export const LAB_CURRICULUM = [
  {
    id: "lab-1",
    chapter: 1,
    title: "Lab 1: NoSQL Families & CTI",
    subtitle: "Document, Key-Value, Column & Graph",
    href: "labs.html?filter=Foundations",
    icon: "fa-project-diagram",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Classify databases and map Cyber Threat Intelligence workloads to NoSQL paradigms."
  },
  {
    id: "lab-2",
    chapter: 2,
    title: "Lab 2: PyMongo CRUD Essentials",
    subtitle: "Connection Pools & BSON Types",
    href: "labs.html?filter=CRUD",
    icon: "fa-plug",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "PyMongo client pooling, BSON serialization, and atomic single-document operations."
  },
  {
    id: "lab-3",
    chapter: 3,
    title: "Lab 3: Document Modeling",
    subtitle: "Embedding vs Referencing",
    href: "labs.html?filter=Modeling",
    icon: "fa-sitemap",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "1:few embedding for feed sources vs N:M referencing for threat actors."
  },
  {
    id: "lab-4",
    chapter: 4,
    title: "Lab 4: Advanced CRUD & Upserts",
    subtitle: "Filters, Array Ops & Bulk Writes",
    href: "labs.html?filter=CRUD",
    icon: "fa-filter",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Complex $in / $regex queries, $push array modifiers, and bulk threat upserts."
  },
  {
    id: "lab-5",
    chapter: 5,
    title: "Lab 5: Aggregation Analytics",
    subtitle: "Pipelines, $lookup & $facet",
    href: "labs.html?filter=Analytics",
    icon: "fa-chart-pie",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Multi-stage aggregations joining actors and indicators with parallel facets."
  },
  {
    id: "lab-6",
    chapter: 6,
    title: "Lab 6: Indexing & ESR Rule",
    subtitle: "Performance & Explain Plans",
    href: "labs.html?filter=Performance",
    icon: "fa-bolt",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "ESR compound indexes and text indexes eliminating full collection scans."
  },
  {
    id: "lab-7",
    chapter: 7,
    title: "Lab 7: Schema & Working Set",
    subtitle: "Schema Design & WiredTiger Cache",
    href: "lab_reports.html",
    icon: "fa-flask",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Production schema embedding vs referencing decisions & $bsonSize working set estimation."
  },
  {
    id: "lab-8",
    chapter: 8,
    title: "Lab 8: Replica Sets & HA",
    subtitle: "High Availability & Failovers",
    href: "lab8_reports.html",
    icon: "fa-server",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Replica set election mechanisms, primary failover observer, and secondary replication lag."
  },
  {
    id: "lab-9",
    chapter: 9,
    title: "Lab 9: CAP & Write Concerns",
    subtitle: "Consistency & Durability",
    href: "lab9_reports.html",
    icon: "fa-network-wired",
    badge: "Done",
    badgeClass: "sidebar-badge-done",
    desc: "Write concern benchmarking (w:1, w:majority, j:true) & network partition split-brain simulation."
  },
  {
    id: "lab-10",
    chapter: 10,
    title: "Lab 10: ACID Transactions",
    subtitle: "Multi-Doc Transactions",
    href: "lab10_reports.html",
    icon: "fa-exchange-alt",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "ACID sessions, snapshot isolation, bank transfers & multi-collection threat quarantines."
  },
  {
    id: "lab-11",
    chapter: 11,
    title: "Lab 11: Sharding & Scale",
    subtitle: "Horizontal Scalability",
    href: "lab11_reports.html",
    icon: "fa-layer-group",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "Shard key evaluation, ranged vs hashed distribution, and monotonic key hotspot avoidance."
  },
  {
    id: "lab-12",
    chapter: 12,
    title: "Lab 12: Security & CIA Triad",
    subtitle: "RBAC, TLS & Encryption",
    href: "lab12_reports.html",
    icon: "fa-shield-alt",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "Role-Based Access Control, field-level redaction views for TLP:RED intelligence, and TLS."
  },
  {
    id: "lab-13",
    chapter: 13,
    title: "Lab 13: Cloud & Containers",
    subtitle: "Docker, K8s & Terraform",
    href: "lab13_reports.html",
    icon: "fa-cubes",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "Production Docker deployment, Kubernetes StatefulSet topologies, and automated cloud orchestration."
  },
  {
    id: "lab-14",
    chapter: 14,
    title: "Lab 14: Production Operations",
    subtitle: "Diagnostics & Backups",
    href: "lab14_reports.html",
    icon: "fa-tachometer-alt",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "Diagnostic metrics (mongostat/mongotop), oplog window monitoring, and point-in-time recovery."
  },
  {
    id: "lab-15",
    chapter: 15,
    title: "Lab 15: Multi-Tenancy SaaS",
    subtitle: "Product as a Service",
    href: "lab15_reports.html",
    icon: "fa-building",
    badge: "Active",
    badgeClass: "sidebar-badge-new",
    desc: "Multi-tenant CTI isolation patterns, tenant boundary guards, and cross-tenant data migration."
  },
  {
    id: "lab-16",
    chapter: 16,
    title: "Lab 16: Polyglot Persistence",
    subtitle: "Cassandra & Neo4j",
    href: "lab16_reports.html",
    icon: "fa-project-diagram",
    badge: "Adv",
    badgeClass: "sidebar-badge-adv",
    desc: "Hybrid data architecture: MongoDB document store + Neo4j graph traversal + Cassandra time-series."
  },
  {
    id: "lab-17",
    chapter: 17,
    title: "Lab 17: AI Vector Search & RAG",
    subtitle: "AI-Native MongoDB",
    href: "lab17_reports.html",
    icon: "fa-brain",
    badge: "Adv",
    badgeClass: "sidebar-badge-adv",
    desc: "Vector embeddings, semantic threat hunting RAG pipeline, and HNSW vs IVF indexing trade-offs."
  },
  {
    id: "lab-18",
    chapter: 18,
    title: "Lab 18: Comparative Capstone",
    subtitle: "Capstone Production Benchmark",
    href: "lab18_reports.html",
    icon: "fa-trophy",
    badge: "Final",
    badgeClass: "sidebar-badge-done",
    desc: "End-to-end benchmark across MongoDB, Relational & Graph engines; comprehensive capstone review."
  },
  {
    id: "appendix-a",
    chapter: 19,
    title: "Appendix A: AI Threat Bot",
    subtitle: "RAG & Autonomous Mitigation",
    href: "chatbot.html",
    icon: "fa-robot",
    badge: "New",
    badgeClass: "sidebar-badge-new",
    desc: "Multi-platform threat triage, MongoDB vector RAG, and autonomous vulnerability scanner bot."
  }
];

export function initSidebar(activePage = "") {
  const sidebarEl = document.getElementById("app-sidebar");
  if (!sidebarEl) return;

  const currentPath = window.location.pathname.split("/").pop() || "index.html";

  sidebarEl.innerHTML = `
    <!-- Top Operations -->
    <div class="sidebar-section">
      <div class="sidebar-title">
        <span>Operations</span>
        <i class="fas fa-satellite-dish" style="color:var(--accent-cyan);font-size:0.75rem;"></i>
      </div>
      <ul class="sidebar-nav">
        <li>
          <a href="index.html" class="sidebar-link ${currentPath === 'index.html' || activePage === 'dashboard' ? 'active' : ''}">
            <i class="fas fa-th-large"></i> Dashboard
          </a>
        </li>
        <li>
          <a href="indicators.html" class="sidebar-link ${currentPath === 'indicators.html' || activePage === 'indicators' ? 'active' : ''}">
            <i class="fas fa-crosshairs"></i> Threat Indicators
            <span class="sidebar-badge badge-active">Live</span>
          </a>
        </li>
        <li>
          <a href="reports.html" class="sidebar-link ${currentPath === 'reports.html' || activePage === 'reports' ? 'active' : ''}">
            <i class="fas fa-file-alt"></i> Threat Reports
          </a>
        </li>
        <li>
          <a href="actors.html" class="sidebar-link ${currentPath === 'actors.html' || activePage === 'actors' ? 'active' : ''}">
            <i class="fas fa-user-secret"></i> Threat Actors
          </a>
        </li>
        <li>
          <a href="analytics.html" class="sidebar-link ${currentPath === 'analytics.html' || activePage === 'analytics' ? 'active' : ''}">
            <i class="fas fa-chart-bar"></i> Performance Analytics
          </a>
        </li>
        <li>
          <a href="chatbot.html" class="sidebar-link ${currentPath === 'chatbot.html' || activePage === 'chatbot' ? 'active' : ''}" style="color:var(--accent-cyan);">
            <i class="fas fa-robot" style="color:var(--accent-cyan);"></i> AI Threat Analyst &amp; Bot
            <span class="sidebar-badge" style="background:#8b5cf6;color:#fff;">AI RAG</span>
          </a>
        </li>
      </ul>
    </div>

    <!-- Curriculum Explorer -->
    <div class="sidebar-section" style="flex:1;">
      <div class="sidebar-title">
        <span>Curriculum (Labs 1 - 18)</span>
        <a href="labs.html" style="font-size:0.65rem;color:var(--accent-cyan);text-transform:none;">View All &rarr;</a>
      </div>
      <ul class="sidebar-nav">
        <li>
          <a href="labs.html" class="sidebar-link ${currentPath === 'labs.html' || activePage === 'labs-hub' ? 'active' : ''}" style="color:var(--accent-cyan);font-weight:600;">
            <i class="fas fa-book-open" style="color:var(--accent-cyan);"></i> All Labs Portal Hub
            <span class="sidebar-badge sidebar-badge-new">19 Modules</span>
          </a>
        </li>
        ${LAB_CURRICULUM.map(lab => `
          <li>
            <a href="${lab.href}" class="sidebar-link ${currentPath === lab.href || activePage === lab.id ? 'active' : ''}" title="${lab.subtitle}">
              <i class="fas ${lab.icon}"></i> ${lab.title}
              <span class="sidebar-badge ${lab.badgeClass}">${lab.badge}</span>
            </a>
          </li>
        `).join('')}
      </ul>
    </div>

    <!-- Student Metadata Footer -->
    <div class="sidebar-section" style="background:rgba(0,0,0,0.3);border-top:1px solid var(--card-border);padding:0.75rem;">
      <div style="font-size:0.72rem;color:var(--text-muted);display:flex;align-items:center;gap:0.4rem;margin-bottom:0.25rem;">
        <i class="fas fa-graduation-cap" style="color:var(--accent-cyan);"></i>
        <span>Student: <strong>M Gouthami</strong></span>
      </div>
      <div style="font-size:0.68rem;color:var(--text-muted);">
        Roll: <span style="font-family:var(--font-mono);color:var(--accent-green);">24BTRCL130</span>
      </div>
    </div>
  `;

  // Attach mobile toggle button handler if button exists
  const toggleBtn = document.getElementById("sidebar-toggle");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      sidebarEl.classList.toggle("open");
    });
  }
}

// Auto-run if DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => initSidebar());
} else {
  initSidebar();
}
