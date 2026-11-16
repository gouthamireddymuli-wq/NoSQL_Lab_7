/**
 * CTI Platform — Dashboard JS
 * Fetches stats + recent data, renders Chart.js charts and tables.
 */

import { fetchStats, fetchReports, fetchIndicators } from './api.js';
import {
  severityBadge, typeBadge, statusBadge,
  formatDate, showToast, loadingHTML, errorHTML, truncate
} from './utils.js';

/* ── Shared Chart.js config ─────────────────────────────────── */
const CHART_COLORS = {
  'ipv4-addr':   '#00d4ff',
  'domain-name': '#00ff88',
  'file:sha256': '#ffaa00',
  'url':         '#9b59b6',
  'email-addr':  '#ff4444',
};

const SEV_COLORS = {
  critical: '#ff4444',
  high:     '#ff7700',
  medium:   '#ffaa00',
  low:      '#00ff88',
};

/* ── Init ───────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
});

async function initDashboard() {
  setLoadingCards();
  try {
    const [stats, reportsData, recentIndicators] = await Promise.all([
      fetchStats(),
      fetchReports({ limit: 5 }),
      fetchIndicators({ limit: 10 }),
    ]);

    renderStatCards(stats);
    renderTypeDoughnut(stats.by_type || {});
    renderSeverityBar(stats.by_severity || {});
    const indList = Array.isArray(recentIndicators) ? recentIndicators : (recentIndicators.indicators || recentIndicators.data || []);
    const repList = Array.isArray(reportsData) ? reportsData : (reportsData.reports || reportsData.data || []);
    renderRecentIndicators(indList);
    renderRecentReports(repList);
  } catch (err) {
    console.error('Dashboard load error:', err);
    showToast(`Failed to load dashboard: ${err.message}`, 'error');
    document.querySelectorAll('.stat-value').forEach(el => el.textContent = '—');
    document.getElementById('recent-indicators').innerHTML = errorHTML(err.message);
    document.getElementById('recent-reports').innerHTML = errorHTML(err.message);
  }
}

/* ── Loading placeholders ───────────────────────────────────── */
function setLoadingCards() {
  document.querySelectorAll('.stat-value').forEach(el => {
    el.innerHTML = '<div class="spinner" style="width:24px;height:24px;border-width:2px;margin:0;"></div>';
  });
  document.getElementById('recent-indicators').innerHTML = loadingHTML();
  document.getElementById('recent-reports').innerHTML = loadingHTML();
}

/* ── Stat Cards ─────────────────────────────────────────────── */
function renderStatCards(stats) {
  const total    = stats.total_indicators ?? 0;
  const active   = (stats.by_status || {}).active ?? 0;
  const critical = (stats.by_severity || {}).critical ?? 0;
  const reports  = stats.total_reports ?? 0;

  setText('stat-total',    total);
  setText('stat-active',   active);
  setText('stat-critical', critical);
  setText('stat-reports',  reports);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* ── Doughnut: Indicators by Type ───────────────────────────── */
let doughnutChart = null;

function renderTypeDoughnut(byType) {
  const ctx = document.getElementById('chart-type')?.getContext('2d');
  if (!ctx) return;

  const labels = Object.keys(byType);
  const data   = Object.values(byType);
  const colors = labels.map(l => CHART_COLORS[l] || '#6b7280');

  if (doughnutChart) doughnutChart.destroy();

  doughnutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + '99'),
        borderColor:     colors,
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#e2e8f0',
            padding: 12,
            font: { size: 11 },
            boxWidth: 12,
          },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed}`,
          },
        },
      },
    },
  });
}

/* ── Bar: Indicators by Severity ────────────────────────────── */
let barChart = null;

function renderSeverityBar(bySeverity) {
  const ctx = document.getElementById('chart-severity')?.getContext('2d');
  if (!ctx) return;

  const order  = ['critical', 'high', 'medium', 'low'];
  const labels = order.filter(k => bySeverity[k] !== undefined);
  const data   = labels.map(k => bySeverity[k] || 0);
  const colors = labels.map(k => SEV_COLORS[k] || '#6b7280');

  if (barChart) barChart.destroy();

  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
      datasets: [{
        label: 'Indicators',
        data,
        backgroundColor: colors.map(c => c + '88'),
        borderColor:     colors,
        borderWidth: 2,
        borderRadius: 4,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.parsed.y} indicators`,
          },
        },
      },
      scales: {
        x: {
          ticks: { color: '#6b7280' },
          grid:  { color: 'rgba(255,255,255,0.05)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#6b7280', precision: 0 },
          grid:  { color: 'rgba(255,255,255,0.05)' },
        },
      },
    },
  });
}

/* ── Recent Indicators Table ────────────────────────────────── */
function renderRecentIndicators(indicators) {
  const el = document.getElementById('recent-indicators');
  if (!el) return;

  if (!indicators.length) {
    el.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i><p>No indicators found</p></div>';
    return;
  }

  el.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Confidence</th>
            <th>First Seen</th>
          </tr>
        </thead>
        <tbody>
          ${indicators.map(ind => `
            <tr onclick="window.location='indicators.html'">
              <td>${typeBadge(ind.type)}</td>
              <td class="td-mono">${truncate(ind.value, 36)}</td>
              <td>${severityBadge(ind.severity)}</td>
              <td>${statusBadge(ind.status)}</td>
              <td>${ind.confidence ?? '—'}%</td>
              <td>${formatDate(ind.first_seen)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`;
}

/* ── Recent Reports List ────────────────────────────────────── */
function renderRecentReports(reports) {
  const el = document.getElementById('recent-reports');
  if (!el) return;

  if (!reports.length) {
    el.innerHTML = '<div class="empty-state"><i class="fas fa-file-alt"></i><p>No reports found</p></div>';
    return;
  }

  el.innerHTML = reports.map(r => `
    <div class="report-mini" onclick="window.location='reports.html'" style="
      padding: 0.75rem;
      border-bottom: 1px solid var(--card-border);
      cursor: pointer;
      transition: background 0.2s;
    " onmouseover="this.style.background='rgba(0,212,255,0.04)'" onmouseout="this.style.background=''">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem;margin-bottom:0.3rem;">
        <span style="font-weight:600;font-size:0.85rem;">${truncate(r.title, 55)}</span>
        <span class="badge badge-${(r.severity||'low').toLowerCase()}" style="flex-shrink:0;">${r.severity||'—'}</span>
      </div>
      <div style="font-size:0.75rem;color:var(--text-muted);">
        ${formatDate(r.published_date)} · ${r.source_url ? new URL(r.source_url).hostname : '—'}
      </div>
    </div>
  `).join('');
}
