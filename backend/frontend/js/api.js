/**
 * CTI Platform — API Client
 * All fetch calls to the Flask backend at http://localhost:5000/api
 */

const API_BASE = window.location.protocol.startsWith('http') ? '/api' : 'http://localhost:5000/api';

/** Generic request helper */
async function apiRequest(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const j = await res.json(); msg = j.error || j.message || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

/** Build query string from params object (omit empty values) */
function buildQuery(params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, v);
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

/* ── Indicators ─────────────────────────────────────────────── */

/**
 * @param {{ search?, type?, severity?, status?, page?, limit? }} params
 */
export async function fetchIndicators(params = {}) {
  return apiRequest(`/indicators${buildQuery(params)}`);
}

export async function fetchIndicator(id) {
  return apiRequest(`/indicators/${id}`);
}

export async function createIndicator(data) {
  return apiRequest('/indicators', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateIndicator(id, data) {
  return apiRequest(`/indicators/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteIndicator(id) {
  return apiRequest(`/indicators/${id}`, { method: 'DELETE' });
}

/* ── Dashboard stats ────────────────────────────────────────── */

export async function fetchStats() {
  return apiRequest('/indicators/stats');
}

/* ── Reports ────────────────────────────────────────────────── */

export async function fetchReports(params = {}) {
  return apiRequest(`/reports${buildQuery(params)}`);
}

export async function fetchReport(id) {
  return apiRequest(`/reports/${id}`);
}

export async function createReport(data) {
  return apiRequest('/reports', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

/* ── Threat Actors ──────────────────────────────────────────── */

export async function fetchActors(params = {}) {
  return apiRequest(`/actors${buildQuery(params)}`);
}

export async function fetchActor(id) {
  return apiRequest(`/actors/${id}`);
}

/* ── Analytics ──────────────────────────────────────────────── */

export async function fetchBsonSizes() {
  return apiRequest('/analytics/bson-sizes');
}

export async function fetchCacheStats() {
  return apiRequest('/analytics/cache-stats');
}

export async function fetchWorkingSet() {
  return apiRequest('/analytics/working-set');
}

/* ── Monitor ────────────────────────────────────────────────── */

export async function fetchCacheHitRatio() {
  return apiRequest('/monitor/cache-hit-ratio');
}

export async function checkNewReports() {
  return apiRequest('/monitor/check-new-reports', { method: 'POST' });
}

/* ── Replica Set (Lab 8) ─────────────────────────────────────── */

export async function fetchReplicaSetStatus() {
  return apiRequest('/replicaset/status');
}

export async function triggerStepDown() {
  return apiRequest('/replicaset/stepdown', { method: 'POST' });
}

export async function insertReplicaSetTest() {
  return apiRequest('/replicaset/insert-test');
}

export async function verifyReplication() {
  return apiRequest('/replicaset/verify-replication');
}

export async function fetchFailoverLog() {
  return apiRequest('/replicaset/failover-log');
}
