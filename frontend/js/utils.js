/**
 * CTI Platform — Utility Functions
 */

/* ── Severity Badge ─────────────────────────────────────────── */
export function severityBadge(severity) {
  const s = (severity || 'unknown').toLowerCase();
  const icons = {
    critical: 'fa-skull-crossbones',
    high:     'fa-exclamation-triangle',
    medium:   'fa-exclamation-circle',
    low:      'fa-info-circle',
  };
  const icon = icons[s] || 'fa-question-circle';
  return `<span class="badge badge-${s}"><i class="fas ${icon}"></i> ${s}</span>`;
}

/* ── Type Badge ─────────────────────────────────────────────── */
export function typeBadge(type) {
  const t = (type || '').toLowerCase();
  const map = {
    'ipv4-addr':     { icon: 'fa-network-wired', label: 'IPv4' },
    'ipv6-addr':     { icon: 'fa-network-wired', label: 'IPv6' },
    'domain-name':   { icon: 'fa-globe',         label: 'Domain' },
    'file:sha256':   { icon: 'fa-file-alt',      label: 'SHA256' },
    'file:md5':      { icon: 'fa-file-alt',      label: 'MD5' },
    'url':           { icon: 'fa-link',           label: 'URL' },
    'email-addr':    { icon: 'fa-envelope',       label: 'Email' },
  };
  const info = map[t] || { icon: 'fa-tag', label: type };
  return `<span class="badge badge-type"><i class="fas ${info.icon}"></i> ${info.label}</span>`;
}

/* ── TLP Badge ──────────────────────────────────────────────── */
export function tlpBadge(tlp) {
  const t = (tlp || 'white').toUpperCase();
  return `<span class="badge badge-tlp-${t.toLowerCase()}">TLP:${t}</span>`;
}

/* ── Status Badge ───────────────────────────────────────────── */
export function statusBadge(status) {
  const s = (status || '').toLowerCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

/* ── Format Date ────────────────────────────────────────────── */
export function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d)) return isoString;
    return d.toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return isoString;
  }
}

export function formatDateTime(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d)) return isoString;
    return d.toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}

/* ── Modal ──────────────────────────────────────────────────── */
let _modalOverlay = null;

function getOverlay() {
  if (!_modalOverlay) {
    _modalOverlay = document.getElementById('modal-overlay');
  }
  return _modalOverlay;
}

export function showModal(title, bodyHTML, footerHTML = '') {
  const overlay = getOverlay();
  if (!overlay) return;

  overlay.querySelector('.modal-title').textContent = title;
  overlay.querySelector('.modal-body').innerHTML = bodyHTML;
  const footer = overlay.querySelector('.modal-footer');
  if (footer) footer.innerHTML = footerHTML + `<button class="btn btn-ghost btn-sm" onclick="hideModal()">Close</button>`;

  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

export function hideModal() {
  const overlay = getOverlay();
  if (overlay) overlay.classList.remove('open');
  document.body.style.overflow = '';
}

// Close on overlay click
document.addEventListener('DOMContentLoaded', () => {
  const overlay = document.getElementById('modal-overlay');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) hideModal();
    });
  }
  // ESC key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideModal();
  });
});

/* ── Toast ──────────────────────────────────────────────────── */
let _toastContainer = null;

function getToastContainer() {
  if (!_toastContainer) {
    _toastContainer = document.getElementById('toast-container');
    if (!_toastContainer) {
      _toastContainer = document.createElement('div');
      _toastContainer.id = 'toast-container';
      document.body.appendChild(_toastContainer);
    }
  }
  return _toastContainer;
}

export function showToast(message, type = 'info', durationMs = 3500) {
  const container = getToastContainer();
  const icons = { success: 'fa-check-circle', error: 'fa-times-circle', info: 'fa-info-circle', warn: 'fa-exclamation-triangle' };
  const icon = icons[type] || icons.info;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<i class="fas ${icon}"></i><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'opacity 0.3s, transform 0.3s';
    setTimeout(() => toast.remove(), 350);
  }, durationMs);
}

/* ── Debounce ───────────────────────────────────────────────── */
export function debounce(fn, ms = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/* ── Confidence HTML ────────────────────────────────────────── */
export function confidenceBar(confidence) {
  const pct = confidence ?? 0;
  const color = pct >= 75 ? 'var(--accent-green)'
              : pct >= 50 ? 'var(--accent-cyan)'
              : pct >= 25 ? 'var(--accent-amber)'
              : 'var(--accent-red)';
  return `
    <div class="confidence-bar">
      <div class="confidence-track">
        <div class="confidence-fill" style="width:${pct}%;background:${color};"></div>
      </div>
      <span>${pct}%</span>
    </div>`;
}

/* ── Truncate text ──────────────────────────────────────────── */
export function truncate(str, n = 40) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

/* ── Loading / Error state HTML ─────────────────────────────── */
export function loadingHTML() {
  return `<div class="loading-state"><div class="spinner"></div><p>Loading…</p></div>`;
}

export function errorHTML(msg) {
  return `<div class="error-state"><i class="fas fa-exclamation-triangle"></i> ${msg}</div>`;
}

/* ── Escape HTML ────────────────────────────────────────────── */
export function escHtml(str) {
  if (!str && str !== 0) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
