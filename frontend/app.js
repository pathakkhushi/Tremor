/**
 * Tremor — Frontend Logic
 * Communicates with the Flask API at http://localhost:5000
 */

const API_BASE = 'http://localhost:5000';

// ─── State ────────────────────────────────────────────────────────────────────
let lastResults = null;

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const ui = {
  statusDot:      $('statusDot'),
  statusLabel:    $('statusLabel'),
  logTypeSelect:  $('logTypeSelect'),
  thresholdInput: $('thresholdInput'),
  windowInput:    $('windowInput'),
  logInput:       $('logInput'),
  charCount:      $('charCount'),
  clearBtn:       $('clearBtn'),
  loadSshBtn:     $('loadSshBtn'),
  loadApacheBtn:  $('loadApacheBtn'),
  analyzeBtn:     $('analyzeBtn'),
  btnIcon:        $('btnIcon'),
  btnText:        $('btnText'),
  btnSpinner:     $('btnSpinner'),
  errorBanner:    $('errorBanner'),
  errorMsg:       $('errorMsg'),
  errorClose:     $('errorClose'),
  resultsSection: $('resultsSection'),
  resultsMeta:    $('resultsMeta'),
  statTotal:      $('statTotal'),
  statUnique:     $('statUnique'),
  statFlagged:    $('statFlagged'),
  statParsed:     $('statParsed'),
  chartsGrid:     $('chartsGrid'),
  flaggedSub:     $('flaggedSub'),
  tableWrap:      $('tableWrap'),
  overlay:        $('overlay'),
  overlayStatus:  $('overlayStatus'),
  lightbox:       $('lightbox'),
  lightboxImg:    $('lightboxImg'),
  lightboxClose:  $('lightboxClose'),
};


// ─── Health Check ─────────────────────────────────────────────────────────────

async function checkHealth() {
  try {
    const r = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      setStatus('online', '✓ API Connected');
    } else {
      setStatus('offline', 'API Error');
    }
  } catch {
    setStatus('offline', 'Tremor offline — double-click START SERVER.bat');
  }
}

function setStatus(state, label) {
  ui.statusDot.className = `status-dot ${state}`;
  ui.statusLabel.textContent = label;
}


// ─── Load Sample ──────────────────────────────────────────────────────────────

async function loadSampleLog(type) {
  const btn = type === 'ssh' ? ui.loadSshBtn : ui.loadApacheBtn;
  const orig = btn.textContent;
  btn.textContent = '⏳ Loading…';
  btn.disabled = true;

  try {
    const r = await fetch(`${API_BASE}/api/sample/${type}/raw`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const text = await r.text();
    ui.logInput.value = text;
    ui.logTypeSelect.value = type;
    updateCharCount();
    hideError();
  } catch (e) {
    const isOffline = e instanceof TypeError && e.message.toLowerCase().includes('fetch');
    showError(
      isOffline
        ? '❌ Cannot reach Tremor server. Please double-click "START SERVER.bat" in the project folder first, then try again.'
        : `Failed to load sample log: ${e.message}`
    );
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
}


// ─── Analyze ──────────────────────────────────────────────────────────────────

async function analyze() {
  const logText = ui.logInput.value.trim();
  if (!logText) {
    showError('Please paste log content or load a sample first.');
    return;
  }

  const body = {
    log_text:       logText,
    log_type:       ui.logTypeSelect.value,
    threshold:      parseInt(ui.thresholdInput.value) || 5,
    window_seconds: parseInt(ui.windowInput.value)    || 60,
  };

  setLoading(true);
  hideError();
  updateOverlayStatus('Parsing log entries…');

  try {
    // Stagger the status messages for a nicer UX feel
    const statusTimer = setTimeout(() => updateOverlayStatus('Running brute-force detection…'), 800);
    const statusTimer2 = setTimeout(() => updateOverlayStatus('Generating charts…'), 1600);

    let r;
    try {
      r = await fetch(`${API_BASE}/api/analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
    } catch (fetchErr) {
      clearTimeout(statusTimer);
      clearTimeout(statusTimer2);
      throw new Error('Cannot reach Tremor server. Please double-click "START SERVER.bat" in the project folder, wait for it to start, then try again.');
    }

    clearTimeout(statusTimer);
    clearTimeout(statusTimer2);

    const data = await r.json();

    if (!r.ok) {
      throw new Error(data.error || `HTTP ${r.status}`);
    }

    lastResults = data;
    renderResults(data);

  } catch (e) {
    showError(`Analysis failed: ${e.message}`);
  } finally {
    setLoading(false);
  }
}


// ─── Render Results ───────────────────────────────────────────────────────────

function renderResults(data) {
  // Show section
  ui.resultsSection.classList.remove('hidden');
  ui.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Meta pills
  ui.resultsMeta.innerHTML = `
    <span class="meta-pill">🔐 ${(data.log_type || 'unknown').toUpperCase()}</span>
    <span class="meta-pill">⏱ ${data.stats?.time_span || 'N/A'}</span>
    <span class="meta-pill">🎯 Threshold: ${ui.thresholdInput.value} / ${ui.windowInput.value}s window</span>
  `;

  // Stats
  const s = data.stats || {};
  animateCounter(ui.statTotal,   s.total_attempts || 0);
  animateCounter(ui.statUnique,  s.unique_ips     || 0);
  animateCounter(ui.statFlagged, s.flagged_count  || 0);
  animateCounter(ui.statParsed,  data.entries_parsed || 0);

  // Charts
  renderCharts(data.charts || {});

  // Table
  const flagged = data.flagged_ips || [];
  ui.flaggedSub.textContent = flagged.length
    ? `${flagged.length} IP${flagged.length > 1 ? 's' : ''} exceeded the detection threshold`
    : 'No IPs exceeded the detection threshold with current settings';
  renderTable(flagged);
}


// ─── Charts ───────────────────────────────────────────────────────────────────

const CHART_META = {
  timeline: { label: '📈 Failed Login Attempts — Timeline',       full: true  },
  top_ips:  { label: '🏴 Top Attacking IPs by Failed Attempts',  full: false },
  heatmap:  { label: '🔥 Attack Intensity Heatmap',              full: true  },
};

function renderCharts(charts) {
  ui.chartsGrid.innerHTML = '';

  const keys = Object.keys(charts).filter(k => charts[k]);
  if (!keys.length) {
    ui.chartsGrid.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">📊</span>
        Not enough data to generate charts. Try loading a sample log.
      </div>`;
    return;
  }

  keys.forEach(key => {
    const meta  = CHART_META[key] || { label: key, full: false };
    const card  = document.createElement('div');
    card.className = `chart-card${meta.full ? ' full-width' : ''}`;
    card.setAttribute('role', 'img');
    card.setAttribute('aria-label', meta.label);
    card.title = 'Click to enlarge';

    const img = document.createElement('img');
    img.className = 'chart-img';
    img.src = `data:image/png;base64,${charts[key]}`;
    img.alt = meta.label;
    img.loading = 'lazy';

    card.innerHTML = `<div class="chart-title">${meta.label}</div>`;
    card.appendChild(img);

    // Lightbox on click
    card.addEventListener('click', () => openLightbox(charts[key], meta.label));

    ui.chartsGrid.appendChild(card);
  });
}

function openLightbox(b64, alt) {
  ui.lightboxImg.src = `data:image/png;base64,${b64}`;
  ui.lightboxImg.alt = alt;
  ui.lightbox.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeLightbox() {
  ui.lightbox.classList.add('hidden');
  document.body.style.overflow = '';
}


// ─── Flagged IPs Table ────────────────────────────────────────────────────────

function renderTable(flagged) {
  if (!flagged.length) {
    ui.tableWrap.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">✅</span>
        No flagged IPs detected with current threshold settings.<br/>
        Try lowering the threshold or loading a sample log.
      </div>`;
    return;
  }

  const rows = flagged.map((d, i) => `
    <tr style="animation-delay:${i * 40}ms">
      <td><span class="ip-cell">${escHtml(d.ip)}</span></td>
      <td><span class="count-cell">${d.total_attempts}</span></td>
      <td><span class="window-cell">${d.max_in_window}</span></td>
      <td><span class="time-cell">${escHtml(d.first_seen)}<br/>${escHtml(d.last_seen)}</span></td>
      <td>${d.duration_minutes}m</td>
      <td>${d.rate_per_minute}/min</td>
      <td>${severityBadge(d.severity)}</td>
    </tr>
  `).join('');

  ui.tableWrap.innerHTML = `
    <table class="ip-table" role="table" aria-label="Flagged IP addresses">
      <thead>
        <tr>
          <th>IP Address</th>
          <th>Total Attempts</th>
          <th>Max / Window</th>
          <th>First → Last Seen</th>
          <th>Duration</th>
          <th>Rate</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function severityBadge(sev) {
  const cls = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium' };
  return `<span class="badge ${cls[sev] || 'badge-medium'}">${escHtml(sev || 'MEDIUM')}</span>`;
}


// ─── Utilities ────────────────────────────────────────────────────────────────

function animateCounter(el, target) {
  const duration = 900;
  const start    = performance.now();
  const from     = parseInt(el.textContent) || 0;

  function step(now) {
    const t      = Math.min((now - start) / duration, 1);
    const eased  = 1 - Math.pow(1 - t, 3);         // ease-out-cubic
    el.textContent = Math.round(from + (target - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function updateCharCount() {
  const n = ui.logInput.value.length;
  ui.charCount.textContent = n.toLocaleString() + ' chars';
}

function showError(msg) {
  ui.errorMsg.textContent = msg;
  ui.errorBanner.classList.remove('hidden');
  ui.errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideError() {
  ui.errorBanner.classList.add('hidden');
}

function setLoading(on) {
  ui.analyzeBtn.disabled = on;
  ui.btnIcon.textContent = on ? '' : '🔍';
  ui.btnText.textContent = on ? 'Analyzing…' : 'Analyze Logs';
  ui.btnSpinner.classList.toggle('hidden', !on);
  ui.overlay.classList.toggle('hidden', !on);
}

function updateOverlayStatus(msg) {
  ui.overlayStatus.textContent = msg;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}


// ─── Event Listeners ──────────────────────────────────────────────────────────

ui.logInput.addEventListener('input', updateCharCount);

ui.clearBtn.addEventListener('click', () => {
  ui.logInput.value = '';
  updateCharCount();
  hideError();
});

ui.loadSshBtn.addEventListener('click',    () => loadSampleLog('ssh'));
ui.loadApacheBtn.addEventListener('click', () => loadSampleLog('apache'));

ui.analyzeBtn.addEventListener('click', analyze);

ui.logInput.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') analyze();
});

ui.errorClose.addEventListener('click', hideError);

ui.lightboxClose.addEventListener('click', closeLightbox);
ui.lightbox.addEventListener('click', e => {
  if (e.target === ui.lightbox) closeLightbox();
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeLightbox();
});


// ─── Init ─────────────────────────────────────────────────────────────────────

(async function init() {
  updateCharCount();
  await checkHealth();

  // Re-check health every 30s
  setInterval(checkHealth, 30_000);
})();
