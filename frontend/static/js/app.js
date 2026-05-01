// ── Helpers ────────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

function _setStatus(id, msg, color) {
  const el = $(id); if (!el) return;
  el.textContent = msg || '';
  el.style.color = color || '';
}

function _parseEmails(raw) {
  return (raw || '')
    .split(/[\s,;]+/)
    .map(s => s.trim())
    .filter(Boolean);
}

async function _apiFetch(url, opts = {}) {
  const r = await fetch(url, { credentials: 'same-origin', ...opts });
  if (r.status === 401) {
    showLogin();
    throw new Error('not authenticated');
  }
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const j = await r.json();
      msg = j.detail || JSON.stringify(j);
    } catch {}
    throw new Error(msg);
  }
  return r;
}

function _esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function _fmtDate(s) {
  if (!s) return '—';
  try {
    const d = new Date(s);
    if (isNaN(d.getTime())) return s;
    return d.toLocaleString();
  } catch { return s; }
}

function _severityBadge(sev) {
  if (!sev || !sev.level) return '';
  const lvl = sev.level;
  const reasons = (sev.reasons || []).join(' • ');
  const title = `${lvl.toUpperCase()} (score ${sev.score})${reasons ? ' — ' + reasons : ''}`;
  return `<span class="sev-badge sev-${_esc(lvl)}" title="${_esc(title)}">${_esc(lvl)}</span>`;
}

const _SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

// ── Tabs ───────────────────────────────────────────────────────────────────────

function initNav() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  document.querySelectorAll('button[id]').forEach(btn => {
    const id = btn.id;
    if (id === 'add-emails-btn')         btn.addEventListener('click', addEmails);
    if (id === 'monitor-scan-btn')       btn.addEventListener('click', runScanNow);
    if (id === 'dash-scan-btn')          btn.addEventListener('click', runScanNow);
    if (id === 'findings-refresh')       btn.addEventListener('click', () => loadFindings('findings'));
    if (id === 'pastes-refresh')         btn.addEventListener('click', loadPastes);
    if (id === 'report-run-btn')         btn.addEventListener('click', runReport);
    if (id === 'cfg-save-btn')           btn.addEventListener('click', saveConfig);
    if (id === 'cfg-test-email-btn')     btn.addEventListener('click', testEmail);
    if (id === 'cfg-test-webhook-btn')   btn.addEventListener('click', testWebhook);
    if (id === 'cfg-regen-btn')          btn.addEventListener('click', regenerateToken);
    if (id === 'login-btn')              btn.addEventListener('click', login);
    if (id === 'logout-btn')             btn.addEventListener('click', logout);
  });
  $('login-token')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') login();
  });
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.view').forEach(v => {
    v.hidden = v.id !== ('view-' + name);
  });
  if (name === 'dashboard') loadDashboard();
  if (name === 'monitor')   loadEmails();
  if (name === 'findings')  loadFindings('findings');
  if (name === 'pastes')    loadPastes();
  if (name === 'config')    loadConfig();
}

// ── WebSocket ──────────────────────────────────────────────────────────────────

let _ws = null;
let _activeReportRunId = null;

function connectWebSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws`;
  _ws = new WebSocket(url);
  const status = $('ws-status');

  _ws.addEventListener('open',  () => { status.classList.remove('bad'); status.classList.add('ok'); });
  _ws.addEventListener('close', () => {
    status.classList.remove('ok'); status.classList.add('bad');
    setTimeout(connectWebSocket, 3000);
  });
  _ws.addEventListener('error', () => { status.classList.remove('ok'); status.classList.add('bad'); });
  _ws.addEventListener('message', (ev) => {
    try {
      const e = JSON.parse(ev.data);
      handleWsEvent(e);
    } catch {}
  });
}

function handleWsEvent(e) {
  switch (e.type) {
    case 'scan_started':
      _showProgress(0, e.email_count, 'Starting…');
      _setScanButtons(true);
      break;
    case 'scan_progress':
      _showProgress(e.index - 1, e.total, `Scanning ${e.email}… (${e.index}/${e.total})`);
      break;
    case 'scan_finished':
      _hideProgress(e.status === 'ok'
        ? `✓ Done — ${e.new_breaches || 0} new breach(es), ${e.new_pastes || 0} new paste(s)`
        : `⚠ ${e.error || 'partial'}`);
      _setScanButtons(false);
      loadDashboard();
      if (document.querySelector('.tab.active')?.dataset.tab === 'findings') loadFindings('findings');
      if (document.querySelector('.tab.active')?.dataset.tab === 'pastes')   loadPastes();
      if (_activeReportRunId && e.run_id === _activeReportRunId) finishReport(e);
      break;
    case 'finding':
      if (_activeReportRunId && e.run_id === _activeReportRunId) {
        _appendReportFinding(e);
      }
      break;
    case 'scan_error':
      _setStatus('dash-scan-status', `Error on ${e.email}: ${e.error}`, '#f85149');
      break;
    case 'alert_sent':
      console.log('Alert dispatched:', e.status);
      break;
  }
}

function _showProgress(done, total, text) {
  const wrap = $('dash-progress');
  if (wrap) wrap.style.display = 'block';
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  if ($('dash-progress-fill')) $('dash-progress-fill').style.width = pct + '%';
  if ($('dash-progress-text')) $('dash-progress-text').textContent = text;
}

function _hideProgress(text) {
  if ($('dash-progress-fill')) $('dash-progress-fill').style.width = '100%';
  if ($('dash-progress-text')) $('dash-progress-text').textContent = text || '';
  setTimeout(() => {
    const wrap = $('dash-progress');
    if (wrap) wrap.style.display = 'none';
  }, 4000);
}

function _setScanButtons(scanning) {
  ['dash-scan-btn', 'monitor-scan-btn'].forEach(id => {
    const b = $(id);
    if (!b) return;
    b.disabled = scanning;
    b.textContent = scanning ? '🕵️ Scanning…' : '🕵️ Scan All Now';
  });
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const r = await _apiFetch('/api/dashboard');
    const d = await r.json();
    $('stat-monitored').textContent = d.monitored_count;
    $('stat-breaches').textContent  = d.unique_breaches;
    $('stat-findings').textContent  = d.total_breach_findings;
    $('stat-pastes').textContent    = d.total_paste_findings;

    const sc = d.severity_counts || { critical:0, high:0, medium:0, low:0 };
    $('stat-critical').textContent = sc.critical || 0;
    $('stat-high').textContent     = sc.high || 0;
    $('stat-medium').textContent   = sc.medium || 0;
    $('stat-low').textContent      = sc.low || 0;

    if (d.last_run) {
      $('dash-last-run').innerHTML =
        `Started ${_esc(_fmtDate(d.last_run.started_at))} · ` +
        `${_esc(d.last_run.status)} · ` +
        `+${d.last_run.new_breaches || 0} breach(es), ` +
        `+${d.last_run.new_pastes || 0} paste(s)`;
    } else {
      $('dash-last-run').textContent = 'No runs yet.';
    }
    $('dash-next-run').textContent = d.next_run_at
      ? `Next scheduled run: ${_fmtDate(d.next_run_at)}`
      : 'Schedule disabled.';

    const ul = $('dash-recent-findings');
    ul.innerHTML = '';
    (d.recent_findings || []).forEach(f => {
      const li = document.createElement('li');
      li.innerHTML =
        `${_severityBadge(f.severity)} ` +
        `<span class="email">${_esc(f.email)}</span> → ` +
        `<span class="breach">${_esc(f.title || f.breach_name)}</span>` +
        `<span class="when">${_esc(_fmtDate(f.first_seen_at))}</span>`;
      ul.appendChild(li);
    });
    if (!ul.children.length) {
      const li = document.createElement('li');
      li.className = 'muted';
      li.textContent = 'No findings yet.';
      ul.appendChild(li);
    }

    const tbody = document.querySelector('#dash-runs tbody');
    tbody.innerHTML = '';
    (d.recent_runs || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${_esc(_fmtDate(r.started_at))}</td>` +
        `<td>${_esc(_fmtDate(r.finished_at))}</td>` +
        `<td>${r.email_count}</td>` +
        `<td>${r.new_breaches}</td>` +
        `<td>${r.new_pastes}</td>` +
        `<td>${_renderRunStatus(r)}</td>`;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.warn('loadDashboard:', e);
  }
}

function _renderRunStatus(r) {
  const cls = r.status === 'ok' ? 'ok' : (r.status === 'partial' ? 'warn' : 'bad');
  const t = r.error ? ` title="${_esc(r.error)}"` : '';
  return `<span class="badge ${cls}"${t}>${_esc(r.status)}</span>`;
}

// ── Monitored ─────────────────────────────────────────────────────────────────

async function loadEmails() {
  try {
    const r = await _apiFetch('/api/emails');
    const d = await r.json();
    const tbody = document.querySelector('#monitor-table tbody');
    tbody.innerHTML = '';
    (d.emails || []).forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${_esc(e.email)}</td>` +
        `<td>${_esc(_fmtDate(e.added_at))}</td>` +
        `<td>${e.breach_count}</td>` +
        `<td>${e.paste_count}</td>` +
        `<td>${_esc(_fmtDate(e.last_breach_at))}</td>` +
        `<td><button class="danger" data-rm="${_esc(e.email)}">Remove</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('button[data-rm]').forEach(b => {
      b.addEventListener('click', () => removeEmail(b.dataset.rm));
    });
    if (!tbody.children.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No emails yet — add some above.</td></tr>';
    }
  } catch (e) {
    console.warn('loadEmails:', e);
  }
}

async function addEmails() {
  const raw = $('add-emails-input').value;
  const emails = _parseEmails(raw);
  if (!emails.length) {
    _setStatus('monitor-add-status', 'Enter at least one email.', '#f85149');
    return;
  }
  try {
    _setStatus('monitor-add-status', 'Adding…', '');
    const r = await _apiFetch('/api/emails', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({emails}),
    });
    const d = await r.json();
    const parts = [`${(d.added||[]).length} added`];
    if ((d.skipped||[]).length) parts.push(`${d.skipped.length} skipped`);
    if ((d.invalid||[]).length) parts.push(`${d.invalid.length} invalid`);
    _setStatus('monitor-add-status', parts.join(', '), '#3fb950');
    $('add-emails-input').value = '';
    loadEmails();
    setTimeout(() => _setStatus('monitor-add-status', '', ''), 4000);
  } catch (e) {
    _setStatus('monitor-add-status', 'Error: ' + e.message, '#f85149');
  }
}

async function removeEmail(email) {
  if (!confirm('Stop monitoring ' + email + '?')) return;
  try {
    await _apiFetch('/api/emails/' + encodeURIComponent(email), { method: 'DELETE' });
    loadEmails();
    loadDashboard();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// ── Findings & pastes ─────────────────────────────────────────────────────────

async function loadFindings(_caller) {
  try {
    const r = await _apiFetch('/api/findings?limit=500');
    const d = await r.json();
    const tbody = document.querySelector('#findings-table tbody');
    tbody.innerHTML = '';
    (d.findings || []).forEach(f => {
      const classes = (f.data_classes || []).map(c => `<span class="badge">${_esc(c)}</span>`).join('');
      const sens = f.is_sensitive ? '<span class="badge bad">sensitive</span>' : '';
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${_severityBadge(f.severity)}</td>` +
        `<td>${_esc(f.email)}</td>` +
        `<td>${_esc(f.title || f.breach_name)} ${sens}<br><span class="muted small">${_esc(f.domain || '')}</span></td>` +
        `<td>${_esc(f.breach_date || '—')}</td>` +
        `<td>${(f.pwn_count || 0).toLocaleString()}</td>` +
        `<td>${classes || '—'}</td>` +
        `<td>${_esc(_fmtDate(f.first_seen_at))}</td>`;
      tbody.appendChild(tr);
    });
    if (!tbody.children.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">No findings yet.</td></tr>';
    }
  } catch (e) {
    console.warn('loadFindings:', e);
  }
}

async function loadPastes() {
  try {
    const r = await _apiFetch('/api/pastes?limit=500');
    const d = await r.json();
    const tbody = document.querySelector('#pastes-table tbody');
    tbody.innerHTML = '';
    (d.pastes || []).forEach(p => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${_severityBadge(p.severity)}</td>` +
        `<td>${_esc(p.email)}</td>` +
        `<td>${_esc(p.source || '?')}</td>` +
        `<td>${_esc(p.title || '—')}</td>` +
        `<td>${_esc(p.paste_date || '—')}</td>` +
        `<td>${(p.email_count || 0).toLocaleString()}</td>` +
        `<td>${_esc(_fmtDate(p.first_seen_at))}</td>`;
      tbody.appendChild(tr);
    });
    if (!tbody.children.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">No paste findings yet.</td></tr>';
    }
  } catch (e) {
    console.warn('loadPastes:', e);
  }
}

// ── Scan actions ──────────────────────────────────────────────────────────────

async function runScanNow() {
  _setScanButtons(true);
  _setStatus('dash-scan-status', 'Starting scan…', '');
  try {
    const r = await _apiFetch('/api/scan', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ persist: true }),
    });
    const d = await r.json();
    _setStatus('dash-scan-status', `Scan started — ${d.email_count} email(s).`, '#58a6ff');
  } catch (e) {
    _setStatus('dash-scan-status', 'Error: ' + e.message, '#f85149');
    _setScanButtons(false);
  }
}

// ── One-shot report ───────────────────────────────────────────────────────────

const _reportBuckets = { breaches: [], pastes: [] };

async function runReport() {
  const raw = $('report-emails-input').value;
  const emails = _parseEmails(raw);
  if (!emails.length) {
    _setStatus('report-status', 'Enter at least one email.', '#f85149');
    return;
  }
  _reportBuckets.breaches = [];
  _reportBuckets.pastes = [];
  $('report-results-panel').style.display = 'none';
  $('report-results').innerHTML = '';
  const btn = $('report-run-btn');
  btn.disabled = true;
  btn.textContent = '🔍 Running…';
  _setStatus('report-status', `Scanning ${emails.length} email(s)…`, '#58a6ff');
  try {
    const r = await _apiFetch('/api/scan', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ emails, persist: false }),
    });
    const d = await r.json();
    _activeReportRunId = d.run_id;
  } catch (e) {
    _setStatus('report-status', 'Error: ' + e.message, '#f85149');
    btn.disabled = false;
    btn.textContent = '🔍 Generate Report';
  }
}

function _appendReportFinding(e) {
  if (e.kind === 'breach') _reportBuckets.breaches.push(e);
  else if (e.kind === 'paste') _reportBuckets.pastes.push(e);
}

function finishReport(e) {
  const btn = $('report-run-btn');
  btn.disabled = false;
  btn.textContent = '🔍 Generate Report';
  _activeReportRunId = null;

  if (e.status === 'error') {
    _setStatus('report-status', 'Error: ' + (e.error || 'unknown'), '#f85149');
    return;
  }
  _setStatus('report-status',
    `Done — ${_reportBuckets.breaches.length} breach(es), ${_reportBuckets.pastes.length} paste(s).`,
    '#3fb950');

  $('report-results-panel').style.display = 'block';
  const out = $('report-results');
  out.innerHTML = '';

  const sortBySev = (a, b) =>
    (_SEV_RANK[(b.severity||{}).level] || 0) - (_SEV_RANK[(a.severity||{}).level] || 0);
  const breaches = [..._reportBuckets.breaches].sort(sortBySev);
  const pastes   = [..._reportBuckets.pastes].sort(sortBySev);

  const summary = document.createElement('div');
  summary.className = 'report-block';
  const counts = { critical:0, high:0, medium:0, low:0 };
  breaches.forEach(f => { counts[(f.severity||{}).level || 'low']++; });
  summary.innerHTML =
    `<h4>Summary</h4>` +
    `<p>${breaches.length} breach finding(s) — ` +
    `<span class="sev-badge sev-critical">${counts.critical} critical</span> ` +
    `<span class="sev-badge sev-high">${counts.high} high</span> ` +
    `<span class="sev-badge sev-medium">${counts.medium} medium</span> ` +
    `<span class="sev-badge sev-low">${counts.low} low</span></p>` +
    `<p>${pastes.length} paste finding(s)</p>`;
  out.appendChild(summary);

  const breachBlock = document.createElement('div');
  breachBlock.className = 'report-block';
  breachBlock.innerHTML = `<h4>Breaches (${breaches.length})</h4>`;
  if (!breaches.length) {
    breachBlock.innerHTML += '<div class="report-empty">None</div>';
  } else {
    const ul = document.createElement('ul');
    ul.className = 'list';
    breaches.forEach(f => {
      const li = document.createElement('li');
      const dc = (f.data_classes || []).map(c => `<span class="badge">${_esc(c)}</span>`).join('');
      li.innerHTML =
        `${_severityBadge(f.severity)} ` +
        `<span class="email">${_esc(f.email)}</span> → ` +
        `<span class="breach">${_esc(f.title || f.breach_name)}</span> ` +
        `<span class="when">${_esc(f.breach_date || '—')}</span><br>` +
        `<span class="muted small">${dc || '—'}</span>`;
      ul.appendChild(li);
    });
    breachBlock.appendChild(ul);
  }
  out.appendChild(breachBlock);

  const pasteBlock = document.createElement('div');
  pasteBlock.className = 'report-block';
  pasteBlock.innerHTML = `<h4>Pastes (${pastes.length})</h4>`;
  if (!pastes.length) {
    pasteBlock.innerHTML += '<div class="report-empty">None</div>';
  } else {
    const ul = document.createElement('ul');
    ul.className = 'list';
    pastes.forEach(f => {
      const li = document.createElement('li');
      li.innerHTML =
        `${_severityBadge(f.severity)} ` +
        `<span class="email">${_esc(f.email)}</span> → ` +
        `<span class="breach">${_esc(f.source || '?')}</span> ` +
        `${_esc(f.title || '')} ` +
        `<span class="when">${_esc(f.paste_date || '—')}</span>`;
      ul.appendChild(li);
    });
    pasteBlock.appendChild(ul);
  }
  out.appendChild(pasteBlock);
}

// ── Config ────────────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    const r = await _apiFetch('/api/config');
    const d = await r.json();

    $('cfg-enabled').checked        = !!d.enabled;
    $('cfg-interval').value         = d.interval_hours || 6;
    $('cfg-rpm').value              = d.hibp_rpm || 10;
    $('cfg-include-pastes').checked = d.include_pastes !== false;
    $('cfg-alert-on-new').checked   = d.alert_on_new !== false;

    $('cfg-smtp-host').value    = d.smtp_host || '';
    $('cfg-smtp-port').value    = d.smtp_port || 587;
    $('cfg-smtp-user').value    = d.smtp_user || '';
    $('cfg-from').value         = d.from_addr || '';
    $('cfg-to').value           = d.to_email || '';
    $('cfg-webhook-url').value  = d.webhook_url || '';
    $('cfg-webhook-kind').value = d.webhook_kind || 'generic';

    $('cfg-hibp-status').textContent = d.hibp_api_key_set
      ? 'API key on file (leave blank to keep, enter new key to replace).'
      : 'No HIBP API key set — required for any scanning.';

    $('cfg-smtp-pass-status').textContent = d.smtp_pass_set
      ? 'Password saved (leave blank to keep).'
      : 'No password saved.';
  } catch (e) {
    console.warn('loadConfig:', e);
  }
}

async function saveConfig() {
  const body = {
    enabled:        $('cfg-enabled').checked,
    interval_hours: parseInt($('cfg-interval').value, 10) || 6,
    hibp_rpm:       parseInt($('cfg-rpm').value, 10) || 10,
    include_pastes: $('cfg-include-pastes').checked,
    alert_on_new:   $('cfg-alert-on-new').checked,
    hibp_api_key:   $('cfg-hibp-key').value || '',
    smtp_host:      $('cfg-smtp-host').value,
    smtp_port:      parseInt($('cfg-smtp-port').value, 10) || 587,
    smtp_user:      $('cfg-smtp-user').value,
    smtp_pass:      $('cfg-smtp-pass').value,
    from_addr:      $('cfg-from').value,
    to_email:       $('cfg-to').value,
    webhook_url:    $('cfg-webhook-url').value,
    webhook_kind:   $('cfg-webhook-kind').value,
  };
  try {
    _setStatus('cfg-schedule-status', 'Saving…', '');
    _setStatus('cfg-alert-status', '', '');
    await _apiFetch('/api/config', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    _setStatus('cfg-schedule-status',
      'Saved' + (body.enabled ? ` — every ${body.interval_hours}h` : ' — disabled'),
      '#3fb950');
    $('cfg-hibp-key').value = '';
    $('cfg-smtp-pass').value = '';
    loadConfig();
    setTimeout(() => _setStatus('cfg-schedule-status', '', ''), 4000);
  } catch (e) {
    _setStatus('cfg-schedule-status', 'Error: ' + e.message, '#f85149');
  }
}

async function testEmail() {
  _setStatus('cfg-alert-status', 'Sending test email…', '');
  try {
    await _apiFetch('/api/config/test-email', { method: 'POST' });
    _setStatus('cfg-alert-status', 'Test email sent.', '#3fb950');
    setTimeout(() => _setStatus('cfg-alert-status', '', ''), 4000);
  } catch (e) {
    _setStatus('cfg-alert-status', 'Email error: ' + e.message, '#f85149');
  }
}

async function testWebhook() {
  _setStatus('cfg-alert-status', 'Sending test webhook…', '');
  try {
    await _apiFetch('/api/config/test-webhook', { method: 'POST' });
    _setStatus('cfg-alert-status', 'Test webhook sent.', '#3fb950');
    setTimeout(() => _setStatus('cfg-alert-status', '', ''), 4000);
  } catch (e) {
    _setStatus('cfg-alert-status', 'Webhook error: ' + e.message, '#f85149');
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

function showLogin() {
  $('login-overlay').hidden = false;
  setTimeout(() => $('login-token')?.focus(), 50);
}

function hideLogin() {
  $('login-overlay').hidden = true;
}

async function login() {
  const token = ($('login-token').value || '').trim();
  if (!token) {
    _setStatus('login-status', 'Enter your admin token.', '#f85149');
    return;
  }
  try {
    _setStatus('login-status', 'Signing in…', '');
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.detail || 'invalid token');
    }
    // Verify the cookie actually stuck before booting the app — a 200 here
    // only means the token is valid, not that the browser stored the cookie.
    const probe = await fetch('/api/auth/status', { credentials: 'same-origin' });
    const pd = await probe.json().catch(() => ({}));
    if (!pd.authenticated) {
      throw new Error(
        'Token accepted, but the session cookie did not persist. ' +
        'Check browser cookie / privacy settings for localhost and retry.'
      );
    }
    $('login-token').value = '';
    _setStatus('login-status', '', '');
    hideLogin();
    bootApp();
  } catch (e) {
    _setStatus('login-status', e.message, '#f85149');
  }
}

async function logout() {
  if (!confirm('Sign out of DarkWebScanner?')) return;
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  } catch {}
  showLogin();
  if (_ws) { try { _ws.close(); } catch {} }
}

async function regenerateToken() {
  if (!confirm('Generate a new admin token? The old token will stop working immediately.')) return;
  _setStatus('cfg-token-status', 'Regenerating…', '');
  try {
    const r = await _apiFetch('/api/auth/regenerate', { method: 'POST' });
    const d = await r.json();
    _setStatus('cfg-token-status',
      `New token saved to ${d.saved_to}. You're already signed in here.`,
      '#3fb950');
  } catch (e) {
    _setStatus('cfg-token-status', 'Error: ' + e.message, '#f85149');
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function bootApp() {
  connectWebSocket();
  loadDashboard();
  loadEmails();
  loadConfig();
}

async function bootstrap() {
  initNav();
  // The server-side `/?token=` handler sets the cookie via redirect, so by
  // the time this script runs we should already be authenticated. Probe once.
  try {
    const r = await fetch('/api/auth/status', { credentials: 'same-origin' });
    const d = await r.json();
    if (d.authenticated) {
      bootApp();
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }
}

document.addEventListener('DOMContentLoaded', bootstrap);
