// ═══════════════════════════════════════════════════════════════
//  SOC Tools — PKI Health, Alert Tuning, Source Health Detail
// ═══════════════════════════════════════════════════════════════

function initSocToolsPane() {
  loadPkiHealth();
  loadAlertTuning();
  loadSourceHealthDetail();
  loadIdsMetrics();
  loadSocMttr();
  loadUebaAnomalies();
  const refreshBtn = document.getElementById('socToolsRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => {
    loadPkiHealth(); loadAlertTuning(); loadSourceHealthDetail(); loadIdsMetrics();
    loadSocMttr(); loadUebaAnomalies();
  });
  const autoCloseBtn = document.getElementById('socAutoCloseBtn');
  if (autoCloseBtn) {
    const role = String(state?.auth?.status?.role || '').toLowerCase();
    const isAuthority = role === 'authority';
    autoCloseBtn.style.display = isAuthority ? '' : 'none';
    autoCloseBtn.toggleAttribute('aria-hidden', !isAuthority);
    autoCloseBtn.disabled = !isAuthority;
    autoCloseBtn.addEventListener('click', runAutoClose);
  }
}

// ─── PKI Health ───────────────────────────────────────────────

async function loadPkiHealth() {
  const container = document.getElementById('pkiHealthContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading PKI health...</div>';
  try {
    let health, stats, caPem;
    try {
      await Promise.all([
        apiFetchJson('/healthz').then(h => { health = h; }).catch(e => {
          console.warn('[PKI Health] /healthz failed:', e?.message);
          health = null;
        }),
        apiFetchJson('/api/stats').then(s => { stats = s; }).catch(e => {
          console.warn('[PKI Health] /api/stats failed:', e?.message);
          stats = null;
        }),
        fetch('/api/ca_cert', { credentials: 'same-origin' }).then((r) => (r.ok ? r.text() : '')).then(c => { caPem = c; }).catch(e => {
          console.warn('[PKI Health] /api/ca_cert failed:', e?.message);
          caPem = '';
        }),
      ]);
    } catch (e) {
      console.error('[PKI Health] Promise.all error:', e?.message);
      throw e;
    }
    if (!health) { container.innerHTML = '<div class="empty-state p-12">No PKI data.</div>'; return; }
    const ts = health.timestamp ? new Date(health.timestamp).toLocaleString() : '—';
    const caStatus = String(health?.ca_service?.status || 'unknown');
    const caCert = caPem ? `PEM loaded (${caPem.length} bytes)` : 'Unavailable';
    const knownAgents = Number(stats?.known_agents?.length || 0);
    const activeAgents = Number(stats?.connected_agents || 0);
    const expiringSoon = 0;
    const expCls = expiringSoon > 0 ? 'warn' : 'ok';
    container.innerHTML = `<div class="soc-tools-grid">
      <div><span class="muted soc-tools-label">CA Certificate</span><div class="soc-tools-value-mono">${escapeHtml(caCert)}</div></div>
      <div><span class="muted soc-tools-label">CA Status</span><div><strong>${escapeHtml(caStatus)}</strong></div></div>
      <div><span class="muted soc-tools-label">Known Agents</span><div><strong>${knownAgents}</strong> <span class="muted">(${activeAgents} active)</span></div></div>
      <div><span class="muted soc-tools-label">Last Health Snapshot</span><div><strong class="${expCls}">${escapeHtml(ts)}</strong></div></div>
    </div>`;
  } catch (e) {
    console.error('[PKI Health] Failed to load:', e?.message);
    container.innerHTML = `<div class="error-state p-12">Error loading PKI health: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load PKI health: ${e?.message || 'Unknown error'}`, 'error');
  }
}

// ─── Alert Tuning ─────────────────────────────────────────────

async function loadAlertTuning() {
  const container = document.getElementById('alertTuningContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading rule tuning…</div>';
  try {
    let alertsResp, rulesResp;
    await Promise.all([
      apiFetchJson('/api/alerts?limit=500').then(r => { alertsResp = r; }).catch(e => {
        console.warn('[Alert Tuning] /api/alerts failed:', e?.message);
        alertsResp = { alerts: [] };
      }),
      apiFetchJson('/api/rules').then(r => { rulesResp = r; }).catch(e => {
        console.warn('[Alert Tuning] /api/rules failed:', e?.message);
        rulesResp = { rules: [] };
      }),
    ]);
    const alerts = Array.isArray(alertsResp?.alerts) ? alertsResp.alerts : (Array.isArray(alertsResp) ? alertsResp : []);
    const rules = Array.isArray(rulesResp?.rules) ? rulesResp.rules : (Array.isArray(rulesResp) ? rulesResp : []);

    // Alert count per rule_id
    const alertsByRule = new Map();
    for (const a of alerts) {
      const rid = a.rule_id || a.rule_name || '—';
      alertsByRule.set(rid, (alertsByRule.get(rid) || 0) + 1);
    }

    // Summary stats
    const bySeverity = alerts.reduce((acc, a) => {
      const s = String(a?.severity || 'unknown').toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});

    const totalAlerts = alerts.length;
    const bars = ['critical','high','medium','low','info'].map(sev => {
      const cnt = bySeverity[sev] || 0;
      const w = totalAlerts > 0 ? Math.min(100, (cnt / totalAlerts) * 100) : 0;
      const barColor = sev === 'critical' ? 'var(--danger)' : sev === 'high' ? 'var(--warn)' : sev === 'medium' ? 'var(--accent)' : 'var(--stroke2, #444)';
      return `<div class="soc-tools-row">
        <span class="soc-tools-range">${escapeHtml(sev)}</span>
        <div class="soc-tools-bar"><div class="soc-tools-bar-fill" style="width:${w}%;background:${barColor};"></div></div>
        <span class="soc-tools-count">${cnt}</span>
      </div>`;
    }).join('');
    let html = `<div class="soc-tools-block"><strong class="soc-tools-title">Alert Distribution (last 500)</strong>${bars}</div>`;

    // Rule Tuning Table
    if (rules.length > 0) {
      const ruleRows = rules
        .sort((a, b) => (alertsByRule.get(b.id) || 0) - (alertsByRule.get(a.id) || 0))
        .slice(0, 50)
        .map(r => {
          const count = alertsByRule.get(r.id) || 0;
          const enabledCls = r.enabled === false ? 'muted' : '';
          const sevOpts = ['critical','high','medium','low','info'].map(s =>
            `<option value="${s}"${String(r.severity||'').toLowerCase()===s?' selected':''}>${s}</option>`
          ).join('');
          return `<tr class="rt-row${r.enabled === false ? ' rt-disabled' : ''}" data-rule-id="${escapeHtml(r.id)}">
            <td class="rt-name ${enabledCls}" title="${escapeHtml(r.id)}">${escapeHtml(r.name || r.id)}</td>
            <td class="rt-count">${count}</td>
            <td><select class="rt-sev filter-select" data-field="severity">${sevOpts}</select></td>
            <td>
              <label class="rt-toggle" title="${r.enabled===false?'Disabled':'Enabled'}">
                <input type="checkbox" class="rt-enable-cb" ${r.enabled !== false ? 'checked' : ''}>
                <span class="rt-toggle-lbl">${r.enabled !== false ? 'On' : 'Off'}</span>
              </label>
            </td>
            <td><button class="btn sm rt-save-btn" data-rule-id="${escapeHtml(r.id)}">Save</button></td>
          </tr>`;
        }).join('');

      html += `<div class="soc-tools-block">
        <strong class="soc-tools-title">Rule Tuning — top rules by alert volume</strong>
        <div class="muted text-12 mt-4 mb-8">Change severity or enable/disable rules, then click Save.</div>
        <div class="tableWrap maxh-320 mt-8">
          <table class="tbl rt-table"><thead>
            <tr><th>Rule</th><th title="Alerts in window">Alerts</th><th>Severity</th><th>Enabled</th><th></th></tr>
          </thead><tbody>${ruleRows}</tbody></table>
        </div>
      </div>`;
    }

    container.innerHTML = html;

    // Wire up Save buttons
    container.querySelectorAll('.rt-save-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const rid = btn.getAttribute('data-rule-id');
        const row = container.querySelector(`.rt-row[data-rule-id="${CSS.escape(rid)}"]`);
        if (!row) return;
        const sev = row.querySelector('.rt-sev')?.value || undefined;
        const enabled = row.querySelector('.rt-enable-cb')?.checked ?? true;
        btn.textContent = '…';
        btn.disabled = true;
        let successTimeout;
        try {
          await apiPostJson(`/api/rules/${encodeURIComponent(rid)}/tune`, { severity: sev, enabled });
          btn.textContent = '✓';
          row.classList.toggle('rt-disabled', !enabled);
          const lbl = row.querySelector('.rt-toggle-lbl');
          if (lbl) lbl.textContent = enabled ? 'On' : 'Off';
          successTimeout = setTimeout(() => { btn.textContent = 'Save'; btn.disabled = false; }, 2000);
        } catch (e) {
          btn.textContent = 'ERR';
          showToast('Tune failed: ' + (e.message || 'error'), 'error');
        } finally {
          setTimeout(() => { if (!btn.disabled) return; btn.textContent = 'Save'; btn.disabled = false; clearTimeout(successTimeout); }, 10000);
        }
      });
    });

    // Enable checkbox label sync
    container.querySelectorAll('.rt-enable-cb').forEach(cb => {
      cb.addEventListener('change', () => {
        const lbl = cb.closest('.rt-toggle')?.querySelector('.rt-toggle-lbl');
        if (lbl) lbl.textContent = cb.checked ? 'On' : 'Off';
      });
    });

  } catch (e) {
    console.error('[Alert Tuning] Failed to load:', e?.message);
    container.innerHTML = `<div class="error-state p-12">Error loading rule tuning: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load rule tuning: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function runAutoClose() {
  const role = String(state?.auth?.status?.role || '').toLowerCase();
  if (role !== 'authority') {
    showToast('Clear-all alerts requires Authority role', 'error');
    return;
  }
  try {
    await apiPostJson('/api/alerts/clear', {});
    showToast('Cleared alerts using /api/alerts/clear', 'ok');
    loadAlertTuning();
  } catch (e) {
    showToast('Auto-close failed: ' + (e.message || 'error'), 'error');
  }
}

// ─── Source Health Detail ─────────────────────────────────────

async function loadSourceHealthDetail() {
  const container = document.getElementById('sourceHealthDetailContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading source health detail...</div>';
  try {
    const data = await apiFetchJson('/api/source_health');
    if (!data || !Array.isArray(data.agents) || data.agents.length === 0) {
      container.innerHTML = '<div class="empty-state p-12">No source health detail available.</div>';
      return;
    }
    const rows = data.agents.map(a => {
      const status = a.status || 'unknown';
      const statusCls = status === 'healthy' ? 'ok' : status === 'degraded' ? 'warn' : 'danger';
      const eps = typeof a.eps === 'number' ? a.eps.toFixed(1) : '—';
      const baseline = typeof a.baseline_eps === 'number' ? a.baseline_eps.toFixed(1) : '—';
      const drift = typeof a.drift_pct === 'number' ? `${a.drift_pct.toFixed(0)}%` : '—';
      const driftCls = typeof a.drift_pct === 'number'
        ? (Math.abs(a.drift_pct) >= 60 ? 'danger' : (Math.abs(a.drift_pct) >= 25 ? 'warn' : 'ok'))
        : 'muted';
      return `<tr>
        <td>${escapeHtml(a.agent_id?.slice(0, 8) || '—')}</td>
        <td>${escapeHtml(a.hostname || '—')}</td>
        <td><span class="${statusCls}">${escapeHtml(status)}</span></td>
        <td>${escapeHtml(eps)}</td>
        <td>${escapeHtml(baseline)}</td>
        <td><span class="${driftCls}">${escapeHtml(drift)}</span></td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-250">
      <table class="tbl"><thead><tr><th>Agent</th><th>Hostname</th><th>Status</th><th>EPS</th><th>Baseline</th><th>Drift</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-12">Error loading source health detail.</div>';
  }
}

// ─── IDS Metrics ──────────────────────────────────────────────

async function loadIdsMetrics() {
  const container = document.getElementById('idsMetricsContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading IDS metrics...</div>';
  try {
    const metrics = await apiFetchJson('/api/stats').catch(() => ({}));
    if (!metrics) { container.innerHTML = '<div class="empty-state p-12">No IDS metrics.</div>'; return; }
    const connectedAgents = Number(metrics.connected_agents || 0);
    const agentsCls = connectedAgents > 0 ? 'ok' : 'danger';
    let html = `<div class="miniStatRow mb-10">
      <span class="muted text-12">Total alerts: <strong>${metrics.total_alerts || 0}</strong></span>
      <span class="muted text-12">Events cached: <strong>${metrics.events_cached || 0}</strong></span>
      <span class="muted text-12">Active agents: <strong class="${agentsCls}">${connectedAgents}</strong></span>
    </div>`;
    const sourceHealth = await apiFetchJson('/api/source_health').catch(() => ({}));
    const topSigs = Array.isArray(sourceHealth?.top_signatures) ? sourceHealth.top_signatures : [];
    if (topSigs.length > 0) {
      const sigRows = topSigs.slice(0, 10).map((s) => {
        const name = Array.isArray(s) ? s[0] : (s?.name || s?.source || '—');
        const count = Array.isArray(s) ? s[1] : (s?.count || 0);
        return `<tr><td class="text-12">${escapeHtml(name || '—')}</td><td class="text-12">signature</td><td>${count || 0}</td></tr>`;
      }).join('');
      html += `<div class="tableWrap maxh-250">
        <table class="tbl"><thead><tr><th>Signature</th><th>Type</th><th>Hits</th></tr></thead>
        <tbody>${sigRows}</tbody></table></div>`;
    } else if (metrics.top_sources && Array.isArray(metrics.top_sources)) {
      const sigRows = metrics.top_sources.slice(0, 10).map((s) =>
        `<tr><td class="text-12">${escapeHtml(s.source || s.name || '—')}</td><td class="text-12">${escapeHtml(s.category || 'source')}</td><td>${s.count || 0}</td></tr>`
      ).join('');
      html += `<div class="tableWrap maxh-250">
        <table class="tbl"><thead><tr><th>Source</th><th>Type</th><th>Hits</th></tr></thead>
        <tbody>${sigRows}</tbody></table></div>`;
    }
    container.innerHTML = html;
  } catch {
    container.innerHTML = '<div class="error-state p-12">Error loading IDS metrics.</div>';
  }
}

// ─── SOC MTTR / KPI Metrics ──────────────────────────────────

async function loadSocMttr() {
  const container = document.getElementById('socMttrContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Computing SOC metrics...</div>';
  try {
    const data = await apiFetchJson('/api/metrics/mttr').catch(() => null);
    if (!data) { container.innerHTML = '<div class="empty-state p-12">MTTR data unavailable.</div>'; return; }

    const rdPct = Number(data.resolve_rate_pct || 0).toFixed(1);
    const mttrH = Number(data.mttr_hours || 0);
    const mttrM = Number(data.mttr_minutes || 0);
    const mttrDisplay = mttrH >= 1 ? `${mttrH.toFixed(1)}h` : `${mttrM}m`;
    const bySev = data.by_severity || {};
    const topRules = Array.isArray(data.top_noisy_rules) ? data.top_noisy_rules : [];
    const topAgents = Array.isArray(data.top_alerted_agents) ? data.top_alerted_agents : [];

    const severityBadge = (sev, count) => {
      if (!count) return '';
      const cls = { critical: 'danger', high: 'warn', medium: '', low: 'ok', info: 'label' }[sev] || '';
      return `<span class="badge ${cls}">${escapeHtml(sev)}: ${count}</span>`;
    };

    let html = `<div class="soc-tools-grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:14px;">
      <div class="stat-card"><div class="stat-card-val">${escapeHtml(String(data.total_alerts || 0))}</div><div class="stat-card-label">Total Alerts</div></div>
      <div class="stat-card"><div class="stat-card-val">${escapeHtml(String(data.backlog || 0))}</div><div class="stat-card-label">Open Backlog</div></div>
      <div class="stat-card"><div class="stat-card-val">${escapeHtml(rdPct)}%</div><div class="stat-card-label">Resolve Rate</div></div>
      <div class="stat-card"><div class="stat-card-val">${data.mttr_seconds ? escapeHtml(mttrDisplay) : '—'}</div><div class="stat-card-label">MTTR</div></div>
    </div>`;

    // Severity breakdown
    html += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;">
      ${Object.entries(bySev).map(([s, c]) => severityBadge(s, c)).join('')}
    </div>`;

    if (topRules.length) {
      html += `<h4 style="margin:0 0 6px;font-size:12px;color:var(--fg-muted,#888);text-transform:uppercase;letter-spacing:.5px;">Top Noisy Rules</h4>
      <div class="tableWrap maxh-200 mb-10"><table class="tbl"><thead><tr><th>Rule</th><th>Alerts</th></tr></thead><tbody>
      ${topRules.map(r => `<tr><td class="text-12">${escapeHtml(String(r.rule_name || r.rule_id || '—').substring(0,60))}</td><td>${escapeHtml(String(r.count || 0))}</td></tr>`).join('')}
      </tbody></table></div>`;
    }

    if (topAgents.length) {
      html += `<h4 style="margin:0 0 6px;font-size:12px;color:var(--fg-muted,#888);text-transform:uppercase;letter-spacing:.5px;">Top Alerted Agents</h4>
      <div class="tableWrap maxh-200"><table class="tbl"><thead><tr><th>Host</th><th>Agent ID</th><th>Alerts</th></tr></thead><tbody>
      ${topAgents.map(a => `<tr><td class="text-12">${escapeHtml(String(a.hostname||'—').substring(0,30))}</td><td class="mono text-xs">${escapeHtml(String(a.agent_id||'—').substring(0,20))}</td><td>${escapeHtml(String(a.count||0))}</td></tr>`).join('')}
      </tbody></table></div>`;
    }

    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="error-state p-12">Error loading SOC metrics: ${escapeHtml(e?.message || 'unknown')}</div>`;
  }
}

// ─── UEBA Behavioral Anomaly Analysis ────────────────────────

async function loadUebaAnomalies() {
  const container = document.getElementById('uebaContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Running behavioral analysis...</div>';
  try {
    const data = await apiFetchJson('/api/ueba/anomalies').catch(() => null);
    if (!data) { container.innerHTML = '<div class="empty-state p-12">UEBA data unavailable.</div>'; return; }

    const anomalies = Array.isArray(data.anomalies) ? data.anomalies : [];
    const vol24h = data.alert_volume_24h || 0;
    const critical24h = data.critical_alerts_24h || 0;
    const high24h = data.high_alerts_24h || 0;
    const agentsAnalyzed = data.agents_analyzed || 0;

    let html = `<div class="miniStatRow mb-10">
      <span class="text-12 muted">Analyzed: <strong>${agentsAnalyzed} agents</strong></span>
      <span class="text-12 muted">24h volume: <strong>${vol24h}</strong></span>
      <span class="text-12 muted">Critical/High: <strong class="${critical24h > 0 ? 'danger' : ''}">${critical24h}</strong>/<strong class="${high24h > 0 ? 'warn' : ''}">${high24h}</strong></span>
      <span class="text-12 muted">Anomalies: <strong class="${anomalies.length > 0 ? 'warn' : 'ok'}">${anomalies.length}</strong></span>
    </div>`;

    if (!anomalies.length) {
      html += '<div class="muted p-8 ta-center">✓ No behavioral anomalies detected in the analysis window.</div>';
    } else {
      const sevIcon = (s) => ({ critical: '🔴', high: '🟠', medium: '🟡', info: '🔵' }[s] || '⚪');
      html += '<div class="ueba-anomaly-list">';
      for (const a of anomalies) {
        const sev = String(a.severity || 'medium');
        const cls = { critical: 'danger', high: 'warn', medium: '', info: 'label' }[sev] || '';
        html += `<div class="ueba-anomaly-item ${cls}" style="border-left:3px solid var(--accent-${sev === 'critical' ? 'red' : sev === 'high' ? 'orange' : sev === 'info' ? 'blue' : 'yellow'},#888);padding:8px 10px;margin-bottom:8px;background:var(--surface2,#222);border-radius:0 4px 4px 0;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span>${sevIcon(sev)}</span>
            <strong class="text-13">${escapeHtml(String(a.description || '').substring(0, 120))}</strong>
            <span class="badge ${cls}" style="margin-left:auto;">${escapeHtml(sev)}</span>
          </div>
          <div class="text-12 muted">${escapeHtml(String(a.detail || '').substring(0, 200))}</div>
          ${a.top_category ? `<div class="text-xs muted" style="margin-top:3px;">Category: ${escapeHtml(String(a.top_category))}</div>` : ''}
        </div>`;
      }
      html += '</div>';
    }

    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="error-state p-12">Error loading UEBA: ${escapeHtml(e?.message || 'unknown')}</div>`;
  }
}
