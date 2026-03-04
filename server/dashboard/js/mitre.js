// ═══════════════════════════════════════════════════════════════
//  MITRE ATT&CK Navigator — Interactive matrix + export
// ═══════════════════════════════════════════════════════════════

function initMitrePane() {
  loadMitreNavigator();
  loadMitreDataSources();
  const refreshBtn = document.getElementById('mitreRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadMitreNavigator(); loadMitreDataSources(); });
  const exportBtn = document.getElementById('mitreExportBtn');
  if (exportBtn) exportBtn.addEventListener('click', exportNavigatorJson);
}

let _navigatorData = null;

async function loadMitreNavigator() {
  const container = document.getElementById('mitreNavigatorContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading MITRE navigator…</div>';
  try {
    const data = await apiFetchJson('/api/mitre/navigator').catch(() => apiFetchJson('/api/detection/coverage'));
    _navigatorData = data;
    const techniques = Array.isArray(data?.techniques)
      ? data.techniques
      : (Array.isArray(data?.coverage) ? data.coverage : []);
    if (!data || techniques.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No technique coverage data available.</div>';
      return;
    }
    // Build matrix grid by tactic
    const tacticOrder = [
      'reconnaissance','resource-development','initial-access','execution',
      'persistence','privilege-escalation','defense-evasion','credential-access',
      'discovery','lateral-movement','collection','command-and-control',
      'exfiltration','impact'
    ];
    const tacticLabels = {
      'reconnaissance':'Recon','resource-development':'Resource Dev','initial-access':'Initial Access',
      'execution':'Execution','persistence':'Persistence','privilege-escalation':'Priv Esc',
      'defense-evasion':'Defense Evasion','credential-access':'Cred Access','discovery':'Discovery',
      'lateral-movement':'Lateral Mvmt','collection':'Collection','command-and-control':'C2',
      'exfiltration':'Exfiltration','impact':'Impact'
    };
    // Group techniques by tactic
    const byTactic = {};
    techniques.forEach(t => {
      const tacs = t.tactic ? [t.tactic] : (t.tactics || []);
      tacs.forEach(tac => {
        const key = tac.toLowerCase().replace(/[_ ]/g, '-');
        if (!byTactic[key]) byTactic[key] = [];
        byTactic[key].push(t);
      });
    });

    // Stats — separate active (alert-correlated) from coverage-only
    const total = techniques.length;
    const active = techniques.filter(t => t.active || (Number(t.alert_count_24h || 0) > 0)).length;
    const covered = techniques.filter(t => Number(t.score || t.coverage_score || 0) > 0 || t.rule_ids?.length > 0).length;
    const activeAlerts = (data?.meta?.total_alerts_24h) || 0;
    const pct = total ? Math.round((covered / total) * 100) : 0;

    const statsHtml = `<div class="miniStatRow mitre-stats-row">
      <span class="muted mitre-stat">Techniques tracked: <strong>${total}</strong></span>
      <span class="mitre-stat" style="color:var(--danger)">● Active detections: <strong>${active}</strong></span>
      <span class="muted mitre-stat mitre-covered">◎ Coverage: <strong>${covered}</strong></span>
      <span class="muted mitre-stat">Coverage %: <strong>${pct}%</strong></span>
      ${activeAlerts > 0 ? `<span class="mitre-stat" style="color:var(--warn)">Alerts (24h): <strong>${activeAlerts}</strong></span>` : ''}
    </div>
    <div class="mitre-legend">
      <span class="mitre-legend-item"><span class="mitre-dot" style="background:var(--danger)"></span>Critical/High active</span>
      <span class="mitre-legend-item"><span class="mitre-dot" style="background:var(--warn)"></span>Medium active</span>
      <span class="mitre-legend-item"><span class="mitre-dot" style="background:var(--accent)"></span>Low active</span>
      <span class="mitre-legend-item"><span class="mitre-dot" style="background:rgba(90,110,160,0.35)"></span>Coverage only</span>
    </div>`;

    // Render matrix columns — active techniques are prominently colored, coverage-only are subdued
    let colsHtml = '';
    for (const tac of tacticOrder) {
      const techs = byTactic[tac] || [];
      const label = tacticLabels[tac] || tac;
      const activeCount = techs.filter(t => t.active || Number(t.alert_count_24h || 0) > 0).length;
      const cells = techs.sort((a, b) => (b.score || 0) - (a.score || 0)).map(t => {
        const isActive = t.active || Number(t.alert_count_24h || 0) > 0;
        const sev = t.severity || 'none';
        const alerts24h = Number(t.alert_count_24h || 0);
        const tid = (t.techniqueID || t.technique_id || '').replace('attack.', '').replace('ATTACK.', '');
        const tname = t.name || '';
        const lastSeen = t.last_seen ? new Date(t.last_seen).toLocaleString() : '';

        let bg, fg, border;
        if (isActive) {
          if (sev === 'critical' || sev === 'high') {
            bg = 'rgba(201, 78, 90, 0.75)'; fg = '#fff'; border = '1px solid rgba(201,78,90,0.9)';
          } else if (sev === 'medium') {
            bg = 'rgba(212, 156, 60, 0.72)'; fg = '#fff'; border = '1px solid rgba(212,156,60,0.9)';
          } else {
            bg = 'rgba(59, 156, 194, 0.7)'; fg = '#fff'; border = '1px solid rgba(59,156,194,0.9)';
          }
        } else {
          bg = 'rgba(90, 110, 160, 0.18)'; fg = 'var(--muted)'; border = '1px solid rgba(120,140,190,0.2)';
        }

        const pulseClass = (isActive && (sev === 'critical' || sev === 'high')) ? ' class="mitre-cell mitre-cell-active"' : ' class="mitre-cell"';
        const tooltip = [
          tname || '—',
          `ID: ${tid}`,
          isActive ? `Alerts (24h): ${alerts24h}` : 'Coverage only',
          isActive ? `Severity: ${sev}` : '',
          lastSeen ? `Last seen: ${lastSeen}` : '',
        ].filter(Boolean).join('\n');

        return `<div${pulseClass} style="background:${bg};color:${fg};border:${border};" title="${escapeHtml(tooltip)}">${escapeHtml(tid)}</div>`;
      }).join('');

      const hd = activeCount > 0
        ? `${escapeHtml(label)}<span class="chip mitre-chip-tiny" style="background:rgba(201,78,90,0.2);color:var(--danger)">${activeCount} active</span>`
        : `${escapeHtml(label)}<span class="chip muted mitre-chip-tiny">${techs.length}</span>`;

      colsHtml += `<div class="mitre-col">
        <div class="mitre-col-hd">${hd}</div>
        <div class="mitre-col-cells">${cells || '<div class="muted mitre-cell-empty">—</div>'}</div>
      </div>`;
    }

    container.innerHTML = statsHtml + `<div class="mitre-matrix">${colsHtml}</div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading MITRE Navigator data.</div>';
  }
}

async function loadMitreDataSources() {
  const container = document.getElementById('mitreDataSourcesContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading MITRE data sources…</div>';
  try {
    const sources = await apiFetchJson('/api/mitre/data_sources').catch(() => apiFetchJson('/api/detection/effectiveness'));
    if (!sources || (!Array.isArray(sources) && !sources.data_sources)) {
      container.innerHTML = '<div class="empty-state p-12">No data source mapping available.</div>';
      return;
    }
    const list = Array.isArray(sources) ? sources : (sources.data_sources || []);
    if (list.length === 0) {
      container.innerHTML = '<div class="empty-state p-12">No data source mappings.</div>';
      return;
    }
    const rows = list.map(ds => {
      const covCls = ds.coverage === 'full' ? 'ok' : ds.coverage === 'partial' ? 'warn' : 'danger';
      return `<tr>
        <td>${escapeHtml(ds.name || '—')}</td>
        <td><span class="${covCls}">${escapeHtml(ds.coverage || 'none')}</span></td>
        <td class="text-12">${escapeHtml(ds.techniques_enabled || ds.technique_count || 0)}</td>
        <td class="text-12">${escapeHtml(ds.source || '—')}</td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-250">
      <table class="tbl"><thead><tr><th>Data Source</th><th>Coverage</th><th>Techniques</th><th>Log Source</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-12">Error loading data sources.</div>';
  }
}

function exportNavigatorJson() {
  if (!_navigatorData) { showToast('No navigator data to export', 'error'); return; }
  const blob = new Blob([JSON.stringify(_navigatorData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'percepta_attack_navigator.json';
  a.click();
  URL.revokeObjectURL(url);
  showToast('Navigator JSON exported', 'ok');
}
