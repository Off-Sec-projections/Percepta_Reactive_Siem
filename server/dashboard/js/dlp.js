// ═══════════════════════════════════════════════════════════════
//  DLP — Data Loss Prevention pane controller
// ═══════════════════════════════════════════════════════════════

function initDlpPane() {
  loadDlpStats();
  loadDlpPatterns();
  loadDlpViolations();
  const refreshBtn = document.getElementById('dlpRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadDlpStats(); loadDlpPatterns(); loadDlpViolations(); });
}

async function loadDlpStats() {
  try {
    const stats = await apiFetchJson('/api/dlp/stats');
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el('dlpStatPatterns', stats.total_patterns || 0);
    el('dlpStatCategories', stats.categories || 0);
    el('dlpStatViolations', stats.total_violations || 0);
    el('dlpStatRecent', stats.recent_24h || 0);
  } catch { /* ignore */ }
}

async function loadDlpPatterns() {
  const container = document.getElementById('dlpPatternsContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading DLP patterns…</div>';
  try {
    const patterns = await apiFetchJson('/api/dlp/patterns');
    if (!Array.isArray(patterns) || patterns.length === 0) {
      container.innerHTML = '<div class="empty-state p-12">No DLP patterns configured.</div>';
      return;
    }
    // Group by category
    const byCategory = {};
    patterns.forEach(p => {
      const cat = p.category || 'other';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(p);
    });
    let html = '';
    for (const [cat, pats] of Object.entries(byCategory)) {
      const pills = pats.map(p => {
        const sevCls = p.severity === 'critical' ? 'danger' : p.severity === 'high' ? 'warn' : 'muted';
        return `<span class="chip ${sevCls}" title="${escapeHtml(p.description || '')}">${escapeHtml(p.name || p.id)}</span>`;
      }).join(' ');
      html += `<div class="dlp-cat-block"><strong class="dlp-cat-title">${escapeHtml(cat)}</strong><div class="dlp-cat-pills">${pills}</div></div>`;
    }
    container.innerHTML = html;
  } catch {
    container.innerHTML = '<div class="error-state p-12">Error loading patterns.</div>';
  }
}

async function loadDlpViolations() {
  const container = document.getElementById('dlpViolationsContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-12">Loading DLP violations…</div>';
  try {
    const violations = await apiFetchJson('/api/dlp/violations');
    if (!Array.isArray(violations) || violations.length === 0) {
      container.innerHTML = '<div class="empty-state p-12">No DLP violations detected.</div>';
      return;
    }
    const rows = violations.slice(0, 100).map(v => {
      const sevCls = v.severity === 'critical' ? 'danger' : v.severity === 'high' ? 'warn' : 'muted';
      const ts = v.timestamp ? new Date(v.timestamp).toLocaleString() : '—';
      return `<tr>
        <td class="text-12">${escapeHtml(ts)}</td>
        <td><span class="${sevCls}">${escapeHtml(v.pattern_name || v.category || '—')}</span></td>
        <td>${escapeHtml(v.category || '—')}</td>
        <td class="text-12">${escapeHtml(v.source || v.agent_id || '—')}</td>
        <td class="text-12 mono">${escapeHtml(v.masked_match || '—')}</td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-400">
      <table class="tbl"><thead><tr><th>Time</th><th>Pattern</th><th>Category</th><th>Source</th><th>Masked Match</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-12">Error loading violations.</div>';
  }
}
