// ═══════════════════════════════════════════════════════════════
//  Detection Coverage — MITRE ATT&CK matrix & effectiveness
// ═══════════════════════════════════════════════════════════════

function initDetectionPane() {
  loadDetectionCoverage();
  loadDetectionEffectiveness();
  const refreshBtn = document.getElementById('detectionRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadDetectionCoverage(); loadDetectionEffectiveness(); });
}

// ─── MITRE ATT&CK Coverage matrix ─────────────────────────────

const MITRE_TACTICS_ORDER = [
  'reconnaissance', 'resource_development', 'initial_access', 'execution',
  'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection', 'command_and_control',
  'exfiltration', 'impact'
];

const MITRE_TACTIC_LABELS = {
  reconnaissance: 'Recon',
  resource_development: 'Resource Dev',
  initial_access: 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  privilege_escalation: 'Priv Esc',
  defense_evasion: 'Defense Evasion',
  credential_access: 'Credential Access',
  discovery: 'Discovery',
  lateral_movement: 'Lateral Movement',
  collection: 'Collection',
  command_and_control: 'C2',
  exfiltration: 'Exfiltration',
  impact: 'Impact'
};

async function loadDetectionCoverage() {
  const container = document.getElementById('detectionCoverageContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading detection coverage…</div>';
  try {
    const data = await apiFetchJson('/api/detection/coverage');
    if (!data || typeof data !== 'object') {
      container.innerHTML = '<div class="empty-state p-24">No coverage data available.</div>';
      return;
    }
    renderMitreMatrix(container, data);
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading detection coverage.</div>';
  }
}

function renderMitreMatrix(container, data) {
  // Convert tactics array to dict if needed
  let tacticsCoverage = data.tactics || data.tactic_coverage || {};
  if (Array.isArray(tacticsCoverage)) {
    // Backend returns array of {tactic, rule_count}, convert to {tactic_name: count}
    tacticsCoverage = {};
    (data.tactics || []).forEach(t => {
      if (t.tactic && typeof t.rule_count === 'number') {
        tacticsCoverage[t.tactic] = t.rule_count;
      }
    });
  }

  const totalRules = data.total_rules || 0;
  const coveredTactics = data.covered_tactics || Object.keys(tacticsCoverage).filter(t => tacticsCoverage[t] > 0).length;

  // Build the ATT&CK-style matrix
  const cols = MITRE_TACTICS_ORDER.map(tactic => {
    const label = MITRE_TACTIC_LABELS[tactic] || tactic;
    const count = tacticsCoverage[tactic] || 0;
    const hasCoverage = count > 0;
    const intensity = Math.min(count / 10, 1); // Scale 0-1 for color
    const bgColor = hasCoverage
      ? `rgba(46, 213, 115, ${0.15 + intensity * 0.45})`
      : 'var(--bg2)';
    const borderColor = hasCoverage ? 'var(--ok, #2ed573)' : 'var(--stroke2)';
    return `<div class="det-matrix-col">
      <div class="det-matrix-col-hd" title="${escapeHtml(tactic)}">${escapeHtml(label)}</div>
      <div class="det-matrix-col-body" style="background:${bgColor};border-color:${borderColor};">
        <div class="det-matrix-col-value" style="color:${hasCoverage ? 'var(--ok, #2ed573)' : 'var(--muted)'};">${count}</div>
        <div class="det-matrix-col-label">rule${count !== 1 ? 's' : ''}</div>
      </div>
    </div>`;
  }).join('');

  // Compute overall score
  const covPct = MITRE_TACTICS_ORDER.length > 0 ? Math.round((coveredTactics / MITRE_TACTICS_ORDER.length) * 100) : 0;

  container.innerHTML = `
    <div class="det-kpi-row">
      <div class="det-kpi-tile">
        <div class="det-kpi-value det-kpi-accent">${covPct}%</div>
        <div class="muted det-kpi-label">Tactic Coverage</div>
      </div>
      <div class="det-kpi-tile">
        <div class="det-kpi-value">${coveredTactics}<span class="muted det-kpi-subvalue">/${MITRE_TACTICS_ORDER.length}</span></div>
        <div class="muted det-kpi-label">Tactics Covered</div>
      </div>
      <div class="det-kpi-tile">
        <div class="det-kpi-value">${totalRules}</div>
        <div class="muted det-kpi-label">Total Rules</div>
      </div>
    </div>
    <div class="det-matrix-row">${cols}</div>
    <div class="muted det-matrix-hint">Based on MITRE ATT&CK Enterprise framework. Darker shading indicates higher rule density.</div>`;
}


// ─── Detection Effectiveness ─────────────────────────────────

async function loadDetectionEffectiveness() {
  const container = document.getElementById('detectionEffContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading detection effectiveness…</div>';
  try {
    const data = await apiFetchJson('/api/detection/effectiveness');
    if (!data || typeof data !== 'object') {
      container.innerHTML = '<div class="empty-state p-24">No effectiveness data yet.</div>';
      return;
    }
    renderEffectiveness(container, data);
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading effectiveness data.</div>';
  }
}

function renderEffectiveness(container, data) {
  const totalAlerts = data.total_alerts || 0;
  const truePositive = data.true_positives || 0;
  const falsePositive = data.false_positives || 0;
  const suppressions = data.suppressions || 0;
  const avgConfidence = data.avg_confidence || 0;

  const tpRate = totalAlerts > 0 ? Math.round((truePositive / totalAlerts) * 100) : 0;
  const fpRate = totalAlerts > 0 ? Math.round((falsePositive / totalAlerts) * 100) : 0;

  // Top rules that fire
  const topRules = Array.isArray(data.top_firing_rules) ? data.top_firing_rules : [];
  const topRulesHtml = topRules.length > 0
    ? topRules.slice(0, 10).map(r => {
        const name = r.rule_id || r.name || '—';
        const count = r.count || r.fires || 0;
        const fp = r.false_positive_rate || '—';
        return `<tr>
          <td class="text-12">${escapeHtml(name)}</td>
          <td class="text-12 ta-right">${count}</td>
          <td class="text-12 ta-right">${escapeHtml(String(fp))}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="3" class="muted ta-center text-12">No rule firing data yet.</td></tr>';

  container.innerHTML = `
    <div class="det-kpi-row det-kpi-row-eff">
      <div class="det-kpi-tile det-kpi-tile-min">
        <div class="det-kpi-value det-kpi-value-sm">${totalAlerts}</div>
        <div class="muted det-kpi-label">Total Alerts</div>
      </div>
      <div class="det-kpi-tile det-kpi-tile-min">
        <div class="det-kpi-value det-kpi-value-sm text-ok">${tpRate}%</div>
        <div class="muted det-kpi-label">True Positive Rate</div>
      </div>
      <div class="det-kpi-tile det-kpi-tile-min">
        <div class="det-kpi-value det-kpi-value-sm text-danger">${fpRate}%</div>
        <div class="muted det-kpi-label">False Positive Rate</div>
      </div>
      <div class="det-kpi-tile det-kpi-tile-min">
        <div class="det-kpi-value det-kpi-value-sm">${suppressions}</div>
        <div class="muted det-kpi-label">Suppressions</div>
      </div>
      <div class="det-kpi-tile det-kpi-tile-min">
        <div class="det-kpi-value det-kpi-value-sm">${typeof avgConfidence === 'number' ? (avgConfidence * 100).toFixed(0) + '%' : '—'}</div>
        <div class="muted det-kpi-label">Avg Confidence</div>
      </div>
    </div>
    <div class="tableWrap maxh-300">
      <table class="tbl"><thead><tr><th>Rule</th><th class="ta-right">Fires</th><th class="ta-right">FP Rate</th></tr></thead>
      <tbody>${topRulesHtml}</tbody></table>
    </div>`;
}
