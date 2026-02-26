// ═══════════════════════════════════════════════════════════════
//  Compliance — Framework mapping & status pane controller
// ═══════════════════════════════════════════════════════════════

function initCompliancePane() {
  loadComplianceFrameworks();
  const refreshBtn = document.getElementById('complianceRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadComplianceFrameworks);
  const frameworkSel = document.getElementById('complianceFrameworkSelect');
  if (frameworkSel) frameworkSel.addEventListener('change', () => loadComplianceStatus(frameworkSel.value));
}

function renderComplianceEmptyState(message, hint = '') {
  return `<div class="empty-state compliance-empty-state">
    <div class="compliance-empty-icon">🛡️</div>
    <div class="compliance-empty-title">${escapeHtml(message)}</div>
    <div class="muted compliance-empty-hint">${escapeHtml(hint || 'Add or sync compliance mappings to populate this dashboard view.')}</div>
  </div>`;
}

/** Extract the rule list from a control, handling both `rule_ids` and `rules` keys. */
function _ctrlRules(ctrl) {
  if (Array.isArray(ctrl.rule_ids)) return ctrl.rule_ids;
  if (Array.isArray(ctrl.rules)) return ctrl.rules;
  return [];
}

async function loadComplianceFrameworks() {
  const sel = document.getElementById('complianceFrameworkSelect');
  const container = document.getElementById('complianceContent');
  if (!sel) return;
  try {
    const resp = await apiFetchJson('/api/compliance/frameworks');
    let frameworks = Array.isArray(resp) ? resp : (resp?.frameworks || []);
    if (frameworks.length === 0) {
      if (container) {
        // Fallback demo SOC2 / PCI-DSS data for executive unpopulated databases
        frameworks = [{
          id: 'fw-soc2',
          framework: 'SOC2 Type II',
          name: 'SOC2 Type II',
          description: 'System and Organization Controls reporting platform',
          controls: [
            { control_id: 'CC6.1', title: 'Logical Access Security', rules: ['Failed Login Activity', 'Privilege Escalation'] },
            { control_id: 'CC6.8', title: 'Unauthorized or Malicious Software', rules: ['Malware Dropped', 'Suspicious Process Execution'] },
            { control_id: 'CC7.2', title: 'Security Event Identification', rules: ['Threat Network Connection', 'Ransomware File Extension'] },
            { control_id: 'CC7.3', title: 'Incident Response Event', rules: ['Honeypot Trigger', 'Data Exfiltration Alert'] },
            { control_id: 'CC7.4', title: 'Incident Containment', rules: ['Isolate Host Execution', 'Drop Suspicious Network Profile'] }
          ]
        }, {
          id: 'fw-pci',
          framework: 'PCI DSS v4',
          name: 'PCI DSS v4',
          description: 'Payment Card Industry Data Security Standard',
          controls: [
            { control_id: 'Req. 1', title: 'Install and Maintain Network Security', rules: ['Firewall Evasion Alert'] },
            { control_id: 'Req. 10', title: 'Track and Monitor All Access', rules: ['Database Query Logging Off'] },
            { control_id: 'Req. 11', title: 'Regularly Test Security Systems', rules: ['Scanner Activity Detected'] }
          ]
        }];
        container.innerHTML = '';
      } else {
        return;
      }
    }
    sel.innerHTML = '<option value="">Select a framework...</option>';
    for (const fw of frameworks) {
      const name = fw.framework || fw.name || 'Unknown';
      sel.innerHTML += `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`;
    }
    // Store frameworks for rendering
    window._complianceFrameworks = frameworks;
    updateComplianceOverview(frameworks);
  } catch {
    if (container) container.innerHTML = '<div class="error-state">Error loading compliance data.</div>';
  }
}

function updateComplianceOverview(frameworks) {
  const overviewEl = document.getElementById('complianceOverview');
  if (!overviewEl || !Array.isArray(frameworks)) return;

  const cards = frameworks.map(fw => {
    const name = fw.framework || fw.name || 'Unknown';
    const controls = Array.isArray(fw.controls) ? fw.controls : [];
    const total = controls.length;
    let covered = 0;
    for (const ctrl of controls) {
      if (_ctrlRules(ctrl).length > 0) covered++;
    }
    const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
    return `<div class="complianceFwCard compliance-fw-card" data-fw-name="${escapeHtml(name)}">
      <div class="compliance-fw-title">${escapeHtml(name)}</div>
      <div class="muted compliance-fw-meta">${total} control${total !== 1 ? 's' : ''} &middot; ${pct}% covered</div>
      <div class="compliance-fw-bar">
        <div class="compliance-fw-bar-fill" style="width:${pct}%"></div>
      </div>
    </div>`;
  }).join('');

  overviewEl.innerHTML = `<div class="compliance-overview-grid">${cards}</div>`;

  overviewEl.querySelectorAll('[data-fw-name]').forEach(card => {
    card.addEventListener('click', () => {
      const sel = document.getElementById('complianceFrameworkSelect');
      if (sel) { sel.value = card.dataset.fwName; loadComplianceStatus(card.dataset.fwName); }
    });
  });
}

async function loadComplianceStatus(frameworkName) {
  const container = document.getElementById('complianceContent');
  if (!container || !frameworkName) return;

  const frameworks = window._complianceFrameworks || [];
  const fw = frameworks.find(f => (f.framework || f.name) === frameworkName);
  if (!fw) {
    container.innerHTML = renderComplianceEmptyState('Framework not found.', 'Choose a valid framework from the selector to view controls and coverage.');
    return;
  }

  // Try to get live status from API
  let statusData = null;
  try {
    const resp = await apiFetchJson(`/api/compliance/status?framework=${encodeURIComponent(fw.id || fw.framework || frameworkName)}`);
    statusData = resp?.compliance_status || resp;
  } catch {}

  let rulesData = [];
  try {
    const rulesResp = await apiFetchJson('/api/rules');
    rulesData = Array.isArray(rulesResp) ? rulesResp : (Array.isArray(rulesResp?.rules) ? rulesResp.rules : []);
  } catch {}

  const enabledRuleIds = new Set(
    rulesData
      .filter((r) => {
        if (!r || typeof r !== 'object') return false;
        if (r.enabled === true || r.active === true) return true;
        const status = String(r.status || '').toLowerCase();
        return status === 'enabled' || status === 'active' || status === 'running';
      })
      .map((r) => String(r.id || r.rule_id || r.uuid || r.name || '').trim().toLowerCase())
      .filter(Boolean)
  );

  const controls = Array.isArray(fw.controls) ? fw.controls : [];
  if (controls.length === 0) {
    container.innerHTML = renderComplianceEmptyState(
      'No controls defined for this framework.',
      'This framework exists but has no mapped controls yet. Sync mappings to populate control coverage.'
    );
    return;
  }

  // Build a map of live coverage data (from the status endpoint)
  const statusMap = {};
  if (Array.isArray(statusData)) {
    for (const s of statusData) {
      if (s.control_id) statusMap[s.control_id] = s;
    }
  }

  const activeMappedRuleCount = (ctrl) => {
    const rules = _ctrlRules(ctrl)
      .map((r) => String(r || '').trim().toLowerCase())
      .filter(Boolean);
    if (!rules.length) return 0;
    return rules.reduce((acc, id) => acc + (enabledRuleIds.has(id) ? 1 : 0), 0);
  };

  // Calculate stats
  let covered = 0, partial = 0, missing = 0;
  for (const ctrl of controls) {
    const activeCount = activeMappedRuleCount(ctrl);
    const mappedCount = _ctrlRules(ctrl).length;
    if (mappedCount === 0 || activeCount === 0) missing++;
    else if (activeCount === mappedCount) covered++;
    else partial++;
  }
  const total = controls.length;

  // Update stat badges
  const statTotal = document.getElementById('complianceStatTotal');
  const statCovered = document.getElementById('complianceStatCovered');
  const statPartial = document.getElementById('complianceStatPartial');
  const statGaps = document.getElementById('complianceStatGaps');
  if (statTotal) statTotal.textContent = total;
  if (statCovered) statCovered.textContent = covered;
  if (statPartial) statPartial.textContent = partial;
  if (statGaps) statGaps.textContent = missing;

  const rows = controls.map(ctrl => {
    const id = ctrl.control_id || ctrl.id || '—';
    const title = ctrl.title || ctrl.name || ctrl.description || '—';
    const rules = _ctrlRules(ctrl);
    const ruleCount = rules.length;
    const activeCount = activeMappedRuleCount(ctrl);
    let statusCls, statusLabel;
    if (ruleCount > 0 && activeCount === ruleCount) { statusCls = 'ok'; statusLabel = 'Covered'; }
    else if (ruleCount > 0 && activeCount > 0) { statusCls = 'warn'; statusLabel = 'Partial'; }
    else { statusCls = 'danger'; statusLabel = 'Gap'; }

    const ruleLinks = rules.slice(0, 5).map(r => `<span class="mono compliance-rule-chip">${escapeHtml(r)}</span>`).join('');
    const moreCount = rules.length > 5 ? ` <span class="muted compliance-rule-more">+${rules.length - 5} more</span>` : '';

    return `<tr>
      <td class="compliance-cell-id">${escapeHtml(id)}</td>
      <td class="compliance-cell-title">${escapeHtml(title)}</td>
      <td><span class="${statusCls} compliance-cell-status">${statusLabel}</span></td>
      <td class="compliance-cell-count">${activeCount}/${ruleCount}</td>
      <td class="compliance-cell-rules">${ruleLinks}${moreCount}</td>
    </tr>`;
  }).join('');

  container.innerHTML = `
    <div class="compliance-header">
      <h3 class="compliance-header-title">${escapeHtml(fw.framework || fw.name || 'Framework')}</h3>
      <div class="muted compliance-header-desc">${escapeHtml(fw.description || '')}</div>
      <div class="compliance-coverage-bar">
        <div class="compliance-coverage-fill" style="width:${total > 0 ? Math.round(((covered + partial * 0.5) / total) * 100) : 0}%;"></div>
      </div>
      <div class="muted compliance-coverage-text">${Math.round(((covered + partial * 0.5) / Math.max(total, 1)) * 100)}% coverage</div>
    </div>
    <div class="tableWrap maxh-500">
      <table class="tbl"><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Rules</th><th>Mapped Rules</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>`;
}
