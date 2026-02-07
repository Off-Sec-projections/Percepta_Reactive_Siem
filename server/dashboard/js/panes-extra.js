// ═══════════════════════════════════════════════════════════════
//  Playbooks, Reactive Response, and Audit Log pane controllers
// ═══════════════════════════════════════════════════════════════

// ─── Playbooks / SOAR ────────────────────────────────────────

function initPlaybooksPane() {
  loadPlaybooks();
  loadPlaybookRuns();
  loadPlaybookLiveStatus();

  const newBtn = document.getElementById('pbNewBtn');
  if (newBtn) newBtn.addEventListener('click', () => showPlaybookEditor(null));
  const refreshBtn = document.getElementById('pbRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadPlaybooks(); loadPlaybookRuns(); loadPlaybookLiveStatus(); });
  const liveToggle = document.getElementById('pbLiveToggle');
  if (liveToggle) liveToggle.addEventListener('change', togglePlaybookLive);
}

async function loadPlaybookLiveStatus() {
  const toggle = document.getElementById('pbLiveToggle');
  const label = document.getElementById('pbLiveLabel');
  if (!toggle) return;
  try {
    const resp = await apiFetchJson('/api/playbooks/live');
    toggle.checked = resp.live === true;
    if (label) label.textContent = resp.live ? 'LIVE' : 'Dry-run';
    if (label) label.style.color = resp.live ? 'var(--danger, #ff4757)' : 'var(--muted)';
  } catch { /* ignore */ }
}

async function togglePlaybookLive() {
  const toggle = document.getElementById('pbLiveToggle');
  const label = document.getElementById('pbLiveLabel');
  if (!toggle) return;
  const live = toggle.checked;
  if (live) {
    const ok = await uiConfirm('Enable LIVE mode? Playbooks will execute real actions (block IPs, disable users, etc).');
    if (!ok) { toggle.checked = false; return; }
  }
  try {
    const resp = await apiPostJson('/api/playbooks/live', { live });
    if (label) label.textContent = resp.live ? 'LIVE' : 'Dry-run';
    if (label) label.style.color = resp.live ? 'var(--danger, #ff4757)' : 'var(--muted)';
    showToast(resp.live ? 'Playbooks set to LIVE mode' : 'Playbooks set to dry-run mode', resp.live ? 'warn' : 'info');
  } catch {
    toggle.checked = !live;
    showToast('Failed to toggle live mode', 'error');
  }
}

async function loadPlaybooks() {
  const container = document.getElementById('pbContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading playbooks…</div>';
  try {
    const resp = await apiFetchJson('/api/playbooks');
    const playbooks = Array.isArray(resp) ? resp : (resp?.items || []);
    if (playbooks.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No playbooks defined. Click <b>+ New Playbook</b> to create one.</div>';
      return;
    }
    const rows = playbooks.map(pb => {
      const enabled = pb.enabled !== false;
      const statusCls = enabled ? 'ok' : 'muted';
      const statusTxt = enabled ? 'Enabled' : 'Disabled';
      // Handle both legacy trigger_conditions and new trigger object
      let triggers = '—';
      if (pb.trigger_conditions) {
        triggers = pb.trigger_conditions.map(t => escapeHtml(t.field + ' ' + t.operator + ' ' + t.value)).join(', ');
      } else if (pb.trigger) {
        const parts = [];
        if (pb.trigger.rule_ids?.length) parts.push(`Rules: ${pb.trigger.rule_ids.length}`);
        if (pb.trigger.severities?.length) parts.push(`Severities: ${pb.trigger.severities.join('/')}`);
        if (pb.trigger.categories?.length) parts.push(`Categories: ${pb.trigger.categories.join('/')}`);
        triggers = parts.join(', ') || '—';
      }
      const actions = (pb.actions || []).map(a => escapeHtml(a.action_type || a.type || '?')).join(', ') || '—';
      return `<tr>
        <td><strong>${escapeHtml(pb.name || pb.id || '?')}</strong></td>
        <td><span class="${statusCls}">${statusTxt}</span></td>
        <td class="text-12">${triggers}</td>
        <td class="text-12">${actions}</td>
        <td>
          <button class="btnSm" data-pb-edit="${escapeHtml(pb.id || '')}">Edit</button>
          <button class="btnSm danger" data-pb-del="${escapeHtml(pb.id || '')}">Delete</button>
        </td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-400">
      <table class="tbl"><thead><tr><th>Name</th><th>Status</th><th>Triggers</th><th>Actions</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
    // Attach edit/delete handlers
    container.querySelectorAll('[data-pb-edit]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.pbEdit;
        const pb = playbooks.find(p => p.id === id);
        if (pb) showPlaybookEditor(pb);
      });
    });
    container.querySelectorAll('[data-pb-del]').forEach(btn => {
      btn.addEventListener('click', () => deletePlaybook(btn.dataset.pbDel));
    });
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading playbooks.</div>';
  }
}

async function loadPlaybookRuns() {
  const container = document.getElementById('pbRunsContent');
  if (!container) return;
  try {
    const resp = await apiFetchJson('/api/playbooks/runs');
    const runs = Array.isArray(resp) ? resp : (resp?.items || []);
    if (runs.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No playbook runs recorded yet.</div>';
      return;
    }
    const rows = runs.slice(0, 50).map(r => {
      // Handle both ts_unix (ms) and started_at field names
      const ts_ms = r.ts_unix || (r.started_at ? r.started_at * 1000 : null);
      const ts = ts_ms ? new Date(ts_ms).toLocaleString() : '—';
      const statusCls = r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'danger' : 'warn';
      return `<tr>
        <td class="text-12">${escapeHtml(ts)}</td>
        <td>${escapeHtml(r.playbook_name || r.playbook_id || '?')}</td>
        <td><span class="${statusCls}">${escapeHtml(r.status || '?')}</span></td>
        <td class="text-12">${escapeHtml(r.alert_id || '—')}</td>
        <td class="text-12">${escapeHtml(r.error || '—')}</td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-300">
      <table class="tbl"><thead><tr><th>Time</th><th>Playbook</th><th>Status</th><th>Alert</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading runs.</div>';
  }
}

async function showPlaybookEditor(existing) {
  const isNew = !existing;

  // Convert backend trigger format to UI format for editing
  let uiTrigger = { rule_ids: [], severities: [], categories: [], sensor_kinds: [] };
  if (existing?.trigger) {
    uiTrigger = existing.trigger;
  } else if (existing?.trigger_conditions) {
    // Backward compatibility: convert legacy format
    uiTrigger.rule_ids = existing.trigger_conditions.map(tc => `rule:${tc.field}`);
  }

  const pb = existing || { name: '', enabled: true, trigger: uiTrigger, actions: [] };

  // Build a form overlay
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  const panel = document.createElement('div');
  panel.className = 'modal-content modal-content-md';
  panel.innerHTML = `
    <h3 class="pane-dialog-title">${isNew ? 'Create' : 'Edit'} Playbook</h3>
    <div class="form-stack">
      <div><label class="muted pane-field-label">Name</label>
        <input id="pbEdName" class="field field-full" value="${escapeHtml(pb.name || '')}"></div>
      <div><label class="pane-check-label"><input type="checkbox" id="pbEdEnabled" ${pb.enabled !== false ? 'checked' : ''}> Enabled</label></div>

      <div><label class="muted pane-field-label">Trigger Rules (JSON array of rule IDs)</label>
        <textarea id="pbEdRuleIds" class="field json-textarea" placeholder='["rule_id_1", "rule_id_2"]'>${escapeHtml(JSON.stringify(pb.trigger?.rule_ids || [], null, 2))}</textarea></div>

      <div><label class="muted pane-field-label">Trigger Severities (JSON array, e.g. ["critical", "high"])</label>
        <textarea id="pbEdSeverities" class="field json-textarea" placeholder='["critical"]'>${escapeHtml(JSON.stringify(pb.trigger?.severities || [], null, 2))}</textarea></div>

      <div><label class="muted pane-field-label">Actions (JSON array)</label>
        <textarea id="pbEdActions" class="field json-textarea" placeholder='[{"action_type":"block_ip","target":"${event.dst_ip}","ttl_seconds":3600}]'>${escapeHtml(JSON.stringify(pb.actions || [], null, 2))}</textarea></div>

      <div class="actions-end mt-8">
        <button class="btn" id="pbEdCancel">Cancel</button>
        <button class="btn primary" id="pbEdSave">${isNew ? 'Create' : 'Save'}</button>
      </div>
    </div>`;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  return new Promise(resolve => {
    const cleanup = () => { try { overlay.remove(); } catch {} resolve(); };
    overlay.addEventListener('click', e => { if (e.target === overlay) cleanup(); });
    panel.querySelector('#pbEdCancel').addEventListener('click', cleanup);
    panel.querySelector('#pbEdSave').addEventListener('click', async () => {
      let rule_ids, severities, categories, sensor_kinds, actions;
      try { rule_ids = JSON.parse(document.getElementById('pbEdRuleIds').value || '[]'); }
      catch { showToast('Invalid JSON for rule IDs', { kind: 'error' }); return; }
      try { severities = JSON.parse(document.getElementById('pbEdSeverities').value || '[]'); }
      catch { showToast('Invalid JSON for severities', { kind: 'error' }); return; }
      try { actions = JSON.parse(document.getElementById('pbEdActions').value || '[]'); }
      catch { showToast('Invalid JSON for actions', { kind: 'error' }); return; }

      const body = {
        id: pb.id,
        name: document.getElementById('pbEdName').value.trim(),
        enabled: document.getElementById('pbEdEnabled').checked,
        trigger: {
          rule_ids: Array.isArray(rule_ids) ? rule_ids : [],
          severities: Array.isArray(severities) ? severities : [],
          categories: [],
          sensor_kinds: [],
        },
        actions: Array.isArray(actions) ? actions : [],
      };

      if (!body.name) {
        showToast('Playbook name is required', { kind: 'error' });
        return;
      }

      try {
        await apiPostJson('/api/playbooks/upsert', body);
        showToast(isNew ? 'Playbook created' : 'Playbook saved', { kind: 'ok' });
        loadPlaybooks();
      } catch (e) {
        showToast('Failed to save playbook: ' + (e.message || 'unknown error'), { kind: 'error' });
      }
      cleanup();
    });
  });
}

async function deletePlaybook(id) {
  if (!id) return;
  const ok = await uiConfirm('Are you sure you want to delete this playbook? This cannot be undone.', { danger: true });
  if (!ok) return;
  try {
    await apiPostJson('/api/playbooks/delete', { id });
    showToast('Playbook deleted', { kind: 'ok' });
    loadPlaybooks();
  } catch {
    showToast('Failed to delete playbook', { kind: 'error' });
  }
}


// ─── Reactive Response ───────────────────────────────────────

function initResponsePane() {
  loadActiveBlocks();

  const blockIpBtn = document.getElementById('respBlockIpBtn');
  if (blockIpBtn) blockIpBtn.addEventListener('click', promptBlockIp);
  const blockUserBtn = document.getElementById('respBlockUserBtn');
  if (blockUserBtn) blockUserBtn.addEventListener('click', promptBlockUser);
  const refreshBtn = document.getElementById('respRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadActiveBlocks);
  const dispatchBtn = document.getElementById('respDispatchBtn');
  if (dispatchBtn) dispatchBtn.addEventListener('click', dispatchCommand);
}

async function loadActiveBlocks() {
  const container = document.getElementById('respContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading active blocks…</div>';
  try {
    const data = await apiFetchJson('/api/reactive/blocks');
    const ipBlocks = data.ip_blocks || [];
    const userBlocks = data.user_blocks || [];
    if (ipBlocks.length === 0 && userBlocks.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No active blocks.</div>';
      populateDispatchAgents();
      return;
    }
    let html = '';
    if (ipBlocks.length > 0) {
      const rows = ipBlocks.map(b => {
        const ip = typeof b === 'string' ? b : (b.ip || String(b));
        return `<tr>
          <td><span class="mono">${escapeHtml(ip)}</span></td>
          <td>${escapeHtml(b.reason || '—')}</td>
          <td class="text-12">${b.blocked_at ? new Date(b.blocked_at * 1000).toLocaleString() : '—'}</td>
          <td><button class="btnSm" data-unblock-ip="${escapeHtml(ip)}">Unblock</button></td>
        </tr>`;
      }).join('');
      html += `<h3 class="pane-section-title">IP Blocks</h3>
        <div class="tableWrap"><table class="tbl"><thead><tr><th>IP</th><th>Reason</th><th>Since</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    }
    if (userBlocks.length > 0) {
      const rows = userBlocks.map(b => {
        const user = typeof b === 'string' ? b : (b.user || String(b));
        return `<tr>
          <td>${escapeHtml(user)}</td>
          <td>${escapeHtml(b.reason || '—')}</td>
          <td class="text-12">${b.blocked_at ? new Date(b.blocked_at * 1000).toLocaleString() : '—'}</td>
          <td><button class="btnSm" data-unblock-user="${escapeHtml(user)}">Unblock</button></td>
        </tr>`;
      }).join('');
      html += `<h3 class="pane-section-title-spaced">User Blocks</h3>
        <div class="tableWrap"><table class="tbl"><thead><tr><th>User</th><th>Reason</th><th>Since</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    }
    container.innerHTML = html;

    container.querySelectorAll('[data-unblock-ip]').forEach(btn => {
      btn.addEventListener('click', () => unblockIp(btn.dataset.unblockIp));
    });
    container.querySelectorAll('[data-unblock-user]').forEach(btn => {
      btn.addEventListener('click', () => unblockUser(btn.dataset.unblockUser));
    });
    populateDispatchAgents();
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading blocks.</div>';
  }
}

function populateDispatchAgents() {
  const sel = document.getElementById('respDispatchAgent');
  if (!sel) return;
  sel.innerHTML = '<option value="">Select agent…</option>';
  const ids = state.connectedAgentIds || [];
  for (const id of ids) {
    const label = state.agentNames?.[id] || id;
    sel.innerHTML += `<option value="${escapeHtml(id)}">${escapeHtml(label)}</option>`;
  }
}

async function promptBlockIp() {
  const ip = await uiPrompt('Enter IP address to block:', '', { title: 'Block IP' });
  if (!ip) return;
  const reason = await uiPrompt('Reason (5+ chars, required):', '', { title: 'Block Reason' });
  if (!reason || reason.trim().length < 5) { showToast('Reason must be at least 5 characters', { kind: 'error' }); return; }
  try {
    await apiPostJson('/api/reactive/block_ip', { value: ip.trim(), reason: reason.trim() });
    showToast('IP blocked', { kind: 'ok' });
    loadActiveBlocks();
  } catch { showToast('Failed to block IP', { kind: 'error' }); }
}

async function promptBlockUser() {
  const user = await uiPrompt('Enter username to block:', '', { title: 'Block User' });
  if (!user) return;
  const reason = await uiPrompt('Reason (5+ chars, required):', '', { title: 'Block Reason' });
  if (!reason || reason.trim().length < 5) { showToast('Reason must be at least 5 characters', { kind: 'error' }); return; }
  try {
    await apiPostJson('/api/reactive/block_user', { value: user.trim(), reason: reason.trim() });
    showToast('User blocked', { kind: 'ok' });
    loadActiveBlocks();
  } catch { showToast('Failed to block user', { kind: 'error' }); }
}

async function unblockIp(ip) {
  try {
    await apiPostJson('/api/reactive/unblock_ip', { value: ip });
    showToast('IP unblocked', { kind: 'ok' });
    loadActiveBlocks();
  } catch { showToast('Failed to unblock', { kind: 'error' }); }
}

async function unblockUser(user) {
  try {
    await apiPostJson('/api/reactive/unblock_user', { value: user });
    showToast('User unblocked', { kind: 'ok' });
    loadActiveBlocks();
  } catch { showToast('Failed to unblock', { kind: 'error' }); }
}

async function dispatchCommand() {
  const agentId = document.getElementById('respDispatchAgent')?.value;
  const kind = document.getElementById('respDispatchKind')?.value || 'custom';
  const value = document.getElementById('respDispatchCmd')?.value?.trim();
  const resultEl = document.getElementById('respDispatchResult');
  if (!agentId) { showToast('Select an agent', { kind: 'error' }); return; }
  if (!value) { showToast('Enter a value or command', { kind: 'error' }); return; }
  try {
    const data = await apiPostJson('/api/reactive/dispatch', { agent_id: agentId, kind: kind, value: value });
    const cmdId = data.command_id || data.id;
    if (resultEl) { resultEl.style.display = 'block'; resultEl.textContent = 'Command dispatched. Waiting for result…'; }
    if (cmdId) pollCommandResult(cmdId);
  } catch { showToast('Failed to dispatch command', { kind: 'error' }); }
}

async function pollCommandResult(cmdId) {
  const resultEl = document.getElementById('respDispatchResult');
  if (!resultEl) return;
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const data = await apiFetchJson(`/api/reactive/command/${encodeURIComponent(cmdId)}`);
      if (data.status === 'completed' || data.status === 'failed') {
        resultEl.textContent = data.output || data.error || data.status;
        return;
      }
      resultEl.textContent = `Status: ${data.status}… (${(i + 1) * 2}s)`;
    } catch { /* retry */ }
  }
  resultEl.textContent += '\nTimed out waiting for response.';
}


// ─── Audit Log ───────────────────────────────────────────────

function initAuditPane() {
  loadAuditLog();
  const refreshBtn = document.getElementById('auditRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadAuditLog);
}

async function loadAuditLog() {
  const tbody = document.getElementById('auditTbody');
  const empty = document.getElementById('auditEmpty');
  if (!tbody) return;
  try {
    const entries = await apiFetchJson('/api/audit/reactive');
    if (!Array.isArray(entries) || entries.length === 0) {
      tbody.innerHTML = '';
      if (empty) empty.style.display = '';
      return;
    }
    if (empty) empty.style.display = 'none';
    tbody.innerHTML = entries.slice(0, 200).map(e => {
      const ts = e.timestamp ? new Date(e.timestamp * 1000).toLocaleString() : e.time || '—';
      return `<tr>
        <td class="text-12 nowrap">${escapeHtml(String(ts))}</td>
        <td>${escapeHtml(e.action || e.action_type || '—')}</td>
        <td><span class="mono">${escapeHtml(e.target || e.ip || e.user || '—')}</span></td>
        <td>${escapeHtml(e.actor || e.performed_by || '—')}</td>
        <td class="text-12">${escapeHtml(e.details || e.reason || '—')}</td>
      </tr>`;
    }).join('');
  } catch {
    if (empty) empty.textContent = 'Error loading audit log.';
  }
}
