// ═══════════════════════════════════════════════════════════════
//  Cases — Case Management pane controller
// ═══════════════════════════════════════════════════════════════

function initCasesPane() {
  loadCases();
  const newBtn = document.getElementById('casesNewBtn');
  if (newBtn) newBtn.addEventListener('click', () => showCreateCaseDialog());
  const refreshBtn = document.getElementById('casesRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadCases);
  const filterSel = document.getElementById('casesFilterStatus');
  if (filterSel) filterSel.addEventListener('change', loadCases);
}

function caseRoleLower() {
  return String(state?.auth?.status?.role || '').toLowerCase();
}

function canCloseHighSeverityCase() {
  return caseRoleLower() === 'authority';
}

async function loadCases() {
  const container = document.getElementById('casesContent');
  if (!container) return;
  const filterSel = document.getElementById('casesFilterStatus');
  const filterVal = filterSel ? filterSel.value : '';
  try {
    const resp = await apiFetchJson('/api/cases');
    const cases = Array.isArray(resp) ? resp : (resp?.cases || []);
    if (!Array.isArray(cases) || cases.length === 0) {
      container.innerHTML = '<div class="empty-state">No cases yet. Click <b>+ New Case</b> to create one.</div>';
      updateCaseStats(cases || []);
      return;
    }
    const filtered = filterVal ? cases.filter(c => (c.status || '').toLowerCase() === filterVal.toLowerCase()) : cases;
    updateCaseStats(cases);
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">No cases matching filter.</div>';
      return;
    }
    const rows = filtered.map(c => {
      const id = c.id || '—';
      const title = c.title || 'Untitled';
      const status = c.status || 'open';
      const severity = c.severity || 'medium';
      const assignee = c.assignee || '—';
      const created = c.created_at ? new Date(c.created_at).toLocaleString() : '—';
      const alertCount = Array.isArray(c.alert_ids) ? c.alert_ids.length : 0;
      const sevCls = severity === 'critical' ? 'danger' : severity === 'high' ? 'warn' : 'muted';
      const statusCls = status === 'closed' ? 'muted' : status === 'in_progress' ? 'warn' : 'ok';
      return `<tr data-case-id="${escapeHtml(id)}" data-case-severity="${escapeHtml(severity)}" data-case-status="${escapeHtml(status)}">
        <td><input type="checkbox" class="caseBulkSel" data-case-select="${escapeHtml(id)}"></td>
        <td><strong>${escapeHtml(String(id).slice(0, 8))}</strong></td>
        <td>${escapeHtml(title)}</td>
        <td><span class="${statusCls}">${escapeHtml(status)}</span></td>
        <td><span class="${sevCls}">${escapeHtml(severity)}</span></td>
        <td>${escapeHtml(assignee)}</td>
        <td class="text-xs">${alertCount}</td>
        <td class="text-xs">${escapeHtml(created)}</td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="row gap8 mb8" id="casesBulkActions">
      <button class="btn" id="casesBulkResolve" disabled>Resolve Selected</button>
      <span class="muted text-xs" id="casesBulkCount">0 selected</span>
    </div>
    <div class="tableWrap maxh-500">
      <table class="tbl"><thead><tr><th style="width:28px"><input type="checkbox" id="casesBulkAll"></th><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Assignee</th><th>Alerts</th><th>Created</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
    const allBox = container.querySelector('#casesBulkAll');
    const boxes = Array.from(container.querySelectorAll('.caseBulkSel'));
    const countEl = container.querySelector('#casesBulkCount');
    const resolveBtn = container.querySelector('#casesBulkResolve');

    const refreshBulkUi = () => {
      const selected = boxes.filter((b) => b.checked);
      if (countEl) countEl.textContent = `${selected.length} selected`;
      if (resolveBtn) resolveBtn.disabled = selected.length === 0;
      if (allBox) {
        allBox.checked = selected.length > 0 && selected.length === boxes.length;
        allBox.indeterminate = selected.length > 0 && selected.length < boxes.length;
      }
    };
    if (allBox) {
      allBox.addEventListener('change', () => {
        const checked = Boolean(allBox.checked);
        boxes.forEach((b) => { b.checked = checked; });
        refreshBulkUi();
      });
    }
    boxes.forEach((b) => b.addEventListener('change', refreshBulkUi));
    refreshBulkUi();

    if (resolveBtn) {
      resolveBtn.addEventListener('click', async () => {
        const selectedRows = boxes
          .filter((b) => b.checked)
          .map((b) => b.closest('tr'))
          .filter(Boolean);
        if (!selectedRows.length) return;

        const blocked = selectedRows.filter((r) => {
          const sev = String(r.dataset.caseSeverity || '').toLowerCase();
          return (sev === 'high' || sev === 'critical') && !canCloseHighSeverityCase();
        });
        if (blocked.length) {
          showToast('High/Critical cases can only be closed by Authority role.', 'warn');
        }

        const resolvable = selectedRows.filter((r) => !blocked.includes(r));
        if (!resolvable.length) return;
        if (!confirm(`Resolve ${resolvable.length} selected case(s)?`)) return;

        let ok = 0;
        for (const row of resolvable) {
          const id = String(row.dataset.caseId || '').trim();
          if (!id) continue;
          try {
            await apiPostJson(`/api/cases/${encodeURIComponent(id)}/status`, { status: 'closed' });
            ok++;
          } catch (e) {
            showToast(`Failed to close case: ${e?.message || 'unknown error'}`, 'error');
          }
        }
        if (ok > 0) showToast(`Resolved ${ok} case(s)`, 'ok');
        if (ok !== resolvable.length) showToast(`${resolvable.length - ok} case(s) failed to update`, 'warn');
        try { await loadCases(); } catch (e) { }
      });
    }

    container.querySelectorAll('[data-case-id]').forEach(row => {
      row.addEventListener('click', (ev) => {
        if (ev.target && ev.target.closest('input[type="checkbox"]')) return;
        showCaseDetail(row.dataset.caseId, cases);
      });
    });
  } catch {
    container.innerHTML = '<div class="error-state">Error loading cases.</div>';
  }
}

function updateCaseStats(cases) {
  const total = document.getElementById('casesStatTotal');
  const open = document.getElementById('casesStatOpen');
  const inProg = document.getElementById('casesStatInProgress');
  const closed = document.getElementById('casesStatClosed');
  if (total) total.textContent = cases.length;
  if (open) open.textContent = cases.filter(c => c.status === 'open').length;
  if (inProg) inProg.textContent = cases.filter(c => c.status === 'in_progress').length;
  if (closed) closed.textContent = cases.filter(c => c.status === 'closed').length;
}

async function showCreateCaseDialog(prefill = {}, options = {}) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  const panel = document.createElement('div');
  panel.className = 'modal-content modal-content-md';
  panel.innerHTML = `
    <h3 class="case-form-title">Create Case</h3>
    <div class="case-form-stack">
      <div><label class="muted case-label">Title</label>
        <input id="caseEdTitle" class="inp case-w-full" placeholder="Brief summary"></div>
      <div><label class="muted case-label">Description</label>
        <textarea id="caseEdDesc" class="inp case-desc-input" placeholder="Detailed description"></textarea></div>
      <div class="case-split">
        <div class="case-col"><label class="muted case-label">Severity</label>
          <select id="caseEdSeverity" class="inp case-w-full">
            <option value="low">Low</option>
            <option value="medium" selected>Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select></div>
        <div class="case-col"><label class="muted case-label">Assignee</label>
          <input id="caseEdAssignee" class="inp case-w-full" placeholder="Analyst name"></div>
      </div>
      <div><label class="muted case-label">Alert IDs (comma-separated, optional)</label>
        <input id="caseEdAlerts" class="inp case-w-full" placeholder="alert-id-1, alert-id-2"></div>
      <div class="case-actions">
        <button class="btn" id="caseEdCancel">Cancel</button>
        <button class="btn primary" id="caseEdSave">Create</button>
      </div>
    </div>`;
  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  const toStr = (v) => (v == null ? '' : String(v));
  const initialAlertIds = Array.isArray(prefill.alert_ids)
    ? prefill.alert_ids.map((v) => String(v).trim()).filter(Boolean)
    : (prefill.related_alert_id ? [String(prefill.related_alert_id).trim()] : []);

  const titleInput = panel.querySelector('#caseEdTitle');
  const descInput = panel.querySelector('#caseEdDesc');
  const severityInput = panel.querySelector('#caseEdSeverity');
  const assigneeInput = panel.querySelector('#caseEdAssignee');
  const alertsInput = panel.querySelector('#caseEdAlerts');
  const saveBtn = panel.querySelector('#caseEdSave');
  const currentUser = String(state?.auth?.status?.username || '').trim();
  const prefillAssignee = toStr(prefill.assignee || '').trim();

  if (titleInput) titleInput.value = toStr(prefill.title || '');
  if (descInput) descInput.value = toStr(prefill.description || '');
  if (severityInput) {
    const sev = toStr(prefill.severity || 'medium').toLowerCase();
    severityInput.value = ['low', 'medium', 'high', 'critical'].includes(sev) ? sev : 'medium';
  }
  if (assigneeInput) {
    assigneeInput.value = prefillAssignee || currentUser || '';
  }
  if (alertsInput && initialAlertIds.length) alertsInput.value = initialAlertIds.join(', ');

  return new Promise(resolve => {
    const cleanup = (result = null) => { try { overlay.remove(); } catch {} resolve(result); };
    overlay.addEventListener('click', e => { if (e.target === overlay) cleanup(); });
    panel.querySelector('#caseEdCancel').addEventListener('click', cleanup);
    panel.querySelector('#caseEdSave').addEventListener('click', async () => {
      if (saveBtn) saveBtn.disabled = true;
      const title = document.getElementById('caseEdTitle').value.trim();
      if (!title) {
        showToast('Title is required', 'error');
        if (saveBtn) saveBtn.disabled = false;
        return;
      }
      const alertsRaw = document.getElementById('caseEdAlerts').value.trim();
      const alertIds = alertsRaw ? alertsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
      const body = {
        title,
        description: document.getElementById('caseEdDesc').value.trim(),
        severity: document.getElementById('caseEdSeverity').value,
        assignee: document.getElementById('caseEdAssignee').value.trim() || undefined,
        alert_ids: alertIds,
      };
      try {
        const created = await apiPostJson('/api/cases', body);
        showToast('Case created', 'ok');
        await loadCases();
        if (options && options.routeOnCreate && created?.id) {
          if (typeof setView === 'function') {
            try { setView('cases'); } catch { try { setView('escalations'); } catch {} }
          }
          showCaseDetail(created.id, [created]);
        }
        cleanup({ createdCase: created || null, cancelled: false });
        return;
      } catch { showToast('Failed to create case', 'error'); }
      if (saveBtn) saveBtn.disabled = false;
    });
  });
}

async function showCaseDetail(caseId, allCases) {
  let caseData = (allCases || []).find(c => c.id === caseId);
  if (!caseData) {
    try { caseData = await apiFetchJson(`/api/cases/${encodeURIComponent(caseId)}`); } catch { showToast('Case not found', 'error'); return; }
  }
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  const panel = document.createElement('div');
  panel.className = 'modal-content modal-content-xl';

  const status = caseData.status || 'open';
  const comments = Array.isArray(caseData.comments) ? caseData.comments : [];
  const alertIds = Array.isArray(caseData.alert_ids) ? caseData.alert_ids : [];

  const commentsHtml = comments.length > 0
    ? comments.map(cm => `<div class="case-comments-item">
        <strong>${escapeHtml(cm.author || 'System')}</strong> <span class="muted">${(cm.created_at || cm.time) ? new Date(cm.created_at || cm.time).toLocaleString() : ''}</span>
        <div class="case-comments-item-text">${escapeHtml(cm.text || '')}</div>
      </div>`).join('')
    : '<div class="muted case-comments-empty">No comments yet.</div>';

  const alertsHtml = alertIds.length > 0
    ? `<div class="case-alerts-wrap">${alertIds.map(a => `<span class="mono case-alert-chip">${escapeHtml(String(a).slice(0, 12))}</span>`).join('')}</div>`
    : '<div class="muted case-comments-empty">No attached alerts.</div>';

  panel.innerHTML = `
    <div class="case-head">
      <h3 class="case-title">${escapeHtml(caseData.title || 'Case')}</h3>
      <button class="btnSm" id="caseDetailClose">✕</button>
    </div>
    <div class="muted case-meta">ID: ${escapeHtml(caseData.id || '—')} · ${escapeHtml(caseData.severity || 'medium')} · Created: ${caseData.created_at ? new Date(caseData.created_at).toLocaleString() : '—'}</div>
    <div class="case-desc">${escapeHtml(caseData.description || 'No description.')}</div>

    <div class="case-status-row">
      <label class="muted case-label">Status:</label>
      <select id="caseDetailStatus" class="inp case-status-select">
        <option value="open" ${status === 'open' ? 'selected' : ''}>Open</option>
        <option value="in_progress" ${status === 'in_progress' ? 'selected' : ''}>In Progress</option>
        <option value="closed" ${status === 'closed' ? 'selected' : ''}>Closed</option>
      </select>
      <button class="btnSm accent" id="caseDetailUpdateStatus">Update</button>
    </div>

    <div class="case-section">
      <strong class="case-section-title">Attached Alerts</strong>
      ${alertsHtml}
    </div>

    <div class="case-section">
      <strong class="case-section-title">Comments</strong>
      <div id="caseCommentsList">${commentsHtml}</div>
      <div class="case-comment-row">
        <input id="caseCommentInput" class="inp case-comment-input" placeholder="Add a comment…">
        <button class="btnSm accent" id="caseCommentAdd">Add</button>
      </div>
    </div>

    <div class="case-footer">
      <button class="btn" id="caseDetailDone">Close</button>
    </div>`;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  const cleanup = () => { try { overlay.remove(); } catch {} };
  overlay.addEventListener('click', e => { if (e.target === overlay) cleanup(); });
  panel.querySelector('#caseDetailClose').addEventListener('click', cleanup);
  panel.querySelector('#caseDetailDone').addEventListener('click', cleanup);

  panel.querySelector('#caseDetailUpdateStatus').addEventListener('click', async () => {
    const newStatus = document.getElementById('caseDetailStatus').value;
    const sev = String(caseData?.severity || '').toLowerCase();
    if (newStatus === 'closed' && (sev === 'high' || sev === 'critical') && !canCloseHighSeverityCase()) {
      showToast('High/Critical cases can only be closed by Authority role.', 'warn');
      return;
    }
    try {
      await apiPostJson(`/api/cases/${encodeURIComponent(caseId)}/status`, { status: newStatus });
      showToast('Status updated', 'ok');
      loadCases();
    } catch { showToast('Failed to update status', 'error'); }
  });

  panel.querySelector('#caseCommentAdd').addEventListener('click', async () => {
    const text = document.getElementById('caseCommentInput').value.trim();
    if (!text) return;
    try {
      await apiPostJson(`/api/cases/${encodeURIComponent(caseId)}/comment`, { text });
      showToast('Comment added', 'ok');
      document.getElementById('caseCommentInput').value = '';
      // Reload detail
      cleanup();
      showCaseDetail(caseId, null);
    } catch { showToast('Failed to add comment', 'error'); }
  });
}

window.openCreateCaseModal = function openCreateCaseModal(caseContext) {
  return showCreateCaseDialog(caseContext || {}, { routeOnCreate: true });
};

window.openCaseDetailById = async function openCaseDetailById(caseId) {
  if (!caseId) return;
  if (typeof setView === 'function') {
    try { setView('cases'); } catch { try { setView('escalations'); } catch {} }
  }
  await loadCases();
  await showCaseDetail(String(caseId), null);
};

window.createCaseFromAlertContext = async function createCaseFromAlertContext(caseContext) {
  const ctx = caseContext || {};
  if (typeof window.openCreateCaseModal === 'function') {
    const result = await window.openCreateCaseModal(ctx);
    if (result?.createdCase?.id && typeof window.openCaseDetailById === 'function') {
      await window.openCaseDetailById(result.createdCase.id);
    }
    return result;
  }

  const created = await apiPostJson('/api/cases', {
    title: String(ctx.title || 'Untitled Case'),
    description: String(ctx.description || ''),
    severity: String(ctx.severity || 'medium'),
    assignee: String(ctx.assignee || ''),
    related_alert_id: ctx.related_alert_id || null,
    alert_ids: Array.isArray(ctx.alert_ids) ? ctx.alert_ids : [],
  });
  showToast('Case created', 'ok');
  if (created?.id && typeof window.openCaseDetailById === 'function') {
    await window.openCaseDetailById(created.id);
  }
  return { createdCase: created || null, cancelled: false };
};
