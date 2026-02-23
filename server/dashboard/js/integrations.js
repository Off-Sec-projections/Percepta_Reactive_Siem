/* ── Integrations Hub Controller ── */
(function () {
  'use strict';

  const INT_API = '/api/integrations';
  const INT_TPL_API = '/api/integrations/templates';
  const INT_TEST_API = '/api/integrations/test';
  const FETCH_TIMEOUT_MS = 5000;
  let _intTemplates = [];
  let _intList = [];
  let _intLoaded = false;
  const AUTH_TYPES = [
    { value: 'header', label: 'Header' },
    { value: 'query_param', label: 'Query Param' },
    { value: 'bearer', label: 'Bearer' },
    { value: 'basic', label: 'Basic' },
    { value: 'none', label: 'None' },
  ];

  const _h = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const normalizeAuthType = (v) => {
    const raw = String(v || '').trim().toLowerCase();
    if (!raw) return 'header';
    if (raw === 'queryparam' || raw === 'query-param') return 'query_param';
    if (raw === 'none') return 'none';
    if (raw === 'header') return 'header';
    if (raw === 'bearer') return 'bearer';
    if (raw === 'basic') return 'basic';
    return 'header';
  };
  const authTypeLabel = (v) => {
    const normalized = normalizeAuthType(v);
    const found = AUTH_TYPES.find((t) => t.value === normalized);
    return found ? found.label : 'Header';
  };
  
  // Fetch with timeout wrapper
  const fetchWithTimeout = async (url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  };

  /* ── Public entry point, called by settings.js when tab activates ── */
  window.loadIntegrations = async function loadIntegrations() {
    try {
      const [tplRes, listRes] = await Promise.all([
        fetchWithTimeout(INT_TPL_API, { credentials: 'same-origin' }, FETCH_TIMEOUT_MS),
        fetchWithTimeout(INT_API, { credentials: 'same-origin' }, FETCH_TIMEOUT_MS),
      ]);
      if (tplRes && tplRes.ok) { const d = await tplRes.json(); _intTemplates = d.templates || d || []; }
      if (listRes && listRes.ok) { const d = await listRes.json(); _intList = d.integrations || d || []; }
      _renderTemplateButtons();
      _renderIntegrationList();
      _renderTestDropdown();
      if (!_intLoaded) {
        _bindEvents();
        _intLoaded = true;
      }
    } catch (e) {
      const msg = e?.name === 'AbortError' ? 'Request timeout (5s)' : (e?.message || 'Unknown error');
      console.error('[Integrations] Load failed:', msg);
      showToast('Failed to load integrations: ' + msg.slice(0, 60), 'error');
      _intList = [];
      _intTemplates = [];
      _renderIntegrationList();
      _renderTemplateButtons();
    }
  };

  /* ── Template quick-add buttons ── */
  function _renderTemplateButtons() {
    const box = document.getElementById('intTplButtons');
    if (!box) return;
    if (!_intTemplates.length) { box.innerHTML = '<span class="muted">No templates available.</span>'; return; }
    box.innerHTML = _intTemplates.map((t) =>
      `<button class="btn sm outline intTplBtn" data-tpl-id="${_h(t.id)}">${_h(t.name)}</button>`
    ).join('');
    box.querySelectorAll('.intTplBtn').forEach((btn) => {
      btn.addEventListener('click', () => _openFormWithTemplate(btn.getAttribute('data-tpl-id')));
    });
  }

  /* ── Integration cards list ── */
  function _renderIntegrationList() {
    const box = document.getElementById('intListContainer');
    if (!box) return;
    if (!_intList.length) { box.innerHTML = '<span class="muted">No integrations configured yet.</span>'; return; }
    box.innerHTML = _intList.map((it) => {
      const badge = it.enabled
        ? '<span style="color:var(--success,#4caf50);font-weight:600;">● Enabled</span>'
        : '<span style="color:var(--muted,#888);">○ Disabled</span>';
      const keyStatus = it.has_api_key
        ? '<span style="color:var(--success,#4caf50);">🔑 Key set</span>'
        : '<span style="color:var(--warning,#ff9800);">⚠ No key</span>';
      const eps = (it.endpoints || []).map((e) => `<code style="background:var(--glass2);padding:1px 5px;border-radius:3px;font-size:10px;">${_h(e.trigger)}</code>`).join(' ');
      const epCount = (it.endpoints || []).length;
      const desc = it.description ? `<div class="muted" style="font-size:11px;margin-top:2px;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_h(it.description)}</div>` : '';
      const docsLink = it.docs_url ? `<a href="${_h(it.docs_url)}" target="_blank" rel="noopener" style="font-size:10px;color:var(--accent,#5c6bc0);text-decoration:none;" title="Open documentation">📄 Docs</a>` : '';
      const authBadge = `<span style="font-size:10px;background:var(--glass2);padding:1px 6px;border-radius:3px;">${_h(authTypeLabel(it.auth_type))}</span>`;
      return `<div class="int-card" style="border:1px solid var(--stroke);border-radius:var(--radius-md,8px);padding:var(--sp-2,12px);margin-bottom:8px;background:var(--panel);">
        <div style="display:flex;align-items:center;gap:var(--sp-2);flex-wrap:wrap;">
          <div style="flex:1;min-width:220px;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <strong style="font-size:14px;">${_h(it.name)}</strong> ${badge} ${authBadge} ${docsLink}
            </div>
            <div class="muted" style="font-size:11px;margin-top:2px;">${_h(it.base_url)}</div>
            ${desc}
            <div style="font-size:11px;margin-top:4px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
              ${keyStatus}
              <span class="muted">·</span>
              <span>${epCount} endpoint${epCount !== 1 ? 's' : ''}: ${eps || '<span class="muted">none</span>'}</span>
              ${it.rate_limit_per_min ? `<span class="muted">· ${it.rate_limit_per_min} req/min</span>` : ''}
            </div>
          </div>
          <div style="display:flex;gap:var(--sp-1,6px);flex-shrink:0;">
            <button class="btn sm outline intEditBtn" data-int-id="${_h(it.id)}">Edit</button>
            <button class="btn sm outline intToggleBtn" data-int-id="${_h(it.id)}" data-enabled="${it.enabled}">${it.enabled ? 'Disable' : 'Enable'}</button>
            <button class="btn sm outline danger intDeleteBtn" data-int-id="${_h(it.id)}">Delete</button>
          </div>
        </div>
      </div>`;
    }).join('');
    box.querySelectorAll('.intToggleBtn').forEach((btn) => {
      btn.addEventListener('click', () => _toggleIntegration(btn.getAttribute('data-int-id'), btn.getAttribute('data-enabled') !== 'true'));
    });
    box.querySelectorAll('.intDeleteBtn').forEach((btn) => {
      btn.addEventListener('click', () => _deleteIntegration(btn.getAttribute('data-int-id')));
    });
    box.querySelectorAll('.intEditBtn').forEach((btn) => {
      btn.addEventListener('click', () => _openFormForEdit(btn.getAttribute('data-int-id')));
    });
  }

  /* ── Test dropdown ── */
  function _renderTestDropdown() {
    const sel = document.getElementById('intTestSelect');
    if (!sel) return;
    const enabled = _intList.filter((i) => i.enabled);
    sel.innerHTML = enabled.length
      ? enabled.map((i) => `<option value="${_h(i.id)}">${_h(i.name)}</option>`).join('')
      : '<option value="">No enabled integrations</option>';
  }

  /* ── Event bindings (once) ── */
  function _bindEvents() {
    const refreshBtn = document.getElementById('intRefreshBtn');
    if (refreshBtn) refreshBtn.addEventListener('click', () => window.loadIntegrations());

    const addBtn = document.getElementById('intAddCustomBtn');
    if (addBtn) addBtn.addEventListener('click', () => _openFormBlank());

    const testBtn = document.getElementById('intTestBtn');
    if (testBtn) testBtn.addEventListener('click', _runTest);
  }

  /* ── CRUD helpers ── */
  async function _toggleIntegration(id, enable) {
    try {
      const res = await fetch(`${INT_API}/${encodeURIComponent(id)}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enable }),
        credentials: 'same-origin',
      });
      if (!res.ok) { showToast('Toggle failed: ' + (await res.text()), 'error'); return; }
      await window.loadIntegrations();
    } catch (e) { showToast('Toggle error: ' + (e?.message || 'Unknown error'), 'error'); }
  }

  async function _deleteIntegration(id) {
    if (!confirm('Delete this integration?')) return;
    try {
      const res = await fetch(`${INT_API}/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      if (!res.ok) { showToast('Delete failed: ' + (await res.text()), 'error'); return; }
      await window.loadIntegrations();
    } catch (e) { showToast('Delete error: ' + (e?.message || 'Unknown error'), 'error'); }
  }

  async function _saveIntegration(payload) {
    try {
      const res = await fetch(INT_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        credentials: 'same-origin',
      });
      if (!res.ok) { showToast('Save failed: ' + (await res.text()), 'error'); return; }
      _closeModal();
      await window.loadIntegrations();
    } catch (e) { showToast('Save error: ' + (e?.message || 'Unknown error'), 'error'); }
  }

  /* ── Test ── */
  async function _runTest() {
    const sel = document.getElementById('intTestSelect');
    const trigSel = document.getElementById('intTestTrigger');
    const valIn = document.getElementById('intTestValue');
    const out = document.getElementById('intTestResult');
    if (!sel || !trigSel || !valIn || !out) return;
    const id = sel.value;
    const trigger = trigSel.value;
    const value = valIn.value.trim();
    if (!id) { showToast('Select an integration first.', 'error'); return; }
    if (!value) { showToast('Enter a test value.', 'error'); return; }
    out.style.display = 'block';
    out.textContent = 'Testing…';
    try {
      const res = await fetch(INT_TEST_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ integration_id: id, trigger, value }),
        credentials: 'same-origin',
      });
      if (!res.ok) {
        out.textContent = `Test failed (HTTP ${res.status}): ${res.statusText}`;
        return;
      }
      const data = await res.json().catch(() => res.text());
      if (typeof data === 'object' && data !== null) {
        out.textContent = JSON.stringify(data, null, 2);
      } else {
        out.textContent = String(data || '(no response)');
      }
    } catch (e) {
      out.textContent = 'Error: ' + (e?.message || 'Unknown error');
    }
  }

  /* ── Modal form (add / edit) ── */
  function _openFormBlank() {
    _showModal({
      id: '', name: '', base_url: 'https://', auth_type: 'header', auth_key_name: '', api_key: '',
      endpoints: [{ trigger: 'ip', path: '/{value}', response_field: '', method: 'GET', body_template: '' }],
      rate_limit_per_min: 30, enabled: true, description: '', docs_url: '',
    });
  }

  function _openFormWithTemplate(tplId) {
    const tpl = _intTemplates.find((t) => t.id === tplId);
    if (!tpl) return;
    _showModal({ ...tpl, api_key: '' });
  }

  function _openFormForEdit(intId) {
    const it = _intList.find((i) => i.id === intId);
    if (!it) return;
    _showModal({ ...it, api_key: '' });
  }

  function _showModal(data) {
    _closeModal();
    const selectedAuthType = normalizeAuthType(data.auth_type);
    const overlay = document.createElement('div');
    overlay.id = 'intFormOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:8000;display:flex;align-items:center;justify-content:center;';
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--panel);border:1px solid var(--stroke);border-radius:var(--radius-md,8px);padding:var(--sp-3,16px);max-width:620px;width:95%;max-height:85vh;overflow:auto;color:var(--text);';

    const isEdit = _intList.some((i) => i.id === data.id);
    const title = isEdit ? 'Edit Integration' : (data.name ? `Add: ${_h(data.name)}` : 'Add Custom Integration');
    const statusBadge = isEdit
      ? (data.enabled
        ? '<span style="color:var(--success,#4caf50);font-size:12px;font-weight:600;">● Active</span>'
        : '<span style="color:var(--muted,#888);font-size:12px;">○ Inactive</span>')
      : '<span style="color:var(--accent,#5c6bc0);font-size:12px;">✦ New</span>';

    const endpointsHTML = (data.endpoints || []).map((ep, i) => `
      <div class="int-ep-row" style="border:1px solid var(--stroke);border-radius:4px;padding:8px;margin-bottom:6px;">
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <select class="field sm intEpTrigger" style="width:80px;">
            ${['ip','hash','domain','url'].map((t) => `<option value="${t}" ${ep.trigger === t ? 'selected' : ''}>${t}</option>`).join('')}
          </select>
          <select class="field sm intEpMethod" style="width:65px;">
            <option value="GET" ${ep.method === 'GET' ? 'selected' : ''}>GET</option>
            <option value="POST" ${ep.method === 'POST' ? 'selected' : ''}>POST</option>
          </select>
          <input class="field sm intEpPath" value="${_h(ep.path)}" placeholder="/path/{value}" style="flex:1;min-width:120px;">
        </div>
        <div style="display:flex;gap:6px;margin-top:4px;">
          <input class="field sm intEpField" value="${_h(ep.response_field || '')}" placeholder="response_field (dot path)" style="flex:1;">
          <button class="btn sm outline danger intEpRm" data-idx="${i}">✕</button>
        </div>
        <input class="field sm intEpBody" value="${_h(ep.body_template || '')}" placeholder="POST body template (optional)" style="width:100%;margin-top:4px;${ep.method === 'POST' ? '' : 'display:none;'}">
      </div>
    `).join('');

    const sectionBorder = 'border-top:1px solid var(--stroke);padding-top:10px;margin-top:10px;';

    card.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
        <h4 style="margin:0;">${title}</h4>
        ${statusBadge}
      </div>
      ${data.description ? `<div class="muted" style="font-size:12px;margin-bottom:4px;">${_h(data.description)}</div>` : ''}
      ${data.docs_url ? `<a href="${_h(data.docs_url)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent,#5c6bc0);text-decoration:none;display:inline-block;margin-bottom:8px;">📄 View Documentation ↗</a>` : '<div style="margin-bottom:8px;"></div>'}

      <div style="display:flex;gap:8px;margin-bottom:8px;">
        <div style="flex:1;">
          <label class="muted" style="font-size:11px;">Name <span style="color:var(--danger,#f44336);">*</span></label>
          <input class="field sm" id="intFName" value="${_h(data.name)}" placeholder="e.g. VirusTotal" style="width:100%;">
        </div>
        <div style="flex:1;">
          <label class="muted" style="font-size:11px;">Base URL <span style="color:var(--danger,#f44336);">*</span></label>
          <input class="field sm" id="intFUrl" value="${_h(data.base_url)}" placeholder="https://api.example.com" style="width:100%;">
        </div>
      </div>

      <div style="${sectionBorder}">
        <label class="muted" style="font-size:11px;font-weight:600;">Authentication</label>
        <div style="display:flex;gap:8px;margin-top:4px;margin-bottom:8px;">
          <div style="flex:1;">
            <label class="muted" style="font-size:11px;">Auth Type</label>
            <select class="field sm" id="intFAuth" style="width:100%;">
              ${AUTH_TYPES.map((a) =>
                `<option value="${a.value}" ${selectedAuthType === a.value ? 'selected' : ''}>${a.label}</option>`
              ).join('')}
            </select>
          </div>
          <div style="flex:1;" id="intFKeyNameWrap">
            <label class="muted" style="font-size:11px;">Auth Key Name</label>
            <input class="field sm" id="intFKeyName" value="${_h(data.auth_key_name)}" placeholder="e.g. x-apikey" style="width:100%;">
          </div>
        </div>
        <label class="muted" style="font-size:11px;">API Key ${isEdit ? '<span style="font-size:10px;color:var(--muted);">(leave blank to keep existing)</span>' : ''}</label>
        <div style="display:flex;gap:0;margin-bottom:8px;position:relative;">
          <input class="field sm" id="intFKey" type="password" value="" placeholder="${data.has_api_key ? '••••••••' : 'Paste API key'}" style="width:100%;padding-right:36px;" autocomplete="off">
          <button type="button" id="intFKeyToggle" title="Show/hide key" style="position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted,#888);cursor:pointer;font-size:14px;padding:2px 4px;">👁</button>
        </div>
        ${data.has_api_key ? '<div style="font-size:10px;color:var(--success,#4caf50);margin-top:-6px;margin-bottom:6px;">🔑 API key is stored securely on the server</div>' : ''}
      </div>

      <div style="${sectionBorder}">
        <label class="muted" style="font-size:11px;font-weight:600;">Settings</label>
        <div style="display:flex;gap:8px;margin-top:4px;margin-bottom:8px;">
          <div style="flex:1;"><label class="muted" style="font-size:11px;">Rate Limit /min</label>
            <input class="field sm" id="intFRate" type="number" min="1" max="1000" value="${data.rate_limit_per_min || 30}" style="width:100%;"></div>
          <div style="flex:2;"><label class="muted" style="font-size:11px;">Description</label>
            <input class="field sm" id="intFDesc" value="${_h(data.description || '')}" placeholder="Brief description of this integration" style="width:100%;"></div>
        </div>
        <label class="muted" style="font-size:11px;">Documentation URL</label>
        <input class="field sm" id="intFDocs" value="${_h(data.docs_url || '')}" placeholder="https://docs.example.com" style="width:100%;margin-bottom:8px;">
      </div>

      <div style="${sectionBorder}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
          <label class="muted" style="font-size:11px;font-weight:600;">Endpoints</label>
          <button class="btn sm outline" id="intFAddEp">+ Endpoint</button>
        </div>
        <div id="intFEndpoints">${endpointsHTML}</div>
      </div>

      <div style="${sectionBorder}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <button class="btn sm outline" id="intFTestConn" ${!isEdit ? 'disabled title="Save the integration first to test"' : ''}>⚡ Test Connection</button>
          <span id="intFTestStatus" style="font-size:11px;"></span>
        </div>
        <pre id="intFTestResult" style="display:none;font-size:11px;background:var(--bg2);border:1px solid var(--stroke);border-radius:4px;padding:8px;max-height:120px;overflow:auto;white-space:pre-wrap;margin:0 0 8px;"></pre>
      </div>

      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px;">
        <button class="btn sm outline" id="intFCancel">Cancel</button>
        <button class="btn sm" id="intFSave">${isEdit ? 'Update' : 'Save'}</button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    overlay.addEventListener('click', (e) => { if (e.target === overlay) _closeModal(); });
    card.querySelector('#intFCancel').addEventListener('click', _closeModal);
    card.querySelector('#intFSave').addEventListener('click', () => _collectAndSave(data.id));

    /* Eye toggle for API key visibility */
    const keyInput = card.querySelector('#intFKey');
    const keyToggle = card.querySelector('#intFKeyToggle');
    if (keyToggle && keyInput) {
      keyToggle.addEventListener('click', () => {
        const showing = keyInput.type === 'text';
        keyInput.type = showing ? 'password' : 'text';
        keyToggle.textContent = showing ? '👁' : '🔒';
        keyToggle.title = showing ? 'Show key' : 'Hide key';
      });
    }

    /* Hide auth key name when auth type is None */
    const authSel = card.querySelector('#intFAuth');
    const keyNameWrap = card.querySelector('#intFKeyNameWrap');
    if (authSel && keyNameWrap) {
      const _updateKeyNameVis = () => {
        keyNameWrap.style.display = authSel.value === 'None' ? 'none' : '';
      };
      _updateKeyNameVis();
      authSel.addEventListener('change', _updateKeyNameVis);
    }

    /* Inline test connection button */
    const testBtn = card.querySelector('#intFTestConn');
    if (testBtn && isEdit) {
      testBtn.addEventListener('click', async () => {
        const statusEl = card.querySelector('#intFTestStatus');
        const resultEl = card.querySelector('#intFTestResult');
        statusEl.textContent = 'Testing…';
        statusEl.style.color = 'var(--muted,#888)';
        resultEl.style.display = 'none';
        testBtn.disabled = true;
        try {
          const firstEp = (data.endpoints || [])[0];
          const trigger = firstEp ? firstEp.trigger : 'ip';
          const sampleValues = { ip: '8.8.8.8', hash: '44d88612fea8a8f36de82e1278abb02f', domain: 'example.com', url: 'https://example.com' };
          const res = await fetch(INT_TEST_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ integration_id: data.id, trigger, value: sampleValues[trigger] || '8.8.8.8' }),
            credentials: 'same-origin',
          });
          if (!res.ok) {
            statusEl.textContent = `✗ Failed (HTTP ${res.status})`;
            statusEl.style.color = 'var(--danger,#f44336)';
            resultEl.style.display = 'block';
            resultEl.textContent = await res.text();
          } else {
            const d = await res.json().catch(() => ({}));
            statusEl.textContent = d.ok ? '✓ Connection successful' : '✗ Test returned error';
            statusEl.style.color = d.ok ? 'var(--success,#4caf50)' : 'var(--danger,#f44336)';
            resultEl.style.display = 'block';
            resultEl.textContent = JSON.stringify(d, null, 2);
          }
        } catch (e) {
          statusEl.textContent = '✗ ' + (e?.message || 'Connection error');
          statusEl.style.color = 'var(--danger,#f44336)';
        } finally {
          testBtn.disabled = false;
        }
      });
    }

    card.querySelector('#intFAddEp').addEventListener('click', () => {
      const box = card.querySelector('#intFEndpoints');
      const idx = box.querySelectorAll('.int-ep-row').length;
      const row = document.createElement('div');
      row.className = 'int-ep-row';
      row.style.cssText = 'border:1px solid var(--stroke);border-radius:4px;padding:8px;margin-bottom:6px;';
      row.innerHTML = `
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <select class="field sm intEpTrigger" style="width:80px;">
            ${['ip','hash','domain','url'].map((t) => `<option value="${t}">${t}</option>`).join('')}
          </select>
          <select class="field sm intEpMethod" style="width:65px;"><option value="GET" selected>GET</option><option value="POST">POST</option></select>
          <input class="field sm intEpPath" value="/{value}" placeholder="/path/{value}" style="flex:1;min-width:120px;">
        </div>
        <div style="display:flex;gap:6px;margin-top:4px;">
          <input class="field sm intEpField" value="" placeholder="response_field" style="flex:1;">
          <button class="btn sm outline danger intEpRm" data-idx="${idx}">✕</button>
        </div>
        <input class="field sm intEpBody" value="" placeholder="POST body template" style="width:100%;margin-top:4px;display:none;">
      `;
      box.appendChild(row);
      _bindEpEvents(row);
    });

    card.querySelectorAll('.int-ep-row').forEach((row) => _bindEpEvents(row));

    /* Toggle body_template visibility based on method */
    card.querySelectorAll('.intEpMethod').forEach((sel) => {
      sel.addEventListener('change', () => {
        const body = sel.closest('.int-ep-row').querySelector('.intEpBody');
        if (body) body.style.display = sel.value === 'POST' ? '' : 'none';
      });
    });
  }

  function _bindEpEvents(row) {
    const rm = row.querySelector('.intEpRm');
    if (rm) rm.addEventListener('click', () => row.remove());
    const meth = row.querySelector('.intEpMethod');
    if (meth) meth.addEventListener('change', () => {
      const body = row.querySelector('.intEpBody');
      if (body) body.style.display = meth.value === 'POST' ? '' : 'none';
    });
  }

  function _collectAndSave(existingId) {
    const name = (document.getElementById('intFName') || {}).value || '';
    const base_url = (document.getElementById('intFUrl') || {}).value || '';
    const auth_type = normalizeAuthType((document.getElementById('intFAuth') || {}).value || 'header');
    const auth_key_name = (document.getElementById('intFKeyName') || {}).value || '';
    const api_key = (document.getElementById('intFKey') || {}).value || '';
    const rate_limit_per_min = parseInt((document.getElementById('intFRate') || {}).value, 10) || 30;
    const description = (document.getElementById('intFDesc') || {}).value || '';
    const docs_url = (document.getElementById('intFDocs') || {}).value || '';

    if (!name.trim()) { showToast('Name is required.', 'error'); return; }
    if (!base_url.trim()) { showToast('Base URL is required.', 'error'); return; }

    /* URL scheme validation */
    try {
      const parsed = new URL(base_url.trim());
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        showToast('Base URL must use https:// or http:// scheme.', 'error'); return;
      }
    } catch (_) {
      showToast('Base URL is not a valid URL.', 'error'); return;
    }

    /* Rate limit bounds */
    const clampedRate = Math.max(1, Math.min(1000, rate_limit_per_min));

    /* Auth key name safety: only allow header-safe chars */
    if (auth_type !== 'none' && auth_key_name && !/^[A-Za-z0-9_-]+$/.test(auth_key_name.trim())) {
      showToast('Auth Key Name may only contain letters, digits, hyphens, and underscores.', 'error'); return;
    }

    const VALID_TRIGGERS = ['ip', 'hash', 'domain', 'url'];
    const endpoints = [];
    let triggerError = false;
    document.querySelectorAll('#intFEndpoints .int-ep-row').forEach((row) => {
      const trigger = (row.querySelector('.intEpTrigger') || {}).value || '';
      const method = (row.querySelector('.intEpMethod') || {}).value || 'GET';
      const path = (row.querySelector('.intEpPath') || {}).value || '';
      const response_field = (row.querySelector('.intEpField') || {}).value || '';
      const body_template = (row.querySelector('.intEpBody') || {}).value || '';
      if (trigger && path) {
        if (!VALID_TRIGGERS.includes(trigger)) { triggerError = true; }
        endpoints.push({ trigger, path, response_field: response_field || null, method, body_template: body_template || null });
      }
    });
    if (triggerError) { showToast('Trigger must be one of: ip, hash, domain, url', 'error'); return; }

    const existing = existingId ? _intList.find((i) => i.id === existingId) : null;
    const payload = {
      id: existingId || name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      name: name.trim(), base_url: base_url.trim(), auth_type, auth_key_name, api_key: api_key || null,
      endpoints, rate_limit_per_min: clampedRate, enabled: existing ? !!existing.enabled : true, description, docs_url,
    };
    /* Strip null values — Rust expects empty strings, not null */
    for (const k of Object.keys(payload)) { if (payload[k] === null) payload[k] = ''; }
    for (const ep of payload.endpoints) { for (const k of Object.keys(ep)) { if (ep[k] === null) ep[k] = ''; } }
    _saveIntegration(payload);
  }

  function _closeModal() {
    const el = document.getElementById('intFormOverlay');
    if (el) el.remove();
  }
})();
