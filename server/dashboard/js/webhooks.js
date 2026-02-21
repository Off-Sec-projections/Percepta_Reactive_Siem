// ═══════════════════════════════════════════════════════════════
//  Webhooks & API Keys management pane controller
// ═══════════════════════════════════════════════════════════════

function initWebhooksPane() {
  loadApiKeys();
  loadWebhooks();
  const refreshBtn = document.getElementById('webhooksRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadApiKeys(); loadWebhooks(); });
  const newKeyBtn = document.getElementById('webhooksNewKeyBtn');
  if (newKeyBtn) newKeyBtn.addEventListener('click', createApiKey);
  const newWhBtn = document.getElementById('webhooksNewWhBtn');
  if (newWhBtn) newWhBtn.addEventListener('click', showCreateWebhookDialog);
}

async function loadApiKeys() {
  const container = document.getElementById('apiKeysContent');
  if (!container) return;
  try {
    let resp;
    try {
      resp = await apiFetchJson('/api/keys');
    } catch (e1) {
      console.warn('[API Keys] Primary endpoint failed, trying fallback:', e1?.message);
      try {
        resp = await apiFetchJson('/api/api_keys');
      } catch (e2) {
        throw new Error(`Both /api/keys and /api/api_keys failed: ${e2?.message}`);
      }
    }
    const keys = Array.isArray(resp) ? resp : (Array.isArray(resp?.api_keys) ? resp.api_keys : []);
    if (keys.length === 0) {
      container.innerHTML = '<div class="muted p-12 ta-center">No API keys. Click <b>+ New Key</b> to create one.</div>';
      return;
    }
    const rows = keys.map(k => {
      const created = k.created_at ? new Date(k.created_at).toLocaleString() : '—';
      const maskedKey = k.prefix ? k.prefix + '…' : (k.key_prefix ? k.key_prefix + '…' : '—');
      return `<tr>
        <td><strong>${escapeHtml(k.name || k.label || '—')}</strong></td>
        <td class="mono text-xs">${escapeHtml(maskedKey)}</td>
        <td class="text-xs">${escapeHtml(created)}</td>
        <td><button class="btnSm danger" data-apikey-revoke="${escapeHtml(k.id || '')}">Revoke</button></td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-250">
      <table class="tbl"><thead><tr><th>Label</th><th>Key</th><th>Created</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
    container.querySelectorAll('[data-apikey-revoke]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          let revokeResp;
          try {
            revokeResp = await apiPostJson('/api/keys/revoke', { id: btn.dataset.apikeyRevoke });
          } catch (e1) {
            console.warn('[API Key Revoke] Primary endpoint failed, trying fallback:', e1?.message);
            try {
              revokeResp = await apiPostJson('/api/api_keys/revoke', { key_id: btn.dataset.apikeyRevoke });
            } catch (e2) {
              throw new Error(`Both revoke endpoints failed: ${e2?.message}`);
            }
          }
          showToast('API key revoked', 'ok');
          loadApiKeys();
        } catch (e) {
          console.error('[API Key Revoke] Failed:', e?.message);
          showToast(`Failed to revoke key: ${e?.message || 'Unknown error'}`, 'error');
        }
      });
    });
  } catch (e) {
    console.error('[API Keys] Failed to load:', e?.message);
    container.innerHTML = `<div class="muted p-12 ta-center">Error loading API keys: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load API keys: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function createApiKey() {
  const label = prompt('API key label:');
  if (!label) return;
  try {
    const resp = await apiPostJson('/api/keys', { name: label, role_id: 'analyst' }).catch(() =>
      apiPostJson('/api/api_keys', { label })
    );
    const rawKey = resp.api_key || resp.key || '';
    if (rawKey) {
      const html = `<div class="form-stack">
        <h3>API Key Created</h3>
        <div class="muted text-xs">Copy this key now. It will not be shown again.</div>
        <input class="field mono" id="apiKeyInput" value="${escapeHtml(rawKey)}" readonly />
        <button class="btn accent" id="apiKeyDone">Done</button>
      </div>`;
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
      document.body.appendChild(overlay);
      overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
      document.getElementById('apiKeyInput')?.addEventListener('click', function() { this.select(); });
      document.getElementById('apiKeyDone')?.addEventListener('click', () => overlay.remove());
    }
    loadApiKeys();
  } catch (e) {
    console.error('[Create API Key] Failed:', e?.message);
    showToast(`Failed to create API key: ${e?.message || 'error'}`, 'error');
  }
}

async function loadWebhooks() {
  const container = document.getElementById('webhooksListContent');
  if (!container) return;
  try {
    let resp;
    try {
      resp = await apiFetchJson('/api/webhooks');
    } catch (e) {
      console.error('[Load Webhooks] Failed:', e?.message);
      throw e;
    }
    const webhooks = Array.isArray(resp) ? resp : (Array.isArray(resp?.webhooks) ? resp.webhooks : []);
    if (webhooks.length === 0) {
      container.innerHTML = '<div class="muted p-12 ta-center">No webhooks configured.</div>';
      return;
    }
    const rows = webhooks.map(w => {
      const events = Array.isArray(w.events) ? w.events.join(', ') : (w.event_types || '—');
      const enabled = w.enabled !== false;
      const statusCls = enabled ? 'ok' : 'muted';
      return `<tr>
        <td><strong>${escapeHtml(w.name || w.id || '—')}</strong></td>
        <td class="text-xs mono break-all">${escapeHtml(w.url || '—')}</td>
        <td class="text-xs">${escapeHtml(events)}</td>
        <td><span class="${statusCls}">${enabled ? 'Active' : 'Disabled'}</span></td>
        <td><button class="btnSm danger" data-wh-remove="${escapeHtml(w.id || '')}">Remove</button></td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-300">
      <table class="tbl"><thead><tr><th>Name</th><th>URL</th><th>Events</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
    container.querySelectorAll('[data-wh-remove]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await apiPostJson('/api/webhooks/remove', { id: btn.dataset.whRemove });
          showToast('Webhook removed', 'ok');
          loadWebhooks();
        } catch (e) {
          console.error('[Webhook Remove] Failed:', e?.message);
          showToast(`Failed to remove webhook: ${e?.message || 'Unknown error'}`, 'error');
        }
      });
    });
  } catch (e) {
    console.error('[Load Webhooks] Failed:', e?.message);
    container.innerHTML = `<div class="muted p-12 ta-center">Error loading webhooks: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load webhooks: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function showCreateWebhookDialog() {
  const eventTypes = ['alert.created','alert.closed','alert.escalated','case.created','case.closed',
    'agent.connected','agent.disconnected','playbook.executed','dlp.violation','ioc.match','honeypot.hit','ids.alert'];
  const checkboxes = eventTypes.map(et => `<label class="check-chip"><input type="checkbox" class="whEventCheck" value="${et}" /> ${et}</label>`).join('');
  const html = `<div class="form-stack">
    <h3>Create Webhook</h3>
    <input class="field" id="whNewName" placeholder="Webhook name" />
    <input class="field" id="whNewUrl" placeholder="https://example.com/webhook" type="url" />
    <input class="field" id="whNewSecret" placeholder="Shared secret (for HMAC signature)" type="password" />
    <div class="card p-12">
      <div class="muted text-xs">Event types:</div>
      ${checkboxes}
    </div>
    <div class="actions-end">
      <button class="btn" id="whModalCancel">Cancel</button>
      <button class="btn accent" id="whCreateSubmit">Create</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-lg">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('whModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('whCreateSubmit')?.addEventListener('click', async () => {
    const name = document.getElementById('whNewName')?.value?.trim();
    const url = document.getElementById('whNewUrl')?.value?.trim();
    const secret = document.getElementById('whNewSecret')?.value;
    const events = Array.from(document.querySelectorAll('.whEventCheck:checked')).map(cb => cb.value);
    if (!name || !url) { showToast('Name and URL required', 'error'); return; }
    if (events.length === 0) { showToast('Select at least one event type', 'error'); return; }
    try {
      await apiPostJson('/api/webhooks', { name, url, secret, events });
      overlay.remove();
      showToast('Webhook created', 'ok');
      loadWebhooks();
    } catch (e) {
      console.error('[Create API Key] Failed:', e?.message);
      showToast(`Failed to create API key: ${e?.message || 'error'}`, 'error');
    }
  });
}
