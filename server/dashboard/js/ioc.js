// ═══════════════════════════════════════════════════════════════
//  IOC — Indicator of Compromise / Threat Intel pane controller
// ═══════════════════════════════════════════════════════════════

function initIocPane() {
  loadIocStats();
  loadIocList();
  const refreshBtn = document.getElementById('iocRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadIocStats(); loadIocList(); });
  const addBtn = document.getElementById('iocAddBtn');
  if (addBtn) addBtn.addEventListener('click', showAddIocDialog);
  const importBtn = document.getElementById('iocImportStixBtn');
  if (importBtn) importBtn.addEventListener('click', showImportStixDialog);
  const filterType = document.getElementById('iocFilterType');
  if (filterType) filterType.addEventListener('change', loadIocList);
}

async function loadIocStats() {
  try {
    const stats = await apiFetchJson('/api/ioc/stats');
    if (!stats || typeof stats !== 'object') {
      console.warn('[IOC Stats] Invalid response format');
      return;
    }
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el('iocStatTotal', stats.total || 0);
    el('iocStatIps', stats.by_type?.ip || stats.by_type?.ipv4 || 0);
    el('iocStatDomains', stats.by_type?.domain || 0);
    el('iocStatHashes', (stats.by_type?.sha256 || 0) + (stats.by_type?.md5 || 0));
    el('iocStatUrls', stats.by_type?.url || 0);
  } catch (e) {
    console.error('[IOC Stats] Failed to load:', e?.message);
    showToast(`Failed to load IOC stats: ${e?.message || 'Unknown error'}`, 'warn');
  }
}

async function loadIocList() {
  const container = document.getElementById('iocContent');
  if (!container) return;
  const filterType = document.getElementById('iocFilterType')?.value || '';
  try {
    let resp;
    try {
      resp = await apiFetchJson('/api/ioc');
    } catch (e1) {
      console.warn('[IOC List] Primary endpoint failed, trying fallback:', e1?.message);
      try {
        resp = await apiFetchJson('/api/ioc/list');
      } catch (e2) {
        throw new Error(`Both /api/ioc and /api/ioc/list failed: ${e2?.message}`);
      }
    }
    if (!resp || typeof resp !== 'object') {
      container.innerHTML = '<div class="empty-state">Invalid response from server. Try refreshing.</div>';
      return;
    }
    const iocs = Array.isArray(resp) ? resp : (Array.isArray(resp?.iocs) ? resp.iocs : []);
    if (!Array.isArray(iocs)) {
      container.innerHTML = '<div class="empty-state">Invalid IOC data format.</div>';
      return;
    }
    if (iocs.length === 0) {
      container.innerHTML = '<div class="empty-state">No IOCs loaded. Add indicators manually or import a STIX bundle.</div>';
      return;
    }
    const filtered = filterType ? iocs.filter(i => i.ioc_type === filterType) : iocs;
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state p-12">No IOCs matching filter.</div>';
      return;
    }
    const rows = filtered.slice(0, 200).map(i => {
      const tlpCls = (i.tlp || '').toLowerCase() === 'red' ? 'danger' : (i.tlp || '').toLowerCase() === 'amber' ? 'warn' : 'muted';
      const added = i.added ? new Date(i.added).toLocaleString() : '—';
      const expires = i.expires ? new Date(i.expires).toLocaleString() : '—';
      return `<tr>
        <td class="mono text-xs break-all">${escapeHtml(i.value || '—')}</td>
        <td>${escapeHtml(i.ioc_type || '—')}</td>
        <td><span class="${tlpCls}">${escapeHtml(i.tlp || 'white')}</span></td>
        <td class="text-xs">${escapeHtml(i.source || '—')}</td>
        <td class="text-xs">${escapeHtml(added)}</td>
        <td class="text-xs">${escapeHtml(expires)}</td>
        <td><button class="btnSm danger" data-ioc-remove="${escapeHtml(i.value || '')}">×</button></td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-400">
      <table class="tbl"><thead><tr><th>Value</th><th>Type</th><th>TLP</th><th>Source</th><th>Added</th><th>Expires</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
    container.querySelectorAll('[data-ioc-remove]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await apiPostJson('/api/ioc/remove', { value: btn.dataset.iocRemove });
          showToast('IOC removed', 'ok');
          loadIocList();
          loadIocStats();
        } catch (e) {
          console.error('[IOC Remove] Failed:', e?.message);
          showToast(`Failed to remove IOC: ${e?.message || 'Unknown error'}`, 'error');
        }
      });
    });
  } catch (e) {
    console.error('[IOC List] Failed to load:', e?.message);
    container.innerHTML = `<div class="error-state p-12">Error loading IOCs: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load IOCs: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function showAddIocDialog() {
  const html = `<div class="form-stack">
    <h3>Add IOC</h3>
    <input class="field" id="iocAddValue" placeholder="Indicator value (IP, domain, hash, URL…)" />
    <select class="inp" id="iocAddType">
      <option value="ipv4">IPv4</option><option value="ipv6">IPv6</option>
      <option value="domain">Domain</option><option value="url">URL</option>
      <option value="sha256">SHA-256</option><option value="md5">MD5</option>
      <option value="email">Email</option><option value="filename">Filename</option>
    </select>
    <select class="inp" id="iocAddTlp">
      <option value="white">TLP:WHITE</option><option value="green">TLP:GREEN</option>
      <option value="amber">TLP:AMBER</option><option value="red">TLP:RED</option>
    </select>
    <input class="field" id="iocAddSource" placeholder="Source (e.g. manual, AlienVault)" value="manual" />
    <div class="actions-end">
      <button class="btn" id="iocModalCancel">Cancel</button>
      <button class="btn accent" id="iocAddSubmit">Add</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('iocModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('iocAddSubmit')?.addEventListener('click', async () => {
    const value = document.getElementById('iocAddValue')?.value?.trim();
    const ioc_type = document.getElementById('iocAddType')?.value;
    const tlp = document.getElementById('iocAddTlp')?.value;
    const source = document.getElementById('iocAddSource')?.value?.trim() || 'manual';
    if (!value) { showToast('Indicator value required', 'error'); return; }
    try {
      await apiPostJson('/api/ioc', { value, ioc_type, tlp, source }).catch(() =>
        apiPostJson('/api/ioc/add', { value, ioc_type, tlp, source })
      );
      overlay.remove();
      showToast('IOC added', 'ok');
      loadIocList();
      loadIocStats();
    } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
  });
}

async function showImportStixDialog() {
  const html = `<div class="form-stack">
    <h3>Import STIX 2.1 Bundle</h3>
    <textarea class="field mono text-xs" id="stixBundleInput" rows="10" placeholder='Paste STIX 2.1 JSON bundle here…'></textarea>
    <div class="actions-end">
      <button class="btn" id="stixModalCancel">Cancel</button>
      <button class="btn accent" id="stixImportSubmit">Import</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-lg">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('stixModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('stixImportSubmit')?.addEventListener('click', async () => {
    try {
      const bundle = JSON.parse(document.getElementById('stixBundleInput').value);
      const resp = await apiPostJson('/api/ioc/import', bundle).catch(() =>
        apiPostJson('/api/ioc/import_stix', bundle)
      );
      overlay.remove();
      showToast(`Imported ${resp.count || resp.imported || 0} IOCs`, 'ok');
      loadIocList();
      loadIocStats();
    } catch (e) { showToast('Import failed: ' + (e.message || 'Invalid JSON'), 'error'); }
  });
}
