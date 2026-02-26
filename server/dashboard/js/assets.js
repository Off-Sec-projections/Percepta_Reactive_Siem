// ═══════════════════════════════════════════════════════════════
//  Assets — CMDB / Asset Inventory pane controller
// ═══════════════════════════════════════════════════════════════

function initAssetsPane() {
  loadAssets();
  loadAssetStats();
  const refreshBtn = document.getElementById('assetsRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadAssets(); loadAssetStats(); });
  const searchInp = document.getElementById('assetsSearch');
  if (searchInp) searchInp.addEventListener('input', debounceAssetsFilter);
  const importBtn = document.getElementById('assetsImportBtn');
  if (importBtn) importBtn.addEventListener('click', showAssetImportDialog);
}

let _assetsFilterTimer = null;
function debounceAssetsFilter() {
  clearTimeout(_assetsFilterTimer);
  _assetsFilterTimer = setTimeout(filterAssetsTable, 300);
}

function filterAssetsTable() {
  const q = (document.getElementById('assetsSearch')?.value || '').toLowerCase();
  document.querySelectorAll('#assetsTableBody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

async function loadAssetStats() {
  try {
    const stats = await apiFetchJson('/api/assets/stats');
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el('assetsStatTotal', stats.total || 0);
    el('assetsStatCritical', stats.by_criticality?.critical || 0);
    el('assetsStatHigh', stats.by_criticality?.high || 0);
    el('assetsStatMedium', stats.by_criticality?.medium || 0);
    el('assetsStatLow', stats.by_criticality?.low || 0);
  } catch { /* ignore */ }
}

async function loadAssets() {
  const container = document.getElementById('assetsContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading assets…</div>';
  try {
    const assets = await apiFetchJson('/api/assets');
    if (!Array.isArray(assets) || assets.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No assets discovered yet. Assets are auto-discovered from agent check-ins or can be imported.</div>';
      return;
    }
    const rows = assets.map(a => {
      const crit = a.criticality || 'medium';
      const critCls = crit === 'critical' ? 'danger' : crit === 'high' ? 'warn' : 'muted';
      const lastSeen = a.last_seen ? new Date(a.last_seen).toLocaleString() : '—';
      const ips = Array.isArray(a.ip_addresses) ? a.ip_addresses.join(', ') : (a.ip_addresses || '—');
      return `<tr>
        <td><strong>${escapeHtml(a.hostname || '—')}</strong></td>
        <td class="text-12">${escapeHtml(ips)}</td>
        <td>${escapeHtml(a.os || '—')}</td>
        <td><span class="${critCls}">${escapeHtml(crit)}</span></td>
        <td>${escapeHtml(a.department || '—')}</td>
        <td>${escapeHtml(a.owner || '—')}</td>
        <td class="text-12">${escapeHtml(lastSeen)}</td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-500">
      <table class="tbl"><thead><tr><th>Hostname</th><th>IP Addresses</th><th>OS</th><th>Criticality</th><th>Department</th><th>Owner</th><th>Last Seen</th></tr></thead>
      <tbody id="assetsTableBody">${rows}</tbody></table></div>`;
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading assets.</div>';
  }
}

async function showAssetImportDialog() {
  const html = `<div class="form-stack">
    <h3 class="pane-dialog-title">Import Assets (JSON)</h3>
    <textarea class="field field-full mono text-12" id="assetImportData" rows="8" placeholder='[{"hostname":"web01","ip_addresses":["10.0.1.5"],"os":"Ubuntu 22.04","criticality":"high","department":"Engineering","owner":"ops-team"}]'></textarea>
    <div class="actions-end">
      <button class="btn" id="assetModalCancel">Cancel</button>
      <button class="btn accent" id="assetImportSubmit">Import</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-xl">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('assetModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('assetImportSubmit')?.addEventListener('click', async () => {
    try {
      const data = JSON.parse(document.getElementById('assetImportData').value);
      await apiPostJson('/api/assets/import', { assets: Array.isArray(data) ? data : [data] });
      overlay.remove();
      showToast('Assets imported successfully', 'ok');
      loadAssets();
      loadAssetStats();
    } catch (e) {
      showToast('Import failed: ' + (e.message || 'Invalid JSON'), 'error');
    }
  });
}
