// ═══════════════════════════════════════════════════════════════
//  Vulnerabilities pane controller
// ═══════════════════════════════════════════════════════════════

function initVulnerabilitiesPane() {
	loadVulnerabilityStats();
	loadVulnerabilities();
	const refreshBtn = document.getElementById('vulnRefreshBtn');
	if (refreshBtn) refreshBtn.addEventListener('click', () => {
		loadVulnerabilityStats();
		loadVulnerabilities();
	});
	const addBtn = document.getElementById('vulnAddBtn');
	if (addBtn) addBtn.addEventListener('click', showCreateVulnerabilityDialog);
}

async function loadVulnerabilityStats() {
	const container = document.getElementById('vulnStatsContent');
	if (!container) return;
	container.innerHTML = '<div class="loading-state p-12">Loading vulnerability stats…</div>';
	try {
		const stats = await apiFetchJson('/api/vulnerabilities/stats');
		container.innerHTML = `<div class="miniStatRow">
			<span class="chip">Total: <strong>${Number(stats?.total || 0)}</strong></span>
			<span class="chip">Critical: <strong>${Number(stats?.critical || 0)}</strong></span>
			<span class="chip">High: <strong>${Number(stats?.high || 0)}</strong></span>
			<span class="chip">Open: <strong>${Number(stats?.open || 0)}</strong></span>
		</div>`;
	} catch {
		container.innerHTML = '<div class="error-state p-12">Unable to load vulnerability stats.</div>';
	}
}

async function loadVulnerabilities() {
	const container = document.getElementById('vulnContent');
	if (!container) return;
	container.innerHTML = '<div class="loading-state p-16">Loading vulnerabilities…</div>';
	try {
		const resp = await apiFetchJson('/api/vulnerabilities');
		const list = Array.isArray(resp?.vulnerabilities) ? resp.vulnerabilities : [];
		if (list.length === 0) {
			container.innerHTML = '<div class="empty-state p-16">No vulnerabilities tracked.</div>';
			return;
		}
		const rows = list.map((v) => {
			const cve = String(v.cve_id || v.cve || '—');
			const sev = String(v.severity || 'unknown').toLowerCase();
			const sevCls = sev === 'critical' ? 'danger' : sev === 'high' ? 'warn' : sev === 'medium' ? 'info' : 'muted';
			const host = String(v.hostname || v.asset || v.target || '—');
			const status = String(v.status || 'open');
			return `<tr>
				<td><button class="btnSm" data-vuln-cve="${escapeHtml(cve)}">${escapeHtml(cve)}</button></td>
				<td><span class="${sevCls}">${escapeHtml(sev)}</span></td>
				<td>${escapeHtml(host)}</td>
				<td>${escapeHtml(status)}</td>
				<td class="text-12">${escapeHtml(v.updated_at ? new Date(v.updated_at).toLocaleString() : '—')}</td>
			</tr>`;
		}).join('');
		container.innerHTML = `<div class="tableWrap maxh-400">
			<table class="tbl"><thead><tr><th>CVE</th><th>Severity</th><th>Asset</th><th>Status</th><th>Updated</th></tr></thead>
			<tbody>${rows}</tbody></table></div>`;

		container.querySelectorAll('[data-vuln-cve]').forEach((btn) => {
			btn.addEventListener('click', () => showVulnerabilityDetails(btn.dataset.vulnCve));
		});
	} catch (e) {
		container.innerHTML = `<div class="error-state p-16">Error: ${escapeHtml(e?.message || 'unknown')}</div>`;
	}
}

async function showVulnerabilityDetails(cveId) {
	if (!cveId) return;
	try {
		const detail = await apiFetchJson(`/api/vulnerabilities/${encodeURIComponent(cveId)}`);
		const payload = detail?.vulnerability || detail || {};
		const summary = payload.summary || payload.description || 'No details available.';
		const cvss = payload.cvss || payload.cvss_score || '—';
		const refs = Array.isArray(payload.references) ? payload.references.slice(0, 8) : [];
		const refsHtml = refs.map((r) => `<li><a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(r)}</a></li>`).join('');

		const overlay = document.createElement('div');
		overlay.className = 'modal-overlay';
		overlay.innerHTML = `<div class="modal-content vuln-modal-lg">
			<h3 class="vuln-modal-title">${escapeHtml(cveId)}</h3>
			<div class="muted mb-10">CVSS: <strong>${escapeHtml(String(cvss))}</strong></div>
			<div class="vuln-summary">${escapeHtml(summary)}</div>
			${refsHtml ? `<h4 class="vuln-refs-title">References</h4><ul>${refsHtml}</ul>` : ''}
			<div class="actions-end mt-8"><button class="btn" id="vulnCloseBtn">Close</button></div>
		</div>`;
		document.body.appendChild(overlay);
		const close = () => { try { overlay.remove(); } catch {} };
		overlay.addEventListener('click', (ev) => { if (ev.target === overlay) close(); });
		overlay.querySelector('#vulnCloseBtn')?.addEventListener('click', close);
	} catch (e) {
		showToast(`Failed to load ${cveId}: ${e?.message || 'error'}`, 'danger');
	}
}

function showCreateVulnerabilityDialog() {
	const overlay = document.createElement('div');
	overlay.className = 'modal-overlay';
	overlay.innerHTML = `<div class="modal-content modal-content-md">
		<h3 class="vuln-modal-title">Add Vulnerability</h3>
		<div class="form-stack">
			<input id="vulnCveId" class="field" placeholder="CVE-YYYY-NNNN" />
			<input id="vulnHost" class="field" placeholder="Asset / Hostname" />
			<select id="vulnSeverity" class="field">
				<option value="low">low</option>
				<option value="medium">medium</option>
				<option value="high">high</option>
				<option value="critical">critical</option>
			</select>
			<textarea id="vulnSummary" class="field" rows="4" placeholder="Summary"></textarea>
			<div class="actions-end">
				<button class="btn" id="vulnCancel">Cancel</button>
				<button class="btn primary" id="vulnCreate">Create</button>
			</div>
		</div>
	</div>`;
	document.body.appendChild(overlay);
	const close = () => { try { overlay.remove(); } catch {} };
	overlay.addEventListener('click', (ev) => { if (ev.target === overlay) close(); });
	overlay.querySelector('#vulnCancel')?.addEventListener('click', close);
	overlay.querySelector('#vulnCreate')?.addEventListener('click', async () => {
		const cve_id = String(overlay.querySelector('#vulnCveId')?.value || '').trim();
		const hostname = String(overlay.querySelector('#vulnHost')?.value || '').trim();
		const severity = String(overlay.querySelector('#vulnSeverity')?.value || 'medium').trim();
		const summary = String(overlay.querySelector('#vulnSummary')?.value || '').trim();
		if (!cve_id) {
			showToast('CVE ID is required', 'warn');
			return;
		}
		try {
			await apiPostJson('/api/vulnerabilities', { cve_id, hostname, severity, summary });
			showToast('Vulnerability added', 'ok');
			close();
			loadVulnerabilityStats();
			loadVulnerabilities();
		} catch (e) {
			showToast(`Create failed: ${e?.message || 'error'}`, 'danger');
		}
	});
}
