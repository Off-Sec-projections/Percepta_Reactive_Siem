// ═══════════════════════════════════════════════════════════════
//  Saved Searches pane controller
// ═══════════════════════════════════════════════════════════════

function initSavedSearchesPane() {
	loadSavedSearches();
	const refreshBtn = document.getElementById('savedSearchesRefreshBtn');
	if (refreshBtn) refreshBtn.addEventListener('click', loadSavedSearches);
	const newBtn = document.getElementById('savedSearchesNewBtn');
	if (newBtn) newBtn.addEventListener('click', showSavedSearchDialog);
}

async function loadSavedSearches() {
	const container = document.getElementById('savedSearchesContent');
	if (!container) return;
	try {
		const resp = await apiFetchJson('/api/saved_searches');
		const list = Array.isArray(resp?.saved_searches) ? resp.saved_searches : [];
		if (list.length === 0) {
			container.innerHTML = '<div class="muted p-16 ta-center">No saved searches yet.</div>';
			return;
		}
		const rows = list.map((s, idx) => {
			const name = s.name || s.title || `Search ${idx + 1}`;
			const query = s.query || s.q || '';
			const created = s.created_at || s.created || '';
			return `<tr>
				<td><strong>${escapeHtml(String(name))}</strong></td>
				<td class="mono text-xs">${escapeHtml(String(query))}</td>
				<td class="text-xs">${escapeHtml(created ? new Date(created).toLocaleString() : '—')}</td>
				<td class="nowrap">
					<button class="btnSm" data-ss-apply="${idx}">Apply</button>
					<button class="btnSm danger" data-ss-del="${idx}">Delete</button>
				</td>
			</tr>`;
		}).join('');
		container.innerHTML = `<div class="tableWrap maxh-340">
			<table class="tbl"><thead><tr><th>Name</th><th>Query</th><th>Created</th><th></th></tr></thead>
			<tbody>${rows}</tbody></table></div>`;

		container.querySelectorAll('[data-ss-apply]').forEach((btn) => {
			btn.addEventListener('click', () => {
				const i = Number(btn.dataset.ssApply);
				const item = list[i] || {};
				const q = String(item.query || item.q || '').trim();
				// Apply to global search
				const inp = document.getElementById('globalSearch');
				if (inp) {
					inp.value = q;
					inp.dispatchEvent(new Event('input', { bubbles: true }));
				}
				// Also apply to hunt query bar if visible
				const huntInp = document.getElementById('huntQueryInput');
				if (huntInp) {
					huntInp.value = q;
					if (typeof _applyHuntQuery === 'function') _applyHuntQuery();
				}
				try { setView('events'); } catch {}
				if (q) showToast(`Applied saved search: ${item.name || item.title || 'query'}`, 'ok');
			});
		});
		container.querySelectorAll('[data-ss-del]').forEach((btn) => {
			btn.addEventListener('click', async () => {
				const i = Number(btn.dataset.ssDel);
				const item = list[i] || {};
				const name = item.name || item.title || '';
				const q = item.query || item.q || '';
				try {
					await apiPostJson('/api/saved_searches/delete', { name, query: q, id: item.id });
					showToast('Saved search deleted', 'ok');
					loadSavedSearches();
				} catch (e) {
					showToast(`Delete failed: ${e?.message || 'error'}`, 'danger');
				}
			});
		});
	} catch (e) {
		container.innerHTML = `<div class="muted p-16 ta-center">Error loading saved searches: ${escapeHtml(e?.message || 'unknown')}</div>`;
	}
}

function showSavedSearchDialog() {
	const overlay = document.createElement('div');
	overlay.className = 'modal-overlay';
	overlay.innerHTML = `<div class="modal-content modal-content-md">
		<h3>Save Search</h3>
		<div class="form-stack">
			<input id="ssName" class="field" placeholder="Name" />
			<textarea id="ssQuery" class="field mono text-xs" rows="5" placeholder="Query"></textarea>
			<div class="actions-end">
				<button class="btn" id="ssCancel">Cancel</button>
				<button class="btn primary" id="ssSave">Save</button>
			</div>
		</div>
	</div>`;
	document.body.appendChild(overlay);

	const q = document.getElementById('globalSearch')?.value || '';
	const queryEl = overlay.querySelector('#ssQuery');
	if (queryEl) queryEl.value = q;

	const close = () => {
		try { overlay.remove(); } catch {}
	};
	overlay.addEventListener('click', (ev) => {
		if (ev.target === overlay) close();
	});
	overlay.querySelector('#ssCancel')?.addEventListener('click', close);
	overlay.querySelector('#ssSave')?.addEventListener('click', async () => {
		const name = String(overlay.querySelector('#ssName')?.value || '').trim();
		const query = String(overlay.querySelector('#ssQuery')?.value || '').trim();
		if (!name || !query) {
			showToast('Name and query are required', 'warn');
			return;
		}
		try {
			await apiPostJson('/api/saved_searches', { name, query });
			showToast('Saved search created', 'ok');
			close();
			loadSavedSearches();
		} catch (e) {
			showToast(`Save failed: ${e?.message || 'error'}`, 'danger');
		}
	});
}
