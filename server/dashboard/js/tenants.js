// ═══════════════════════════════════════════════════════════════
//  Tenants pane controller (local tenant context)
// ═══════════════════════════════════════════════════════════════

const TENANTS_STORAGE_KEY = 'percepta.tenants.v1';
const ACTIVE_TENANT_STORAGE_KEY = 'percepta.tenants.active.v1';

function initTenantsPane() {
	renderTenants();
	const refreshBtn = document.getElementById('tenantsRefreshBtn');
	if (refreshBtn) refreshBtn.addEventListener('click', renderTenants);
	const addBtn = document.getElementById('tenantsAddBtn');
	if (addBtn) addBtn.addEventListener('click', showAddTenantDialog);
}

function readTenants() {
	try {
		const raw = localStorage.getItem(TENANTS_STORAGE_KEY);
		const arr = JSON.parse(raw || '[]');
		return Array.isArray(arr) ? arr : [];
	} catch {
		return [];
	}
}

function writeTenants(items) {
	try {
		localStorage.setItem(TENANTS_STORAGE_KEY, JSON.stringify(Array.isArray(items) ? items : []));
	} catch {}
}

function getActiveTenantId() {
	try {
		return String(localStorage.getItem(ACTIVE_TENANT_STORAGE_KEY) || '').trim();
	} catch {
		return '';
	}
}

function setActiveTenantId(id) {
	try {
		localStorage.setItem(ACTIVE_TENANT_STORAGE_KEY, String(id || ''));
	} catch {}
}

function renderTenants() {
	const container = document.getElementById('tenantsContent');
	if (!container) return;
	const tenants = readTenants();
	const activeId = getActiveTenantId();

	if (tenants.length === 0) {
		container.innerHTML = '<div class="empty-state p-16">No tenants defined yet. Add one to segment investigations and saved filters.</div>';
		return;
	}

	const rows = tenants.map((t, idx) => {
		const id = String(t.id || `tenant-${idx + 1}`);
		const active = id === activeId;
		return `<tr>
			<td><strong>${escapeHtml(String(t.name || id))}</strong></td>
			<td class="text-12">${escapeHtml(id)}</td>
			<td class="text-12">${escapeHtml(String(t.description || '—'))}</td>
			<td>${active ? '<span class="ok">Active</span>' : '<span class="muted">Inactive</span>'}</td>
			<td class="nowrap">
				<button class="btnSm" data-tenant-activate="${escapeHtml(id)}">Activate</button>
				<button class="btnSm danger" data-tenant-del="${escapeHtml(id)}">Delete</button>
			</td>
		</tr>`;
	}).join('');

	container.innerHTML = `<div class="tableWrap maxh-340">
		<table class="tbl"><thead><tr><th>Name</th><th>ID</th><th>Description</th><th>Status</th><th></th></tr></thead>
		<tbody>${rows}</tbody></table></div>`;

	container.querySelectorAll('[data-tenant-activate]').forEach((btn) => {
		btn.addEventListener('click', () => {
			const id = btn.dataset.tenantActivate;
			setActiveTenantId(id);
			try { state.activeTenant = id; } catch {}
			showToast(`Active tenant: ${id}`, 'ok');
			renderTenants();
		});
	});
	container.querySelectorAll('[data-tenant-del]').forEach((btn) => {
		btn.addEventListener('click', async () => {
			const id = btn.dataset.tenantDel;
			const ok = await uiConfirm(`Delete tenant '${id}' from local browser storage?`, { danger: true });
			if (!ok) return;
			const next = readTenants().filter((t) => String(t.id || '') !== id);
			writeTenants(next);
			if (getActiveTenantId() === id) setActiveTenantId('');
			showToast('Tenant deleted', 'ok');
			renderTenants();
		});
	});
}

function showAddTenantDialog() {
	const overlay = document.createElement('div');
	overlay.className = 'modal-overlay';
	overlay.innerHTML = `<div class="modal-content modal-content-md">
		<h3 class="pane-dialog-title">Add Tenant</h3>
		<div class="form-stack">
			<input id="tenantName" class="field" placeholder="Tenant Name" />
			<input id="tenantId" class="field" placeholder="tenant-id" />
			<textarea id="tenantDesc" class="field" rows="4" placeholder="Description"></textarea>
			<div class="actions-end">
				<button class="btn" id="tenantCancel">Cancel</button>
				<button class="btn primary" id="tenantSave">Save</button>
			</div>
		</div>
	</div>`;
	document.body.appendChild(overlay);
	const close = () => { try { overlay.remove(); } catch {} };
	overlay.addEventListener('click', (ev) => { if (ev.target === overlay) close(); });
	overlay.querySelector('#tenantCancel')?.addEventListener('click', close);
	overlay.querySelector('#tenantSave')?.addEventListener('click', () => {
		const name = String(overlay.querySelector('#tenantName')?.value || '').trim();
		const idRaw = String(overlay.querySelector('#tenantId')?.value || '').trim();
		const id = idRaw || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
		const description = String(overlay.querySelector('#tenantDesc')?.value || '').trim();
		if (!name || !id) {
			showToast('Tenant name and id are required', 'warn');
			return;
		}
		const list = readTenants();
		if (list.some((t) => String(t.id || '') === id)) {
			showToast('Tenant ID already exists', 'warn');
			return;
		}
		list.push({ id, name, description, created_at: new Date().toISOString() });
		writeTenants(list);
		showToast('Tenant added', 'ok');
		close();
		renderTenants();
	});
}
