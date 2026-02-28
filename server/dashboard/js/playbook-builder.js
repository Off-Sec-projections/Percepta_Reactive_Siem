// ═══════════════════════════════════════════════════════════════
//  Playbook Builder helpers (advanced authoring facade)
// ═══════════════════════════════════════════════════════════════

function initPlaybookBuilderPane() {
	loadPlaybookBuilderCatalog();
	const refreshBtn = document.getElementById('pbBuilderRefreshBtn');
	if (refreshBtn) refreshBtn.addEventListener('click', loadPlaybookBuilderCatalog);
	const createBtn = document.getElementById('pbBuilderCreateBtn');
	if (createBtn) createBtn.addEventListener('click', () => openPlaybookBuilderWizard(null));
}

async function loadPlaybookBuilderCatalog() {
	const container = document.getElementById('pbBuilderContent');
	if (!container) return;
	try {
		const list = await apiFetchJson('/api/playbooks');
		const playbooks = Array.isArray(list) ? list : [];
		if (playbooks.length === 0) {
			container.innerHTML = '<div class="empty-state p-16">No playbooks defined. Create one from the builder.</div>';
			return;
		}
		const cards = playbooks.map((pb) => {
			const triggerCount = Array.isArray(pb.trigger_conditions) ? pb.trigger_conditions.length : 0;
			const actionCount = Array.isArray(pb.actions) ? pb.actions.length : 0;
			const enabled = pb.enabled !== false;
			return `<div class="miniCard p-12 mb-10">
				<div class="pane-card-row">
					<strong>${escapeHtml(pb.name || pb.id || 'unnamed')}</strong>
					<span class="${enabled ? 'ok' : 'muted'}">${enabled ? 'Enabled' : 'Disabled'}</span>
				</div>
				<div class="muted pane-subnote">Triggers: ${triggerCount} • Actions: ${actionCount}</div>
				<div class="pane-actions-row">
					<button class="btnSm" data-pbb-edit="${escapeHtml(pb.id || '')}">Open Builder</button>
					<button class="btnSm" data-pbb-legacy="${escapeHtml(pb.id || '')}">Legacy Editor</button>
				</div>
			</div>`;
		}).join('');

		container.innerHTML = cards;
		container.querySelectorAll('[data-pbb-edit]').forEach((btn) => {
			btn.addEventListener('click', () => {
				const id = btn.dataset.pbbEdit;
				const pb = playbooks.find((x) => String(x.id || '') === id);
				openPlaybookBuilderWizard(pb || null);
			});
		});
		container.querySelectorAll('[data-pbb-legacy]').forEach((btn) => {
			btn.addEventListener('click', () => {
				const id = btn.dataset.pbbLegacy;
				const pb = playbooks.find((x) => String(x.id || '') === id);
				if (pb) showPlaybookEditor(pb);
			});
		});
	} catch (e) {
		container.innerHTML = `<div class="error-state p-16">Error loading playbooks: ${escapeHtml(e?.message || 'unknown')}</div>`;
	}
}

function openPlaybookBuilderWizard(existing) {
	const pb = existing || {
		name: '',
		enabled: true,
		trigger_conditions: [{ field: 'event.kind', operator: 'contains', value: '' }],
		actions: [{ action_type: 'notify', params: {} }],
	};

	const overlay = document.createElement('div');
	overlay.className = 'modal-overlay';
	overlay.innerHTML = `<div class="modal-content vuln-modal-lg">
		<h3 class="pane-dialog-title">${existing ? 'Edit Playbook' : 'Create Playbook'}</h3>
		<div class="pane-dialog-grid-two">
			<div class="pane-dialog-span-full"><input id="pbbName" class="field" placeholder="Playbook Name" value="${escapeHtml(pb.name || '')}" /></div>
			<label class="pane-check-label"><input id="pbbEnabled" type="checkbox" ${pb.enabled !== false ? 'checked' : ''}/> Enabled</label>
			<div></div>
			<div>
				<label class="muted pane-field-label">Trigger Field</label>
				<input id="pbbField" class="field" value="${escapeHtml(pb.trigger_conditions?.[0]?.field || 'event.kind')}" />
			</div>
			<div>
				<label class="muted pane-field-label">Trigger Value</label>
				<input id="pbbValue" class="field" value="${escapeHtml(pb.trigger_conditions?.[0]?.value || '')}" />
			</div>
			<div>
				<label class="muted pane-field-label">Action</label>
				<select id="pbbAction" class="field">
					<option value="notify">notify</option>
					<option value="block_ip">block_ip</option>
					<option value="block_user">block_user</option>
					<option value="isolate_host">isolate_host</option>
					<option value="webhook">webhook</option>
				</select>
			</div>
			<div>
				<label class="muted pane-field-label">Action Parameter</label>
				<input id="pbbActionParam" class="field" placeholder="optional" />
			</div>
		</div>
		<div class="pane-dialog-actions">
			<button class="btn" id="pbbCancel">Cancel</button>
			<button class="btn" id="pbbOpenLegacy">Open Legacy JSON Editor</button>
			<button class="btn primary" id="pbbSave">Save</button>
		</div>
	</div>`;
	document.body.appendChild(overlay);

	const actionSelect = overlay.querySelector('#pbbAction');
	const currentAction = String(pb.actions?.[0]?.action_type || pb.actions?.[0]?.type || 'notify');
	if (actionSelect) actionSelect.value = currentAction;
	const actionParamEl = overlay.querySelector('#pbbActionParam');
	if (actionParamEl) {
		const params = pb.actions?.[0]?.params || {};
		actionParamEl.value = String(params?.value || params?.target || params?.message || '');
	}

	const close = () => { try { overlay.remove(); } catch {} };
	overlay.addEventListener('click', (ev) => { if (ev.target === overlay) close(); });
	overlay.querySelector('#pbbCancel')?.addEventListener('click', close);
	overlay.querySelector('#pbbOpenLegacy')?.addEventListener('click', () => {
		close();
		showPlaybookEditor(existing || null);
	});
	overlay.querySelector('#pbbSave')?.addEventListener('click', async () => {
		const name = String(overlay.querySelector('#pbbName')?.value || '').trim();
		const enabled = !!overlay.querySelector('#pbbEnabled')?.checked;
		const field = String(overlay.querySelector('#pbbField')?.value || '').trim();
		const value = String(overlay.querySelector('#pbbValue')?.value || '').trim();
		const action_type = String(overlay.querySelector('#pbbAction')?.value || 'notify').trim();
		const actionValue = String(overlay.querySelector('#pbbActionParam')?.value || '').trim();

		if (!name || !field || !value) {
			showToast('Name, trigger field, and trigger value are required', 'warn');
			return;
		}

		const body = {
			id: existing?.id,
			name,
			enabled,
			trigger_conditions: [{ field, operator: 'contains', value }],
			actions: [{ action_type, params: actionValue ? { value: actionValue } : {} }],
		};

		try {
			await apiPostJson('/api/playbooks/upsert', body);
			showToast(existing ? 'Playbook updated' : 'Playbook created', 'ok');
			close();
			loadPlaybookBuilderCatalog();
			try { loadPlaybooks(); } catch {}
		} catch (e) {
			showToast(`Save failed: ${e?.message || 'error'}`, 'danger');
		}
	});
}
