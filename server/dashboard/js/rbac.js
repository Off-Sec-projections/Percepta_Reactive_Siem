// ═══════════════════════════════════════════════════════════════
//  RBAC — Users & Roles management pane controller
// ═══════════════════════════════════════════════════════════════

function initRbacPane() {
  loadRbacUsers();
  loadRbacRoles();
  const refreshBtn = document.getElementById('rbacRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => { loadRbacUsers(); loadRbacRoles(); });
  const newUserBtn = document.getElementById('rbacNewUserBtn');
  if (newUserBtn) newUserBtn.addEventListener('click', showCreateRbacUserDialog);
  const newRoleBtn = document.getElementById('rbacNewRoleBtn');
  if (newRoleBtn) newRoleBtn.addEventListener('click', showCreateRbacRoleDialog);
}

async function loadRbacUsers() {
  const container = document.getElementById('rbacUsersContent');
  if (!container) return;
  try {
    const resp = await apiFetchJson('/api/rbac/users');
    const users = Array.isArray(resp) ? resp : (resp?.users || []);
    if (users.length === 0) {
      container.innerHTML = '<div class="muted rbac-state-msg">No RBAC users configured.</div>';
      return;
    }
    const rows = users.map(u => {
      const role = u.role_id || u.role || (Array.isArray(u.roles) ? u.roles.join(', ') : '—');
      const enabled = u.enabled !== false;
      const statusCls = enabled ? 'ok' : 'muted';
      const toggleLabel = enabled ? 'Disable' : 'Enable';
      const toggleCls = enabled ? 'btn-danger-small' : 'btn-ok-small';
      return `<tr>
        <td><strong>${escapeHtml(u.username || '—')}</strong></td>
        <td>${escapeHtml(u.display_name || u.username || '—')}</td>
        <td>${escapeHtml(role)}</td>
        <td><span class="${statusCls}">${enabled ? 'Active' : 'Disabled'}</span></td>
        <td class="rbac-user-last-login">${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
        <td class="rbac-user-actions">
          <button class="btn btn-xs" data-action="password" data-username="${escapeHtml(u.username)}">Password</button>
          <button class="btn btn-xs" data-action="role" data-username="${escapeHtml(u.username)}" data-role="${escapeHtml(role)}">Role</button>
          <button class="btn btn-xs ${toggleCls}" data-action="toggle" data-username="${escapeHtml(u.username)}" data-enabled="${enabled}">${toggleLabel}</button>
        </td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-400">
      <table class="tbl"><thead><tr><th>Username</th><th>Display Name</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;

    // Event delegation for user action buttons
    container.addEventListener('click', async (ev) => {
      const btn = ev.target.closest('[data-action]');
      if (!btn) return;
      const action = btn.dataset.action;
      const username = btn.dataset.username;
      if (!username) return;

      if (action === 'password') {
        showChangePasswordDialog(username);
      } else if (action === 'role') {
        const currentRole = btn.dataset.role;
        showChangeRoleDialog(username, currentRole);
      } else if (action === 'toggle') {
        const currentEnabled = btn.dataset.enabled === 'true';
        toggleUserEnabled(username, !currentEnabled);
      }
    });
  } catch (e) {
    console.error('[RBAC Users] Failed to load:', e?.message);
    container.innerHTML = `<div class="error-state">Error loading users: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load RBAC users: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function loadRbacRoles() {
  const container = document.getElementById('rbacRolesContent');
  if (!container) return;
  try {
    const resp = await apiFetchJson('/api/rbac/roles');
    const roles = Array.isArray(resp) ? resp : (resp?.roles || []);
    if (roles.length === 0) {
      container.innerHTML = '<div class="muted rbac-state-msg">No roles defined.</div>';
      return;
    }
    const cards = roles.map(r => {
      const perms = Array.isArray(r.permissions) ? r.permissions : [];
      const permPills = perms.slice(0, 8).map(p => `<span class="chip muted rbac-chip-tiny">${escapeHtml(p)}</span>`).join(' ');
      const more = perms.length > 8 ? ` <span class="muted rbac-chip-tiny">+${perms.length - 8} more</span>` : '';
      const builtIn = r.is_builtin ? '<span class="chip rbac-chip-tiny">Built-in</span>' : '';
      return `<div class="miniCard rbac-role-card">
        <div class="rbac-role-header">
          <strong>${escapeHtml(r.name || r.id)}</strong> ${builtIn}
        </div>
        <div class="rbac-role-desc">${escapeHtml(r.description || '')}</div>
        <div class="rbac-role-perms">${permPills}${more}</div>
      </div>`;
    }).join('');
    container.innerHTML = `<div class="rbac-roles-list">${cards}</div>`;
  } catch (e) {
    console.error('[RBAC Roles] Failed to load:', e?.message);
    container.innerHTML = `<div class="error-state">Error loading roles: ${escapeHtml(e?.message || 'Unknown error')}</div>`;
    showToast(`Failed to load RBAC roles: ${e?.message || 'Unknown error'}`, 'error');
  }
}

async function showCreateRbacUserDialog() {
  let rolesOpts = '';
  try {
    let resp;
    try {
      resp = await apiFetchJson('/api/rbac/roles');
    } catch (e) {
      console.warn('[RBAC Create User] Failed to load roles:', e?.message);
      throw e;
    }
    const roles = Array.isArray(resp) ? resp : (resp?.roles || []);
    // IMPORTANT: backend expects role_id to be the role's ID (e.g. "administrator"),
    // not the display name (e.g. "Administrator"). Sending the name causes 409.
    if (roles.length > 0) {
      rolesOpts = roles
        .map(r => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.name || r.id)}</option>`)
        .join('');
    }
  } catch (e) {
    console.error('[RBAC Roles Load] Error:', e?.message);
    showToast(`Warning: Could not load roles for user creation: ${e?.message}`, 'warn');
  }
  const html = `<div class="form-stack">
    <h3 class="rbac-modal-title">Create RBAC User</h3>
    <input class="field" id="rbacNewUsername" placeholder="Username" />
    <input class="field" id="rbacNewEmail" placeholder="Email" type="email" />
    <input class="field" id="rbacNewPassword" placeholder="Password" type="password" />
    <select class="field" id="rbacNewRole">${rolesOpts}</select>
    <div class="actions-end">
      <button class="btn" id="rbacModalCancel">Cancel</button>
      <button class="btn accent" id="rbacCreateUserSubmit">Create</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('rbacModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('rbacCreateUserSubmit')?.addEventListener('click', async () => {
    const username = document.getElementById('rbacNewUsername')?.value?.trim();
    const email = document.getElementById('rbacNewEmail')?.value?.trim();
    const password = document.getElementById('rbacNewPassword')?.value;
    const role = document.getElementById('rbacNewRole')?.value;
    if (!username || !password) { showToast('Username and password required', 'error'); return; }
    try {
      await apiPostJson('/api/rbac/users', { username, password, display_name: username, role_id: role });
      overlay.remove();
      showToast('User created', 'ok');
      loadRbacUsers();
    } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
  });
}

async function showCreateRbacRoleDialog() {
  let permsOpts = '';
  try {
    let perms;
    try {
      perms = await apiFetchJson('/api/rbac/permissions');
    } catch (e1) {
      console.warn('[RBAC Create Role] Primary permissions endpoint failed, trying fallback:', e1?.message);
      try {
        perms = await apiFetchJson('/api/rbac/me/permissions');
      } catch (e2) {
        throw new Error(`Both permissions endpoints failed: ${e2?.message}`);
      }
    }
    const list = Array.isArray(perms) ? perms : (Array.isArray(perms?.permissions) ? perms.permissions : []);
    if (list.length > 0) permsOpts = list.map(p => `<label class="rbac-perm-option"><input type="checkbox" value="${escapeHtml(p)}" class="rbacPermCheck" /> ${escapeHtml(p)}</label>`).join('');
  } catch (e) {
    console.error('[RBAC Permissions Load] Error:', e?.message);
    showToast(`Warning: Could not load permissions for role creation: ${e?.message}`, 'warn');
  }
  const html = `<div class="form-stack">
    <h3 class="rbac-modal-title">Create Custom Role</h3>
    <input class="field" id="rbacNewRoleName" placeholder="Role name" />
    <input class="field" id="rbacNewRoleDesc" placeholder="Description" />
    <div class="rbac-perms-box">${permsOpts}</div>
    <div class="actions-end">
      <button class="btn" id="rbacModalCancel">Cancel</button>
      <button class="btn accent" id="rbacCreateRoleSubmit">Create</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('rbacModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('rbacCreateRoleSubmit')?.addEventListener('click', async () => {
    const name = document.getElementById('rbacNewRoleName')?.value?.trim();
    const description = document.getElementById('rbacNewRoleDesc')?.value?.trim();
    const permissions = Array.from(document.querySelectorAll('.rbacPermCheck:checked')).map(cb => cb.value);
    if (!name) { showToast('Role name required', 'error'); return; }
    const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
    try {
      await apiPostJson('/api/rbac/roles', { id, name, description, permissions });
      overlay.remove();
      showToast('Role created', 'ok');
      loadRbacRoles();
    } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
  });
}

// ─── User Action Dialogs ─────────────────────────────────────────────

async function showChangePasswordDialog(username) {
  const html = `<div class="form-stack">
    <h3 class="rbac-modal-title">Change Password — ${escapeHtml(username)}</h3>
    <input class="field" id="rbacNewPw" placeholder="New password" type="password" autocomplete="new-password" />
    <input class="field" id="rbacConfirmPw" placeholder="Confirm password" type="password" autocomplete="new-password" />
    <div class="actions-end">
      <button class="btn" id="rbacModalCancel">Cancel</button>
      <button class="btn accent" id="rbacPwSubmit">Save</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('rbacModalCancel')?.addEventListener('click', () => overlay.remove());
  document.getElementById('rbacPwSubmit')?.addEventListener('click', async () => {
    const pw = document.getElementById('rbacNewPw')?.value;
    const confirm = document.getElementById('rbacConfirmPw')?.value;
    if (!pw || pw.length < 8) { showToast('Password must be at least 8 characters', 'error'); return; }
    if (pw !== confirm) { showToast('Passwords do not match', 'error'); return; }
    try {
      await apiPostJson('/api/rbac/users/update', { username, password: pw });
      overlay.remove();
      showToast('Password changed — user sessions revoked', 'ok');
      loadRbacUsers();
    } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
  });
}

async function showChangeRoleDialog(username, currentRole) {
  let rolesOpts = '';
  try {
    const resp = await apiFetchJson('/api/rbac/roles');
    const roles = Array.isArray(resp) ? resp : (resp?.roles || []);
    if (roles.length > 0) rolesOpts = roles.map(r => {
      const sel = (r.id === currentRole || r.name === currentRole) ? ' selected' : '';
      return `<option value="${escapeHtml(r.id)}"${sel}>${escapeHtml(r.name || r.id)}</option>`;
    }).join('');
  } catch { /* ignore */ }
  const html = `<div class="form-stack">
    <h3 class="rbac-modal-title">Change Role — ${escapeHtml(username)}</h3>
    <select class="field" id="rbacNewRoleSelect">${rolesOpts}</select>
    <div class="actions-end">
      <button class="btn" id="rbacModalCancel">Cancel</button>
      <button class="btn accent" id="rbacRoleSubmit">Save</button>
    </div>
  </div>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-content modal-content-sm">${html}</div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('rbacRoleSubmit')?.addEventListener('click', async () => {
    const role_id = document.getElementById('rbacNewRoleSelect')?.value;
    if (!role_id) { showToast('Select a role', 'error'); return; }
    try {
      await apiPostJson('/api/rbac/users/update', { username, role_id });
      overlay.remove();
      showToast('Role updated', 'ok');
      loadRbacUsers();
    } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
  });
}

async function toggleUserEnabled(username, enable) {
  try {
    await apiPostJson('/api/rbac/users/update', { username, enabled: enable });
    showToast(`User ${username} ${enable ? 'enabled' : 'disabled'}`, 'ok');
    loadRbacUsers();
  } catch (e) { showToast('Failed: ' + (e.message || 'error'), 'error'); }
}
