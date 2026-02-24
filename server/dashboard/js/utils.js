    function paintSettingsAgentsThrottled() {
      const now = Date.now();
      if (now - (paintSettingsAgentsThrottled._last || 0) < 600) return;
      paintSettingsAgentsThrottled._last = now;
      paintSettingsAgents();
    }
    paintSettingsAgentsThrottled._last = 0;

    function paintSettingsAgents() {
      const host = document.getElementById('settingsAgents');
      if (!host) return;
      const summaryHost = document.getElementById('settingsAgentsSummary');

      const known = Array.isArray(state.knownAgents) ? state.knownAgents : [];
      const connectedSet = new Set((Array.isArray(state.agentIds) ? state.agentIds : []).map((x) => String(x || '').trim()).filter(Boolean));
      const nowSec = Math.floor(Date.now() / 1000);

      // Build rows for all known agents (MAC optional).
      const rows = [];
      for (const a of known) {
        const aid = String(a?.agent_id || '').trim();
        if (!aid) continue;
        const mac = normalizeMac(String(a?.mac || state.agentMacById.get(aid) || ''));
        const ord = agentOrdinalForAgentId(aid);
        if (!ord) continue;

        const label = agentLabel(aid);
        const display = String(state.agentNameById.get(aid) || a?.hostname || a?.display_name || '').trim();
        const ip = String(a?.ip || '').trim();
        const lastSeen = Number(a?.last_seen_unix || 0);
        const connected = connectedSet.has(aid);
        const ageSec = lastSeen > 0 ? Math.max(0, nowSec - lastSeen) : Number.POSITIVE_INFINITY;
        const category = connected ? 'connected' : (ageSec <= 900 ? 'stale' : 'offline');
        rows.push({ ord, aid, mac, label, display, ip, lastSeen, connected, ageSec, category });
      }

      rows.sort((a, b) => (a.ord - b.ord) || String(a.mac).localeCompare(String(b.mac)));

      // Prime device labels for the MACs we’re about to show.
      enqueueDeviceNameLookup(rows.map((r) => r.mac).filter(Boolean));

      if (summaryHost) {
        const connectedN = rows.filter((r) => r.category === 'connected').length;
        const staleN = rows.filter((r) => r.category === 'stale').length;
        const offlineN = rows.filter((r) => r.category === 'offline').length;
        summaryHost.innerHTML = `
          <div class="miniStat"><div class="k">Known</div><div class="v">${rows.length.toLocaleString()}</div></div>
          <div class="miniStat"><div class="k">Connected</div><div class="v">${connectedN.toLocaleString()}</div></div>
          <div class="miniStat"><div class="k">Stale</div><div class="v">${staleN.toLocaleString()}</div></div>
          <div class="miniStat"><div class="k">Offline</div><div class="v">${offlineN.toLocaleString()}</div></div>
        `;
      }

      const cat = String(state.settingsAgentsCategory || 'all');
      const filtered = (cat === 'all') ? rows : rows.filter((r) => r.category === cat);

      if (!filtered.length) {
        host.textContent = t('settings.agents.none');
        return;
      }

      const wrap = document.createElement('div');
      wrap.className = 'tableWrap settings-agents-table-wrap';

      const table = document.createElement('table');
      table.innerHTML = `<thead><tr>
        <th width="120">${escapeHtml(t('settings.agents.col.agent'))}</th>
        <th width="220">${escapeHtml(t('settings.agents.col.label'))}</th>
        <th width="220">${escapeHtml(t('settings.agents.col.deviceLabel'))}</th>
        <th width="190">${escapeHtml(t('settings.agents.col.mac'))}</th>
        <th width="170">${escapeHtml(t('settings.agents.col.ip'))}</th>
        <th>${escapeHtml(t('settings.agents.col.agentId'))}</th>
        <th width="80"></th>
      </tr></thead>`;

      const tbody = document.createElement('tbody');
      for (const r of filtered.slice(0, 500)) {
        const tr = document.createElement('tr');
        const agentName = t('agent.ordinal', { n: r.ord });
        const label = r.display ? `${agentName} (${r.display})` : r.label;
        const devLabel = getDeviceNameForMac(r.mac);
        const statePill = r.connected ? '<span class="ruleBadge">connected</span>' : `<span class="ruleBadge off">${escapeHtml(r.category)}</span>`;
        tr.innerHTML = `
          <td><span class="sev info">${escapeHtml(agentName)}</span> ${statePill}</td>
          <td>${escapeHtml(label)}</td>
          <td>${escapeHtml(devLabel || '—')}</td>
          <td class="mono">${escapeHtml(r.mac || '—')}</td>
          <td class="mono">${escapeHtml(r.ip || '—')}</td>
          <td class="mono">${escapeHtml(shortText(r.aid, 42))}</td>
          <td></td>
        `;
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btnDanger btnXs';
        delBtn.textContent = 'Delete';
        delBtn.title = `Remove agent ${r.aid}`;
        delBtn.addEventListener('click', async () => {
          if (!confirm(`Delete agent "${agentName}"? This removes it from the server database.`)) return;
          try {
            const resp = await fetch(`/api/agents/${encodeURIComponent(r.aid)}`, { method: 'DELETE' });
            if (!resp.ok) { const t = await resp.text(); throw new Error(t || resp.statusText); }
            // Remove from local state
            state.knownAgents = (state.knownAgents || []).filter(a => String(a?.agent_id||'').trim() !== r.aid);
            state.dirty.settings = true;
            scheduleRender();
          } catch (err) {
            showToast('Failed to delete agent: ' + (err?.message || 'Unknown error'), 'error');
          }
        });
        tr.lastElementChild.appendChild(delBtn);
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      wrap.appendChild(table);

      host.innerHTML = '';
      host.appendChild(wrap);
    }

    async function ensureFullEventByHash(hash) {
      const h = String(hash || '').trim();
      if (!h) return;
      const existing = getEventByKey(h);
      const hasCore = Boolean(existing?.event?.original_message || existing?.event?.provider || existing?.process?.name || existing?.file?.path);
      if (hasCore) return;

      const full = await fetchEventByLooseHash(h);
      if (!full) return;
      // Replace in state.events if present.
      const idx = state.events.findIndex((e) => eventKey(e) === h);
      if (idx >= 0) {
        state.events[idx] = full;
        // Refresh derived views from the updated events slice.
        state.honeypot = state.events.filter(isHoneypotEvent);
        state.ids = state.events.filter(isIdsEvent);
        state.dirty.details = true;
        scheduleRender();
      }
    }

    function clearUiLoadingOnce() {
      if (state.uiLoadingCleared) return;
      state.uiLoadingCleared = true;
      try { document.documentElement.classList.remove('ui-loading'); } catch {}
    }

    async function fetchEventByLooseHash(hash) {
      const h = String(hash || '').trim();
      if (!h) return null;
      try {
        const lookback = 168;
        const url = `${API.search}?limit=1&lookback_hours=${lookback}&q=${encodeURIComponent(h)}`;
        const payload = await apiFetchJson(url, { timeoutMs: 3500, headers: { 'Accept': 'application/json' } });
        const evs = Array.isArray(payload?.events) ? payload.events : [];
        return evs.length ? evs[0] : null;
      } catch {
        return null;
      }
    }

    function buildEscalationDetailsBox(escalation, linkedEvent) {
      const wrap = document.createElement('div');
      wrap.className = 'section';

      // Rich header with status + priority.
      const hdr = document.createElement('div');
      hdr.className = 'esc-details-header';
      hdr.innerHTML = '<h3 class="esc-details-title">Escalation Details</h3>';
      // Status badge.
      const st = String(escalation?.status || '').toLowerCase();
      const sCls = ['open','pending'].includes(st) ? 'open' : st === 'approved' ? 'approved' : st === 'rejected' ? 'rejected' : 'closed';
      const sLabel = st.charAt(0).toUpperCase() + st.slice(1);
      hdr.innerHTML += `<span class="esc-status-badge ${sCls}">${escapeHtml(sLabel || 'Unknown')}</span>`;
      // Priority badge.
      if (typeof escInferPriority === 'function') {
        const p = escInferPriority(escalation);
        const pIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
        hdr.innerHTML += `<span class="esc-priority-badge p-${p}">${pIcons[p] || ''} ${p}</span>`;
      }
      wrap.appendChild(hdr);

      // Time context.
      const timeCtx = document.createElement('div');
      timeCtx.className = 'esc-details-time';
      const ago = typeof escTimeAgo === 'function' ? escTimeAgo(escalation?.created_at) : '';
      timeCtx.innerHTML = `<span>Created: <strong class="esc-details-time-strong">${escapeHtml(formatTime(escalation?.created_at))}</strong>${ago ? ` <span class="esc-details-time-faint">(${escapeHtml(ago)})</span>` : ''}</span>`;
      if (escalation?.created_by) timeCtx.innerHTML += `<span>By: <strong class="esc-details-time-strong">${escapeHtml(escalation.created_by)}</strong></span>`;
      wrap.appendChild(timeCtx);

      const kv = document.createElement('div');
      kv.className = 'kv';
      kv.append(...kvRow('ID', escalation?.id || ''));
      if (escalation?.decision_by) kv.append(...kvRow('Decision by', escalation.decision_by));
      if (escalation?.decision_at) kv.append(...kvRow('Decision at', formatTime(escalation.decision_at)));
      if (escalation?.decision_note) kv.append(...kvRow('Decision note', escalation.decision_note));
      if (escalation?.event_hash) {
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.flexWrap = 'wrap';
        row.style.gap = '8px';
        row.style.alignItems = 'center';
        const mono = document.createElement('span');
        mono.className = 'mono';
        mono.textContent = String(escalation.event_hash);
        row.appendChild(mono);
        const b = document.createElement('button');
        b.className = 'btn sm';
        b.textContent = '🔍 Search hash';
        b.addEventListener('click', () => pivotSearch(String(escalation.event_hash), 'events'));
        row.appendChild(b);
        kv.append(...kvRow('Event hash', row));
      }
      if (escalation?.title) kv.append(...kvRow('Title', escalation.title));
      if (escalation?.description) {
        const descWrap = document.createElement('div');
        descWrap.style.cssText = 'white-space:pre-wrap; font-size:12px; line-height:1.5; max-height:200px; overflow:auto; padding:8px 10px; border:1px solid var(--stroke2); border-radius:8px; background:var(--glass);';
        descWrap.textContent = String(escalation.description);
        kv.append(...kvRow('Description', descWrap));
      }
      wrap.appendChild(kv);

      const actions = document.createElement('div');
      actions.style.cssText = 'display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; padding-top:12px; border-top:1px solid var(--stroke2);';

      const dl = document.createElement('button');
      dl.className = 'btn sm';
      dl.textContent = '📦 Download evidence bundle';
      dl.addEventListener('click', () => {
        const ts = new Date().toISOString().replaceAll(':', '-');
        const obj = { escalation, linked_event: linkedEvent || null };
        downloadText(`percepta-escalation-${escapeHtml(String(escalation?.id || 'unknown'))}-${ts}.json`, JSON.stringify(obj, null, 2), 'application/json;charset=utf-8');
      });
      actions.appendChild(dl);

      wrap.appendChild(actions);

      // Traceback pivots (safe, defensive correlation + OSINT).
      const traceSec = document.createElement('div');
      traceSec.className = 'section';
      traceSec.innerHTML = '<h3>Traceback</h3>';

      const desc = String(escalation?.description || '');
      const alertIdMatch = desc.match(/\bAlertId\s*:\s*([^\s]+)/i);
      const alertId = String(alertIdMatch?.[1] || '').trim();

      const ev = linkedEvent || {};
      const evNet = ev?.network || {};
      const evIp = String(evNet?.src_ip || evNet?.dst_ip || '').trim();
      const evUser = String(getBestUser(ev) || '').trim();
      const evAgent = String(ev?.agent?.id || ev?.agent_id || '').trim();

      const pivRow = document.createElement('div');
      pivRow.style.display = 'flex';
      pivRow.style.gap = '8px';
      pivRow.style.flexWrap = 'wrap';

      const mkPivotBtn = (label, q) => {
        const b = document.createElement('button');
        b.className = 'btn sm';
        b.textContent = label;
        b.disabled = !String(q || '').trim();
        b.addEventListener('click', () => pivotSearch(q, 'events'));
        return b;
      };

      pivRow.appendChild(mkPivotBtn('Pivot: Events for IP', evIp));
      pivRow.appendChild(mkPivotBtn('Pivot: Events for user', evUser));
      pivRow.appendChild(mkPivotBtn('Pivot: Events for agent', evAgent));
      if (alertId) pivRow.appendChild(mkPivotBtn('Pivot: Events for AlertId', alertId));
      traceSec.appendChild(pivRow);

      if (evIp) {
        const intelRow = document.createElement('div');
        intelRow.style.marginTop = '8px';
        intelRow.style.display = 'flex';
        intelRow.style.flexDirection = 'column';
        intelRow.style.gap = '8px';

        const intelTop = document.createElement('div');
        intelTop.style.display = 'flex';
        intelTop.style.alignItems = 'center';
        intelTop.style.gap = '10px';
        intelTop.style.flexWrap = 'wrap';
        intelTop.innerHTML = `<span class="mono">${escapeHtml(evIp)}</span><span class="muted">IP intel (OSINT)</span>`;
        intelRow.appendChild(intelTop);

        const intelOut = document.createElement('div');
        intelOut.className = 'muted';
        intelOut.style.fontSize = '12px';
        intelOut.textContent = t('intel.notLoaded');
        intelRow.appendChild(intelOut);

        const intelDetails = document.createElement('div');
        intelRow.appendChild(intelDetails);

        const btns = document.createElement('div');
        btns.style.display = 'flex';
        btns.style.flexWrap = 'wrap';
        btns.style.gap = '8px';

        const fetchBtn = document.createElement('button');
        fetchBtn.className = 'btn sm';
        fetchBtn.textContent = t('btn.fetchIpIntel');
        fetchBtn.addEventListener('click', async () => {
          try {
            fetchBtn.disabled = true;
            intelOut.textContent = t('common.loading');
            intelDetails.innerHTML = '';
            const resp = await apiPostJson('/api/intel/ip', { ip: evIp }, { timeoutMs: 4500 });
            const s = summarizeIpIntel(resp);
            const parts = [];
            if (s.score !== null) parts.push(t('intel.abuseScore', { score: s.score }));
            if (s.reports !== null) parts.push(t('intel.reports', { n: s.reports }));
            if (s.otxPulses !== null) parts.push(t('intel.otxPulses', { n: s.otxPulses }));
            if (!parts.length) parts.push(t('intel.noData'));
            intelOut.textContent = parts.join(' · ');
            if (resp && typeof resp === 'object') {
              const providers = resp.providers && typeof resp.providers === 'object' ? resp.providers : {};
              for (const [name, obj] of Object.entries(providers)) {
                intelDetails.appendChild(buildJsonDetails(t('intel.apiResponseTitle', { name }), obj, { open: false }));
              }
            }
          } catch {
            intelOut.textContent = t('intel.unavailable');
            intelDetails.innerHTML = '';
          } finally {
            fetchBtn.disabled = false;
          }
        });
        btns.appendChild(fetchBtn);

        for (const p of ['abuseipdb', 'otx', 'urlhaus']) {
          const u = intelUrlForIp(p, evIp);
          if (!u) continue;
          const b = document.createElement('button');
          b.className = 'btn sm';
          b.textContent = t('btn.openProvider', { name: p });
          b.addEventListener('click', () => openExternal(u));
          btns.appendChild(b);
        }

        intelRow.appendChild(btns);
        traceSec.appendChild(intelRow);
      }

      if (!evIp && !evUser && !evAgent && !alertId) {
        const m = document.createElement('div');
        m.className = 'muted';
        m.style.marginTop = '8px';
        m.textContent = t('alerts.noPivotsHint');
        traceSec.appendChild(m);
      }

      wrap.appendChild(traceSec);

      // Audit trail (reactive actions) correlated via AlertId (best-effort).
      const auditSec = document.createElement('div');
      auditSec.className = 'section';
      auditSec.innerHTML = `<h3>${escapeHtml(t('audit.title'))}</h3>`;
      const auditOut = document.createElement('div');
      auditOut.className = 'muted';
      auditOut.textContent = alertId ? t('common.loading') : t('audit.noAlertId');
      auditSec.appendChild(auditOut);
      if (alertId) {
        apiFetchJson(`/api/audit/reactive?limit=30&context_alert_id=${encodeURIComponent(alertId)}`, { timeoutMs: 3500, headers: { 'Accept': 'application/json' } })
          .then((resp) => {
            const entries = Array.isArray(resp?.entries) ? resp.entries : [];
            if (!entries.length) {
              auditOut.textContent = t('audit.none');
              return;
            }
            auditOut.innerHTML = '';
            const list = document.createElement('div');
            list.style.display = 'flex';
            list.style.flexDirection = 'column';
            list.style.gap = '6px';
            for (const e of entries.slice(0, 30)) {
              const row = document.createElement('div');
              row.className = 'kv';
              const ts = Number(e?.ts_unix || 0) * 1000;
              const t = ts ? new Date(ts).toLocaleString() : '';
              const who = String(e?.actor || '');
              const act = String(e?.action || '');
              const tgt = `${String(e?.target_type || '')}:${String(e?.target_value || '')}`;
              const ok = (e?.ok === true);
              row.innerHTML = `<span class="muted">${escapeHtml(t)}</span><span><span class="mono">${escapeHtml(who)}</span> · ${escapeHtml(act)} · <span class="mono">${escapeHtml(tgt)}</span>${ok ? '' : ` · ${escapeHtml(t('audit.failed'))}`}</span>`;
              list.appendChild(row);
            }
            auditOut.appendChild(list);
          })
          .catch(() => {
            auditOut.textContent = t('audit.unavailable');
          });
      }
      wrap.appendChild(auditSec);

      const forensics = document.createElement('div');
      forensics.className = 'section';
      forensics.innerHTML = `<h3>${escapeHtml(t('forensics.title'))}</h3>`;
      const host = document.createElement('div');
      host.innerHTML = linkedEvent ? '' : `<div class="muted">${escapeHtml(t('forensics.noneLinked'))}</div>`;
      host.id = `escEv_${String(escalation?.id || '').replaceAll(/[^a-zA-Z0-9_-]/g, '_')}`;
      forensics.appendChild(host);
      wrap.appendChild(forensics);

      if (linkedEvent) {
        // Re-use the existing rich event details renderer into our container.
        const tmpId = host.id;
        paintEventDetails(tmpId, linkedEvent);
      }

      return wrap;
    }

    function loadAgentOrdinals() {
      const raw = storageGetJson('percepta.agent_ordinals.v1', null);
      if (!raw || typeof raw !== 'object') return;
      const next = Number(raw.next || 1);
      const byKey = raw.byKey && typeof raw.byKey === 'object' ? raw.byKey : {};
      state.agentOrdinal.next = Number.isFinite(next) && next > 0 ? next : 1;
      state.agentOrdinal.byKey = new Map(Object.entries(byKey).map(([k, v]) => [String(k), Number(v) || 0]).filter(([, v]) => v > 0));
    }

    async function restoreAgentOrdinalsFromServer() {
      try {
        const remote = await apiFetchJson(API.agentOrdinals, { timeoutMs: 3000 });
        if (!remote || typeof remote !== 'object') return;
        const next = Number(remote.next || 1);
        const byKey = remote.by_key && typeof remote.by_key === 'object' ? remote.by_key : {};
        const nameById = remote.name_by_id && typeof remote.name_by_id === 'object' ? remote.name_by_id : {};
        if (!Object.keys(byKey).length && !Object.keys(nameById).length) return;
        // Server data takes precedence over localStorage
        state.agentOrdinal.next = Number.isFinite(next) && next > 0 ? next : 1;
        state.agentOrdinal.byKey = new Map(Object.entries(byKey).map(([k, v]) => [String(k), Number(v) || 0]).filter(([, v]) => v > 0));
        for (const [k, v] of Object.entries(nameById)) {
          if (typeof v === 'string' && v.trim()) state.agentNameById.set(String(k), String(v).trim());
        }
        // Mirror to localStorage as well
        const obj = { next: state.agentOrdinal.next, byKey: Object.fromEntries(state.agentOrdinal.byKey.entries()) };
        storageSetJson('percepta.agent_ordinals.v1', obj);
      } catch {}
    }

    function persistAgentOrdinals() {
      const obj = { next: state.agentOrdinal.next, byKey: Object.fromEntries(state.agentOrdinal.byKey.entries()) };
      storageSetJson('percepta.agent_ordinals.v1', obj);
      _pushAgentOrdinalsToServer();
    }

    let _agentOrdPushTimer = null;
    function _pushAgentOrdinalsToServer() {
      clearTimeout(_agentOrdPushTimer);
      _agentOrdPushTimer = setTimeout(async () => {
        try {
          const payload = {
            next: state.agentOrdinal.next,
            by_key: Object.fromEntries(state.agentOrdinal.byKey.entries()),
            name_by_id: Object.fromEntries(state.agentNameById.entries()),
          };
          await apiPostJson(API.agentOrdinals, payload, { timeoutMs: 3000 });
        } catch {}
      }, 2000);
    }

    function getBestUserForAgentEvent(e) {
      const meta = (e?.metadata && typeof e.metadata === 'object') ? e.metadata : {};
      const cu = String(meta?.current_user || '').trim();
      if (cu && cu.toLowerCase() !== 'unknown') return cu;
      const un = String(e?.user?.name || '').trim();
      if (un && un.toLowerCase() !== 'unknown') return un;
      return '';
    }

    function observeAgentFromEvent(e) {
      const aid = String(e?.agent?.id || e?.agent_id || '').trim();
      if (!aid) return;

      const mac = normalizeMac(getBestMac(e));
      if (mac) state.agentMacById.set(aid, mac);

      const u = getBestUserForAgentEvent(e);
      if (u) state.agentUserById.set(aid, u);

      const hn = String(hostLabel(e) || '').trim();
      if (hn) state.agentNameById.set(aid, hn);

      // Ensure ordinal assignment is stable once we can bind to MAC.
      agentOrdinalForAgentId(aid);
    }

    function agentOrdinalForAgentId(agentId) {
      const id = String(agentId || '').trim();
      if (!id) return 0;
      const mac = state.agentMacById.get(id) || '';
      const preferredKey = mac ? `mac:${mac}` : `id:${id}`;
      const existingKey = state.agentKeyById.get(id) || '';

      // If we previously assigned by id, and now know MAC, transfer if safe.
      if (mac && existingKey && existingKey !== preferredKey) {
        const existingOrd = state.agentOrdinal.byKey.get(existingKey);
        if (existingOrd && !state.agentOrdinal.byKey.has(preferredKey)) {
          state.agentOrdinal.byKey.set(preferredKey, existingOrd);
          state.agentOrdinal.byKey.delete(existingKey);
          state.agentKeyById.set(id, preferredKey);
          persistAgentOrdinals();
          return existingOrd;
        }
      }

      const key = existingKey || preferredKey;
      state.agentKeyById.set(id, key);
      let ord = state.agentOrdinal.byKey.get(key) || 0;
      if (!ord) {
        ord = state.agentOrdinal.next++;
        state.agentOrdinal.byKey.set(key, ord);
        persistAgentOrdinals();
      }
      return ord;
    }

    function storageGetJson(key, fallback) {
      try {
        const raw = localStorage.getItem(key);
        if (!raw) return fallback;
        return JSON.parse(raw);
      } catch {
        return fallback;
      }
    }

    function storageSetJson(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
      } catch {}
    }

    function normalizeMac(mac) {
      const m = String(mac || '').trim().toLowerCase();
      if (!m) return '';
      const cleaned = m.replaceAll('-', ':');
      if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(cleaned)) return cleaned;
      return m;
    }

    function getDeviceNamesMap() {
      return storageGetJson('percepta.device_names.v1', {});
    }

    function getDeviceNameForMac(mac) {
      const key = normalizeMac(mac);
      if (!key) return '';
      const v = state.deviceNames.cache.get(key);
      if (v) return String(v || '').trim();
      // Legacy fallback (single-browser only). Kept for backward compatibility.
      const map = getDeviceNamesMap();
      const legacy = map && typeof map === 'object' ? map[key] : '';
      return String(legacy || '').trim();
    }

    async function setDeviceNameForMac(mac, name) {
      const key = normalizeMac(mac);
      if (!key) return;
      const v = String(name || '').trim();

      // Best-effort server update (uniform across browsers/users).
      try {
        await apiPostJson(API.deviceSet, { mac: key, name: v }, { timeoutMs: 3000, headers: { 'Accept': 'application/json' } });
        // Update local cache immediately.
        if (!v) state.deviceNames.cache.delete(key);
        else state.deviceNames.cache.set(key, v);
        state.dirty.tables = true;
        state.dirty.details = true;
        scheduleRender();
        return;
      } catch (e) {
        // If not logged in / forbidden, inform user.
        if (e && (e.status === 401 || e.status === 403)) {
          showToast(e.status === 401 ? t('deviceNames.set.requireLogin') : t('deviceNames.set.forbidden'));
          return;
        }
      }

      // Fallback: keep legacy localStorage mapping if the backend is unavailable.
      const map = getDeviceNamesMap();
      if (!v) delete map[key];
      else map[key] = v;
      storageSetJson('percepta.device_names.v1', map);
      state.dirty.tables = true;
      state.dirty.details = true;
      scheduleRender();
      showToast(t('deviceNames.set.savedLocalFallback'));
    }

    async function clearDeviceNameForMac(mac) {
      const key = normalizeMac(mac);
      if (!key) return;

      try {
        await apiPostJson(API.deviceClear, { mac: key, name: '' }, { timeoutMs: 3000, headers: { 'Accept': 'application/json' } });
        state.deviceNames.cache.delete(key);
        state.dirty.tables = true;
        scheduleRender();
        return;
      } catch (e) {
        if (e && (e.status === 401 || e.status === 403)) {
          showToast(e.status === 401 ? t('deviceNames.clear.requireLogin') : t('deviceNames.clear.forbidden'));
          return;
        }
      }

      // Legacy fallback.
      const map = getDeviceNamesMap();
      delete map[key];
      storageSetJson('percepta.device_names.v1', map);
      state.deviceNames.cache.delete(key);
      state.dirty.tables = true;
      scheduleRender();
      showToast(t('deviceNames.clear.clearedLocalFallback'));
    }

    function enqueueDeviceNameLookup(macs) {
      const list = Array.isArray(macs) ? macs : [];
      for (const m of list) {
        const key = normalizeMac(m);
        if (!key) continue;
        if (state.deviceNames.cache.has(key)) continue;
        state.deviceNames.inflight.add(key);
      }
      if (!state.deviceNames.inflight.size) return;

      if (state.deviceNames.timer) clearTimeout(state.deviceNames.timer);
      state.deviceNames.timer = setTimeout(async () => {
        const batch = Array.from(state.deviceNames.inflight).slice(0, 200);
        state.deviceNames.inflight.clear();
        try {
          const resp = await apiPostJson(API.deviceLookup, { macs: batch }, { timeoutMs: 2500, headers: { 'Accept': 'application/json' } });
          const names = resp && typeof resp.names === 'object' ? resp.names : {};
          for (const [mac, name] of Object.entries(names)) {
            const k = normalizeMac(mac);
            if (!k) continue;
            const v = String(name || '').trim();
            if (v) state.deviceNames.cache.set(k, v);
          }
          state.dirty.tables = true;
          scheduleRender();
        } catch {
          // Non-fatal: fall back to legacy localStorage.
        }
      }, 200);
    }

    function sevRank(label) {
      const s = String(label || '').toLowerCase();
      if (s === 'critical') return 4;
      if (s === 'high') return 3;
      if (s === 'medium') return 2;
      if (s === 'low') return 1;
      return 0;
    }

    function alertSeverityLabel(a) {
      const v = a?.severity;
      if (typeof v === 'number' && Number.isFinite(v)) {
        if (v >= 4) return 'critical';
        if (v === 3) return 'high';
        if (v === 2) return 'medium';
        if (v === 1) return 'low';
        return 'info';
      }
      const s = String(v ?? '').trim().toLowerCase();
      if (!s) return 'info';
      // Allow numeric-in-string.
      if (!Number.isNaN(Number(s))) return alertSeverityLabel({ severity: Number(s) });
      if (s === 'crit') return 'critical';
      if (s === 'warn' || s === 'warning') return 'medium';
      if (s === 'err' || s === 'error') return 'high';
      if (s === 'informational') return 'info';
      if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
      return 'info';
    }

    function alertRiskScore(a) {
      const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
      const direct = Number(a?.risk_score);
      if (Number.isFinite(direct) && direct >= 0) return Math.max(0, Math.min(100, Math.round(direct)));

      const fromMeta = Number(md.risk_score);
      if (Number.isFinite(fromMeta) && fromMeta >= 0) {
        return Math.max(0, Math.min(100, Math.round(fromMeta)));
      }

      const sev = alertSeverityLabel(a);
      if (sev === 'critical') return 95;
      if (sev === 'high') return 80;
      if (sev === 'medium') return 60;
      if (sev === 'low') return 35;
      return 20;
    }

    function toggleSort(table, key) {
      const fallback = table === 'alerts' ? { key: 'risk', dir: 'desc' } : { key: 'time', dir: 'desc' };
      const st = state.sort?.[table] || fallback;
      const next = { key, dir: 'desc' };
      if (st.key === key) next.dir = st.dir === 'desc' ? 'asc' : 'desc';
      state.sort[table] = next;
      state.dirty.tables = true;
      scheduleRender();
    }

    function applyEventSort(list) {
      const st = state.sort?.events || { key: 'time', dir: 'desc' };
      const dir = st.dir === 'asc' ? 1 : -1;
      const key = st.key;

      const get = (e) => {
        if (key === 'time') return eventTimeSeconds(e);
        if (key === 'sev') return sevRank(severityLabel(e));
        if (key === 'cat') return categoryActionLabel(e);
        if (key === 'summary') return displaySummary(e);
        if (key === 'actor') return actorLabel(e);
        if (key === 'agent') return agentNumberLabelForEvent(e) || '';
        if (key === 'host') return hostDisplayName(e) || '';
        if (key === 'agent_ip') return agentIpForEvent(e) || '';
        if (key === 'src') return srcLabel(e) || '';
        if (key === 'dst') return dstLabel(e) || '';
        if (key === 'process') return processLabel(e) || '';
        if (key === 'object') return objectLabel(e);
        if (key === 'flow') return flowLabel(e);
        if (key === 'attacker') return honeypotAttackerLabel(e);
        if (key === 'target') return honeypotTargetLabel(e);
        if (key === 'activity') return honeypotActivityLabel(e);
        if (key === 'signature') return idsSignatureLabel(e);
        if (key === 'action') return idsActionLabel(e);
        if (key === 'proto') return idsProtoLabel(e);
        if (key === 'user') return getBestUser(e) || '';
        if (key === 'outcome') return outcomeLabel(e) || '';
        if (key === 'eid') return Number(getEventIdValue(e) || 0);
        if (key === 'ip') return getBestIp(e) || '';
        if (key === 'agent_display') return String(e?.agent?.hostname || e?.agent?.id || e?.agent_id || '');
        if (String(key).startsWith('field:')) return eventPathTextValue(e, String(key).slice(6));
        return 0;
      };

      return (Array.isArray(list) ? list : []).sort((a, b) => {
        const va = get(a);
        const vb = get(b);
        if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
        return String(va).localeCompare(String(vb)) * dir;
      });
    }

    function applyAlertSort(list) {
      const st = state.sort?.alerts || { key: 'risk', dir: 'desc' };
      const dir = st.dir === 'asc' ? 1 : -1;
      const key = st.key;

      const toSec = (t) => tsToSec(t);

      const get = (a) => {
        if (key === 'time') return toSec(a?.last_seen || a?.first_seen);
        if (key === 'risk') return alertRiskScore(a);
        if (key === 'sev') return sevRank(alertSeverityLabel(a));
        if (key === 'message') return String(a?.rule_name || a?.rule_id || '') + ' ' + String(a?.message || '');
        if (key === 'agent') return String(a?.agent_hostname || a?.agent_id || '');
        if (key === 'status') return String(a?.status || '');
        return 0;
      };

      return (Array.isArray(list) ? list : []).sort((a, b) => {
        const va = get(a);
        const vb = get(b);
        if (typeof va === 'number' && typeof vb === 'number') {
          const primary = (va - vb) * dir;
          if (primary !== 0) return primary;
          if (key === 'risk') {
            const ta = toSec(a?.last_seen || a?.first_seen);
            const tb = toSec(b?.last_seen || b?.first_seen);
            return (tb - ta);
          }
          return 0;
        }
        return String(va).localeCompare(String(vb)) * dir;
      });
    }
    function shortText(text, maxLen) {
      const s = String(text ?? '');
      if (!maxLen || s.length <= maxLen) return s;
      return s.slice(0, Math.max(0, maxLen - 1)) + '…';
    }

    function getEventIdValue(e) {
      const v = e?.event?.event_id;
      if (v === undefined || v === null) return '';
      if (typeof v === 'number') return String(v);
      const s = String(v);
      return s === '0' ? '' : s;
    }

    function getBestIp(e) {
      const isIpv4 = (s) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(s || '').trim());
      const isPrivateIpv4 = (s) => {
        const v = String(s || '').trim();
        if (!isIpv4(v)) return false;
        const parts = v.split('.').map((x) => Number(x));
        if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;
        const [a, b] = parts;
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 0) return true;
        if (a === 169 && b === 254) return true;
        if (a === 192 && b === 168) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        return false;
      };
      const isPrivateIpv6 = (s) => {
        const v = String(s || '').trim().toLowerCase();
        if (!v.includes(':')) return false;
        if (v === '::1') return true;
        if (v.startsWith('fe80:')) return true; // link-local
        if (v.startsWith('fc') || v.startsWith('fd')) return true; // ULA
        return false;
      };
      const isPublicIp = (s) => {
        const v = String(s || '').trim();
        if (!v) return false;
        if (v.includes(':')) return !isPrivateIpv6(v);
        return isIpv4(v) && !isPrivateIpv4(v);
      };

      const net = e?.network || {};
      const src = net?.src_ip ? String(net.src_ip) : '';
      const dst = net?.dst_ip ? String(net.dst_ip) : '';
      const dir = net?.direction; // proto enum (number) or text
      const dirNum = (typeof dir === 'number') ? dir : null;

      // Prefer the likely remote/public IP.
      if (src && dst) {
        const srcPub = isPublicIp(src);
        const dstPub = isPublicIp(dst);
        if (dirNum === 2) return dst; // OUTBOUND
        if (dirNum === 1) return src; // INBOUND
        if (srcPub && !dstPub) return src;
        if (dstPub && !srcPub) return dst;
        // If both are public or both private, prefer dst (typical pivot target).
        return dst;
      }
      if (src) return src;
      if (dst) return dst;

      const hostIpVal = e?.host?.ip;
      const hostIps = Array.isArray(hostIpVal) ? hostIpVal.map(String) : (hostIpVal ? [String(hostIpVal)] : []);
      for (const ip of hostIps) {
        if (isPublicIp(ip)) return ip;
      }
      if (hostIps.length) return hostIps[0];

      const a = e?.agent || {};
      if (a?.ip) return String(a.ip);
      return '';
    }

    function getBestUser(e) {
      const isSystemUser = (name) => {
        const n = String(name || '').trim().toLowerCase();
        if (!n) return false;
        return n === 'system' || n === 'nt authority\\system' || n === 'local system';
      };

      const meta0 = e?.metadata && typeof e.metadata === 'object' ? e.metadata : {};
      const provider = String(e?.event?.provider || '').toLowerCase();
      const isWindowsLike = (() => {
        if (String(meta0?.['winlog.event_id'] || '').trim()) return true;
        for (const k of Object.keys(meta0)) {
          if (String(k).startsWith('winlog.')) return true;
        }
        return provider.includes('microsoft-windows') || provider.includes('security') || provider.includes('windows');
      })();

      const user = e?.user || {};
      const uname = String(user?.name || '').trim();
      const dom = String(user?.domain || '').trim();

      // For non-Windows sources, the agent-injected "current_user" is a useful display hint.
      // For Windows event logs, it can be misleading (collector-time user != event principal).
      if (!isWindowsLike) {
        const cu = String(meta0?.current_user || '').trim();
        if (cu && cu.toLowerCase() !== 'unknown') return cu;
        if (uname) return dom ? `${dom}\\${uname}` : uname;
      }

      const meta = meta0;
      const lowerMap = new Map();
      for (const [k, v] of Object.entries(meta)) {
        if (typeof k === 'string') lowerMap.set(k.toLowerCase(), String(v ?? ''));
      }
      const pick = (k) => String(lowerMap.get(String(k).toLowerCase()) ?? '').trim();

      const normUser = () => {
        const u = pick('norm.user') || pick('metadata.norm.user');
        const d = pick('norm.user_domain') || pick('metadata.norm.user_domain');
        if (!u) return '';
        return d ? `${d}\\${u}` : u;
      };

      if (isWindowsLike) {
        const subjUser = pick('winlog.event_data.subjectusername') || pick('event_data.subjectusername') || pick('subjectusername');
        const subjDom = pick('winlog.event_data.subjectdomainname') || pick('event_data.subjectdomainname') || pick('subjectdomainname');
        const tgtUser = pick('winlog.event_data.targetusername') || pick('event_data.targetusername') || pick('targetusername');
        const tgtDom = pick('winlog.event_data.targetdomainname') || pick('event_data.targetdomainname') || pick('targetdomainname');

        const subj = subjUser ? (subjDom ? `${subjDom}\\${subjUser}` : subjUser) : '';
        const tgt = tgtUser ? (tgtDom ? `${tgtDom}\\${tgtUser}` : tgtUser) : '';
        if (subj && !isSystemUser(subjUser)) return subj;
        if (tgt) return tgt;

        // If server normalization already populated `user`, trust it next.
        if (uname) return dom ? `${dom}\\${uname}` : uname;

        const nu = normUser();
        if (nu) return nu;
      }

      // General fallbacks.
      if (uname) return dom ? `${dom}\\${uname}` : uname;

      const candidates = [
        'norm.user',
        'norm.user_domain',
        'user.name',
        'username',
        'user',
        'account',
        'account.name',
        'subject.username',
        'target.username',
        'winlog.event_data.AccountName',
        'winlog.event_data.UserName',
        'winlog.event_data.CallerUserName',
        'winlog.event_data.AccountDomain',
        'winlog.event_data.UserDomain',
        'winlog.event_data.SubjectUserName',
        'winlog.event_data.TargetUserName',
        'SubjectUserName',
        'TargetUserName',
      ];
      for (const k of candidates) {
        const v = pick(k);
        if (v) return v;
      }

      const nu2 = normUser();
      if (nu2) return nu2;

      const txt = `${e?.event?.summary || ''} ${e?.event?.original_message || ''} ${e?.message || ''}`;
      const m = /\buser(?:name)?\b\s*[:=]\s*([A-Za-z0-9_.\\-]{1,64})/i.exec(txt);
      if (m && m[1]) return String(m[1]).trim();

      return 'unknown';
    }

    function agentIpForEvent(e) {
      const a = e?.agent || {};
      const ip = String(a?.ip || '').trim();
      if (ip) return ip;
      const hostIpVal = e?.host?.ip;
      const hostIps = Array.isArray(hostIpVal) ? hostIpVal.map(String) : (hostIpVal ? [String(hostIpVal)] : []);
      return String(hostIps[0] || '').trim();
    }

    function agentIpForAlert(a) {
      const obj = a && typeof a === 'object' ? a : {};
      const direct = String(obj?.agent_ip || obj?.agent?.ip || '').trim();
      if (direct) return direct;

      const meta = (obj?.metadata && typeof obj.metadata === 'object') ? obj.metadata : {};
      const lowerMap = new Map();
      for (const [k, v] of Object.entries(meta)) {
        if (typeof k === 'string') lowerMap.set(k.toLowerCase(), String(v ?? ''));
      }
      const pick = (k) => String(lowerMap.get(String(k).toLowerCase()) ?? '').trim();

      for (const k of ['agent_ip', 'agent.ip', 'host.ip', 'host_ip', 'agentip']) {
        const v = pick(k);
        if (v) return v;
      }

      return '';
    }

    function agentIdentityLabelForEvent(e) {
      const aid = String(e?.agent?.id || e?.agent_id || e?.agent?.hostname || '').trim();
      const ord = aid ? agentOrdinalForAgentId(aid) : 0;
      const hn = String(hostDisplayName(e) || '').trim();
      const ip = agentIpForEvent(e);
      const bits = [];
      if (ord > 0) bits.push(`Agent ${ord}`);
      else if (aid) bits.push('Agent');
      if (hn) bits.push(hn);
      else if (aid) bits.push(shortId(aid));
      if (ip) bits.push(ip);
      return bits.join(' · ');
    }

    function agentNumberLabelForEvent(e) {
      const aid = String(e?.agent?.id || e?.agent_id || '').trim();
      if (!aid) return '';
      const ord = agentOrdinalForAgentId(aid);
      return ord > 0 ? `Agent ${ord}` : 'Agent';
    }

    function hostDisplayName(e) {
      const mac = getBestMac(e);
      const deviceName = mac ? getDeviceNameForMac(mac) : '';
      if (mac && !deviceName) enqueueDeviceNameLookup([mac]);
      const hn = String(hostLabel(e) || '').trim();
      return String(deviceName || hn || '').trim();
    }

    function deviceNameForAgentId(agentId) {
      const aid = String(agentId || '').trim();
      if (!aid) return '';
      const mac = normalizeMac(String(state.agentMacById.get(aid) || ''));
      if (!mac) return '';
      const name = getDeviceNameForMac(mac);
      if (name) return name;
      enqueueDeviceNameLookup([mac]);
      return '';
    }

    function agentIdentityLabelForAlert(a) {
      const obj = a && typeof a === 'object' ? a : {};
      const aid = String(obj?.agent_id || obj?.agent?.id || obj?.agent_hostname || '').trim();
      const ord = aid ? agentOrdinalForAgentId(aid) : 0;
      const hn = String(deviceNameForAgentId(aid) || obj?.agent_hostname || obj?.agent?.hostname || '').trim();
      const ip = agentIpForAlert(obj);
      const bits = [];
      if (ord > 0) bits.push(`Agent ${ord}`);
      else if (aid) bits.push('Agent');
      if (hn) bits.push(hn);
      else if (aid) bits.push(shortId(aid));
      if (ip) bits.push(ip);
      return bits.join(' · ');
    }

    function getBestMac(e) {
      // Prefer agent.mac for stable device identity.
      // host.mac can change frequently (VPN, Docker, Wi-Fi/Ethernet switching).
      const aMac = normalizeMac(e?.agent?.mac);
      if (aMac) return aMac;

      const hostMacVal = e?.host?.mac;
      const hostMacs = Array.isArray(hostMacVal) ? hostMacVal.map(String) : (hostMacVal ? [String(hostMacVal)] : []);
      for (const m of hostMacs) {
        const nm = normalizeMac(m);
        if (nm) return nm;
      }

      const meta = e?.metadata && typeof e.metadata === 'object' ? e.metadata : {};
      const lowerMap = new Map();
      for (const [k, v] of Object.entries(meta)) {
        if (typeof k === 'string') lowerMap.set(k.toLowerCase(), String(v ?? ''));
      }
      const pick = (k) => String(lowerMap.get(String(k).toLowerCase()) ?? '').trim();

      const candidates = ['host.mac', 'mac', 'agent.mac'];
      for (const k of candidates) {
        const nm = normalizeMac(pick(k));
        if (nm) return nm;
      }
      return '';
    }

    function relevantInfo(e) {
      const ev = e?.event || {};
      const u = getBestUser(e);

      const out = outcomeLabel(e);
      const action = ev?.action ? String(ev.action) : '';

      // 1) Network-first: show flow + SNI + protocol.
      const net = e?.network || {};
      const srcIp = String(net?.src_ip || metaFirst(e, [
        'norm.src_ip',
        'norm.client_ip',
        'winlog.event_data.SourceAddress',
        'winlog.event_data.IpAddress',
        'winlog.event_data.SourceNetworkAddress',
        'winlog.event_data.ClientAddress',
        'winlog.event_data.SourceIp',
      ]) || '').trim();
      const dstIp = String(net?.dst_ip || metaFirst(e, [
        'norm.dst_ip',
        'winlog.event_data.DestAddress',
        'winlog.event_data.DestinationAddress',
        'winlog.event_data.DestinationIp',
      ]) || '').trim();
      const srcPort = (net?.src_port ? String(net.src_port) : '') || metaFirst(e, [
        'norm.src_port',
        'winlog.event_data.SourcePort',
        'winlog.event_data.IpPort',
        'winlog.event_data.ClientPort',
      ]);
      const dstPort = (net?.dst_port ? String(net.dst_port) : '') || metaFirst(e, [
        'norm.dst_port',
        'winlog.event_data.DestPort',
        'winlog.event_data.DestinationPort',
      ]);
      const tlsSni = String(net?.tls_sni || metaFirst(e, ['network.tls_sni', 'tls.sni', 'tls.server_name', 'tls_sni']) || '').trim();
      const proto = String(net?.protocol || metaFirst(e, ['norm.proto', 'network.protocol', 'proto']) || '').trim();
      const src = srcIp ? `${srcIp}${srcPort ? ':' + srcPort : ''}` : '';
      const dst = dstIp ? `${dstIp}${dstPort ? ':' + dstPort : ''}` : '';
      if (src || dst || tlsSni || proto) {
        const parts = [];
        if (u) parts.push(`user ${u}`);
        if (src || dst) parts.push(`flow ${src}${(src && dst) ? ' → ' : ''}${dst}`);
        if (tlsSni) parts.push(`sni ${tlsSni}`);
        if (proto) parts.push(String(proto).toLowerCase());
        return shortText(parts.join(' · '), 120);
      }

      // 2) Auth/user: principal + action + outcome.
      const partsU = [];
      if (u) partsU.push(`user ${u}`);
      if (action) partsU.push(action);
      if (out) partsU.push(out);
      if (partsU.length) return shortText(partsU.join(' · '), 120);

      // 3) Process: name + pid + (short) cmdline.
      const proc = e?.process || {};
      if (proc?.name) {
        const parts = [];
        parts.push(String(proc.name));
        if (proc?.pid) parts.push(`pid=${proc.pid}`);
        if (proc?.command_line) parts.push(shortText(String(proc.command_line), 80));
        return shortText(parts.join(' · '), 120);
      }

      // 4) File: op + path.
      const file = e?.file || {};
      if (file?.path || file?.name) {
        const parts = [];
        if (file?.operation !== undefined && file?.operation !== null) parts.push(String(file.operation));
        parts.push(String(file.path || file.name));
        return shortText(parts.join(' · '), 120);
      }

      // 5) Registry: path + value preview.
      const reg = e?.registry || {};
      if (reg?.path) {
        const parts = [String(reg.path)];
        if (reg?.value) parts.push(shortText(String(reg.value), 60));
        return shortText(parts.join(' · '), 120);
      }

      // Fallback: provider/action/level.
      const parts = [];
      if (u) parts.push(`user ${u}`);
      if (ev?.provider) parts.push(providerToDisplayName(ev.provider));
      if (action) parts.push(action);
      if (out) parts.push(out);
      return shortText(parts.join(' · '), 120);
    }

    function pivotSearch(q, view = 'events') {
      const query = String(q || '').trim();
      if (!query) return;
      const search = document.getElementById('globalSearch');
      if (search) search.value = query;
      state.searchText = query;
      setView(view);
      fetchEvents().finally(() => {
        state.dirty.tables = true;
        scheduleRender();
      });
    }


    function escapeHtml(str) {
      return String(str ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function setTextIfChanged(id, value) {
      const el = document.getElementById(id);
      if (!el) return false;
      const next = String(value ?? '');
      if (el.textContent === next) return false;
      el.textContent = next;
      return true;
    }

    // Track last flash time per element to prevent animation stacking during high-frequency updates
    const _chipFlashTimers = new Map();

    function flashClosestChip(childId) {
      const el = document.getElementById(childId);
      const chip = el && el.closest ? el.closest('.chip') : null;
      if (!chip) return;
      
      // Debounce: prevent multiple flashes within 200ms to avoid animation stacking
      const now = Date.now();
      const lastFlashTime = _chipFlashTimers.get(childId) || 0;
      if (now - lastFlashTime < 200) return;
      _chipFlashTimers.set(childId, now);
      
      // Use requestAnimationFrame instead of forcing reflow to prevent jank
      chip.classList.remove('flash');
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          chip.classList.add('flash');
        });
      });
    }

    function showToast(content, explicitKind, durationMs, { html = false } = {}) {
      const box = document.getElementById('toast');
      const msg = document.getElementById('toastMsg');
      if (!box || !msg) return;
      
      // Log all error/warning messages to console for debugging connectivity/API issues
      const contentStr = String(content || '');
      if (explicitKind === 'danger' || explicitKind === 'warn' || contentStr.toLowerCase().includes('error')) {
        console.warn('[Toast]', contentStr);
      }
      
      if (html) {
        msg.innerHTML = content;
      } else {
        msg.textContent = content;
      }

      let kind = explicitKind || 'info';
      if (!explicitKind) {
        // Backward-compatible: infer kind from message.
        const raw = String(content || '').toLowerCase();
        if (raw.includes('forbidden') || raw.includes('failed') || raw.includes('error') || raw.includes('blocked')) kind = 'danger';
        else if (raw.includes('login') || raw.includes('requires')) kind = 'warn';
        else if (raw.includes('restored') || raw.includes('saved') || raw.includes('updated') || raw.includes('downloaded') || raw.includes('submitted')) kind = 'ok';
      }

      box.classList.remove('kind-ok', 'kind-warn', 'kind-danger');
      if (kind !== 'info') box.classList.add(`kind-${kind}`);

      box.classList.add('show');
      clearTimeout(showToast._t);
      showToast._t = setTimeout(() => box.classList.remove('show'), durationMs || 6500);
    }
    showToast._t = null;

    function openUiDialog({ title = '', message = '', confirmLabel = 'OK', cancelLabel = 'Cancel', danger = false, inputValue = null } = {}) {
      return new Promise((resolve) => {
        if (!document?.body) {
          resolve({ ok: false, value: null });
          return;
        }

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.style.position = 'fixed';
        overlay.style.inset = '0';
        overlay.style.zIndex = '3200';
        overlay.style.display = 'flex';
        overlay.style.alignItems = 'center';
        overlay.style.justifyContent = 'center';
        overlay.style.padding = '18px';
        overlay.style.background = 'rgba(2, 6, 20, 0.62)';
        overlay.style.backdropFilter = 'blur(4px)';

        const panel = document.createElement('div');
        panel.style.width = 'min(560px, 96vw)';
        panel.style.maxHeight = '90vh';
        panel.style.overflow = 'auto';
        panel.style.borderRadius = '14px';
        panel.style.border = '1px solid var(--stroke2)';
        panel.style.background = 'linear-gradient(180deg, var(--bg1), var(--bg2))';
        panel.style.boxShadow = 'var(--shadow)';
        panel.style.padding = '14px';

        const hd = document.createElement('div');
        hd.style.display = 'flex';
        hd.style.alignItems = 'center';
        hd.style.justifyContent = 'space-between';
        hd.style.gap = '10px';
        hd.style.marginBottom = '10px';

        const h = document.createElement('div');
        h.style.fontSize = '13px';
        h.style.fontWeight = '800';
        h.style.letterSpacing = '0.6px';
        h.style.textTransform = 'uppercase';
        h.textContent = String(title || 'Confirm');
        hd.appendChild(h);

        const body = document.createElement('div');
        body.style.fontSize = '13px';
        body.style.color = 'var(--text)';
        body.style.whiteSpace = 'pre-wrap';
        body.style.wordBreak = 'break-word';
        body.textContent = String(message || '');

        let input = null;
        if (inputValue !== null) {
          input = document.createElement('input');
          input.className = 'field';
          input.type = 'text';
          input.value = String(inputValue ?? '');
          input.style.marginTop = '12px';
          input.style.width = '100%';
          input.setAttribute('aria-label', String(title || 'Input'));
        }

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.justifyContent = 'flex-end';
        actions.style.gap = '8px';
        actions.style.marginTop = '14px';

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn';
        cancelBtn.textContent = String(cancelLabel || 'Cancel');

        const okBtn = document.createElement('button');
        okBtn.className = danger ? 'btn danger' : 'btn primary';
        okBtn.textContent = String(confirmLabel || 'OK');

        actions.appendChild(cancelBtn);
        actions.appendChild(okBtn);

        panel.appendChild(hd);
        panel.appendChild(body);
        if (input) panel.appendChild(input);
        panel.appendChild(actions);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        const cleanup = (result) => {
          try { window.removeEventListener('keydown', onKey); } catch {}
          try { overlay.remove(); } catch {}
          resolve(result);
        };

        const onKey = (ev) => {
          if (!overlay.isConnected) return;
          if (ev.key === 'Escape') {
            ev.preventDefault();
            cleanup({ ok: false, value: null });
            return;
          }
          if (ev.key === 'Enter') {
            ev.preventDefault();
            cleanup({ ok: true, value: input ? String(input.value ?? '') : null });
          }
        };

        cancelBtn.addEventListener('click', () => cleanup({ ok: false, value: null }));
        okBtn.addEventListener('click', () => cleanup({ ok: true, value: input ? String(input.value ?? '') : null }));
        overlay.addEventListener('click', (ev) => {
          if (ev.target === overlay) cleanup({ ok: false, value: null });
        });

        try { window.addEventListener('keydown', onKey); } catch {}
        setTimeout(() => {
          try {
            if (input) {
              input.focus();
              input.select();
            } else {
              okBtn.focus();
            }
          } catch {}
        }, 0);
      });
    }

    async function uiConfirm(message, opts = {}) {
      try {
        const tx = (k, fallback) => {
          try { return (typeof t === 'function') ? String(t(k) || fallback) : fallback; } catch { return fallback; }
        };
        const res = await openUiDialog({
          title: opts.title || tx('dialog.confirmTitle', 'Confirm action'),
          message: String(message || ''),
          confirmLabel: opts.confirmLabel || tx('btn.confirm', 'Confirm'),
          cancelLabel: opts.cancelLabel || tx('btn.cancel', 'Cancel'),
          danger: Boolean(opts.danger),
          inputValue: null,
        });
        return Boolean(res?.ok);
      } catch {
        return window.confirm(String(message || ''));
      }
    }

    async function uiPrompt(message, defaultValue = '', opts = {}) {
      try {
        const tx = (k, fallback) => {
          try { return (typeof t === 'function') ? String(t(k) || fallback) : fallback; } catch { return fallback; }
        };
        const res = await openUiDialog({
          title: opts.title || tx('dialog.inputTitle', 'Input required'),
          message: String(message || ''),
          confirmLabel: opts.confirmLabel || tx('btn.save', 'Save'),
          cancelLabel: opts.cancelLabel || tx('btn.cancel', 'Cancel'),
          danger: Boolean(opts.danger),
          inputValue: String(defaultValue ?? ''),
        });
        if (!res?.ok) return null;
        return String(res.value ?? '');
      } catch {
        return window.prompt(String(message || ''), String(defaultValue ?? ''));
      }
    }

    async function copyTextToClipboard(text) {
      const s = String(text ?? '');
      if (!s) return false;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(s);
          return true;
        }
      } catch {}
      try {
        const ta = document.createElement('textarea');
        ta.value = s;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.left = '-1000px';
        document.body.appendChild(ta);
        ta.select();
        ta.setSelectionRange(0, ta.value.length);
        const ok = document.execCommand('copy');
        ta.remove();
        return ok;
      } catch {
        return false;
      }
    }

    function downloadBlob(filename, blob) {
      try {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10_000);
      } catch {}
    }

    function downloadText(filename, content, mime = 'text/plain;charset=utf-8') {
      const blob = new Blob([String(content ?? '')], { type: mime });
      downloadBlob(filename, blob);
    }

    function csvEscape(v) {
      const s = String(v ?? '');
      if (/["]/.test(s)) return '"' + s.replaceAll('"', '""') + '"';
      if (/[\n\r,]/.test(s)) return '"' + s + '"';
      return s;
    }

    function formatTimeIso(ts) {
      if (!ts) return '';
      try {
        const date = (typeof ts === 'string')
          ? new Date(ts)
          : (typeof ts === 'number')
            ? new Date(ts * 1000)
            : (typeof ts === 'object' && ts && typeof ts.seconds === 'number')
              ? new Date(ts.seconds * 1000)
              : null;
        if (!date || !Number.isFinite(date.getTime())) return '';
        return date.toISOString();
      } catch {}
      return '';
    }

    function eventsToCsv(events) {
      const cols = [
        'time',
        'severity',
        'summary',
        'user',
        'outcome',
        'event_id',
        'src_ip',
        'dst_ip',
        'agent',
        'process',
        'sha256',
        'hash',
      ];
      // Sort events chronologically (oldest first)
      const sorted = (Array.isArray(events) ? [...events] : []).sort((a, b) => eventTimeSeconds(a) - eventTimeSeconds(b));
      const lines = [cols.join(',')];
      for (const e of sorted) {
        const ev = e?.event || {};
        const summary = String(ev?.summary || ev?.original_message || '').trim() || displaySummary(e);
        const net = e?.network || {};
        const agent = e?.agent?.hostname || e?.agent?.id || e?.agent_id || '';
        const user = getBestUser(e);
        const proc = e?.process?.name || '';
        const sha = getBestSha256(e);
        // For the hash column: show the event's dedup/correlation hash, but if the
        // top-level hash is actually an MD5 file hash (32 hex chars) surface it here.
        const rawHash = String(e?.hash || '').trim().toLowerCase();
        const hash = (isMd5(rawHash) && !isSha256(rawHash)) ? rawHash : (e?.correlation_id || rawHash);
        const row = [
          formatTimeIso(eventPrimaryTime(e)),
          severityLabel(e),
          summary,
          user,
          outcomeLabel(e),
          getEventIdValue(e),
          net?.src_ip || '',
          net?.dst_ip || '',
          agent,
          proc,
          sha,
          hash,
        ].map(csvEscape);
        lines.push(row.join(','));
      }
      return lines.join('\n');
    }

    function getEventListForExport(view) {
      const v = String(view || '').toLowerCase();
      const filterOut = (list) => filtered(list, 'event').filter(e => !isAgentInternalEvent(e)).slice(0, LIMITS.maxEvents);
      if (v === 'honeypot') return filterOut(state.honeypot);
      if (v === 'ids') return filterOut(state.ids);
      return filterOut(state.events);
    }

    function exportEvents(view, format) {
      const list = getEventListForExport(view);
      const tag = String(view || 'events');
      const ts = new Date().toISOString().replaceAll(':', '-');
      if (!list.length) {
        showToast('Nothing to export for current view/filter.');
        return;
      }
      if (format === 'csv') {
        downloadText(`percepta-${tag}-${ts}.csv`, eventsToCsv(list), 'text/csv;charset=utf-8');
        return;
      }
      downloadText(`percepta-${tag}-${ts}.json`, JSON.stringify(list, null, 2), 'application/json;charset=utf-8');
    }

    function openExternal(url) {
      const u = String(url || '').trim();
      if (!u) return;
      window.open(u, '_blank', 'noopener,noreferrer');
    }

    function intelUrlForIp(provider, ip) {
      const v = String(ip || '').trim();
      if (!v) return '';
      if (provider === 'abuseipdb') return `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`;
      if (provider === 'otx') return `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(v)}`;
      if (provider === 'urlhaus') return `https://urlhaus.abuse.ch/host/${encodeURIComponent(v)}/`;
      return '';
    }

    function intelUrlForHash(provider, sha256) {
      const v = String(sha256 || '').trim().toLowerCase();
      if (!v) return '';
      if (provider === 'malwarebazaar') return `https://bazaar.abuse.ch/sample/${encodeURIComponent(v)}/`;
      if (provider === 'otx') return `https://otx.alienvault.com/indicator/file/${encodeURIComponent(v)}`;
      return '';
    }

    function markApiOk() {
      if (!state.apiOk) {
        state.apiOk = true;
        state.lastApiError = '';
        showToast('Backend connection restored.');
      }
    }

    function showApiFailureOnce(context, err) {
      const status = err?.status;
      const body = (err?.body || '').toString().slice(0, 180);
      const msg = `${context}: ${status ? 'HTTP ' + status : 'network error'}${body ? ' — ' + body : ''}`;
      if (state.apiOk || state.lastApiError !== msg) {
        state.apiOk = false;
        state.lastApiError = msg;
        showToast(
          `Backend unreachable or blocked. ${escapeHtml(msg)}<br/>` +
          `Open <a href="/healthz">/healthz</a> and confirm you are using <strong>https://&lt;host&gt;:8080/dashboard</strong> (not a local HTML file).`
        );
      }
    }

    function formatTime(ts) {
      if (!ts) return '';
      try {
        const date = (typeof ts === 'string')
          ? new Date(ts)
          : (typeof ts === 'number')
            ? new Date(ts * 1000)
            : (typeof ts === 'object' && ts && typeof ts.seconds === 'number')
              ? new Date(ts.seconds * 1000)
              : null;

        if (!date || !Number.isFinite(date.getTime())) return '';

        // ── Timezone-aware formatting (ISS-059) ───────────────────────────
        const tzPref = (typeof localStorage !== 'undefined' && localStorage.getItem('percepta.ui.timezone')) || 'Asia/Karachi';
        let absolute;
        let tzLabel;
        if (tzPref === 'utc') {
          absolute = date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
          tzLabel = 'UTC';
        } else if (tzPref && tzPref !== 'local' && tzPref.includes('/')) {
          // IANA timezone string e.g. "America/New_York"
          try {
            absolute = date.toLocaleString('en-US', { timeZone: tzPref });
            tzLabel = tzPref.split('/').pop().replace(/_/g, ' ');
          } catch {
            absolute = date.toLocaleString();
            tzLabel = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
          }
        } else {
          absolute = date.toLocaleString();
          tzLabel = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        }

        const deltaSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
        const relative = deltaSec < 60
          ? `${deltaSec}s ago`
          : deltaSec < 3600
            ? `${Math.floor(deltaSec / 60)}m ago`
            : deltaSec < 86400
              ? `${Math.floor(deltaSec / 3600)}h ago`
              : `${Math.floor(deltaSec / 86400)}d ago`;
        return `${relative} (${absolute} ${tzLabel})`;
      } catch {}
      return '';
    }

    function tsToSec(ts) {
      if (!ts) return 0;
      if (typeof ts === 'number') return Number.isFinite(ts) ? ts : 0;
      if (typeof ts === 'string' && ts) {
        const ms = new Date(ts).getTime();
        return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
      }
      if (typeof ts === 'object' && ts && typeof ts.seconds === 'number') return ts.seconds;
      return 0;
    }

    function eventPrimaryTime(e) {
      return e?.event_time || e?.ingest_time || e?.timestamp || '';
    }

    function eventTimeSeconds(e) {
      return tsToSec(eventPrimaryTime(e));
    }
    function eventIngestTimeSeconds(e) {
      // For rate/trend widgets we want ingestion-time so delayed/replayed logs still show as "real-time" traffic.
      return tsToSec(e?.ingest_time || e?.event_time || e?.timestamp || '');
    }

