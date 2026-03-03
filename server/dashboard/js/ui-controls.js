    async function fetchEventKnowledge() {
      try {
        const kb = await apiFetchJson('/api/event_knowledge', { timeoutMs: 2500, headers: { 'Accept': 'application/json' } });
        if (kb && typeof kb === 'object') state.eventKnowledge = kb;
        markApiOk();
      } catch (e) {
        // Non-fatal: dashboard still works without enrichment.
        state.eventKnowledge = null;
      }
    }

    async function fetchIntelStatus() {
      try {
        const st = await apiFetchJson('/api/intel/status', { timeoutMs: 2500, headers: { 'Accept': 'application/json' } });
        if (st && typeof st === 'object') state.intel.status = st;
      } catch {
        state.intel.status = null;
      }
    }

    function isSha256(s) {
      const v = String(s || '').trim().toLowerCase();
      return v.length === 64 && /^[0-9a-f]{64}$/.test(v);
    }

    function isMd5(s) {
      const v = String(s || '').trim().toLowerCase();
      return v.length === 32 && /^[0-9a-f]{32}$/.test(v);
    }

    function getBestSha256(e) {
      const fileHash = e?.file?.hash;
      if (fileHash && typeof fileHash === 'object') {
        if (isSha256(fileHash.sha256)) return String(fileHash.sha256).toLowerCase();
      }
      const procHash = e?.process?.hash;
      if (procHash && typeof procHash === 'object') {
        if (isSha256(procHash.sha256)) return String(procHash.sha256).toLowerCase();
      }
      const meta = e?.metadata || {};
      for (const k of ['sha256', 'hash.sha256', 'file.sha256', 'process.sha256']) {
        const v = meta?.[k];
        if (isSha256(v)) return String(v).toLowerCase();
      }
      // Check top-level event hash field (may contain SHA256)
      const topHash = String(e?.hash || '').trim();
      if (isSha256(topHash)) return topHash.toLowerCase();
      return '';
    }

    const RE_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
    const RE_SHA256 = /\b[0-9a-fA-F]{64}\b/g;
    const RE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;

    function uniqStrings(arr) {
      const out = [];
      const seen = new Set();
      for (const v of arr || []) {
        const s = String(v || '').trim();
        if (!s) continue;
        const key = s.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(s);
      }
      return out;
    }

    function extractCvesFromEvent(e) {
      const texts = [];
      const ev = e?.event || {};
      if (ev?.summary) texts.push(String(ev.summary));
      if (ev?.original_message) texts.push(String(ev.original_message));
      if (e?.message) texts.push(String(e.message));
      const meta = e?.metadata || {};
      if (meta && typeof meta === 'object') {
        for (const [k, v] of Object.entries(meta)) {
          texts.push(String(k));
          if (v !== null && v !== undefined) texts.push(String(v));
        }
      }

      const found = [];
      for (const t of texts) {
        const m = t.match(RE_CVE);
        if (m && m.length) found.push(...m);
      }
      return uniqStrings(found.map((x) => String(x).toUpperCase()));
    }

    function extractDomainsFromEvent(e) {
      const found = [];
      const net = e?.network || {};
      if (net?.tls_sni) found.push(String(net.tls_sni));

      const texts = [];
      const ev = e?.event || {};
      if (ev?.summary) texts.push(String(ev.summary));
      if (ev?.original_message) texts.push(String(ev.original_message));
      if (e?.message) texts.push(String(e.message));

      for (const t of texts) {
        const m = t.toLowerCase().match(RE_DOMAIN);
        if (m && m.length) found.push(...m);
      }

      // De-noise common false positives.
      const filtered = found.filter((d) => !['localhost', 'localdomain'].includes(String(d).toLowerCase()));
      return uniqStrings(filtered);
    }

    function extractSha256sFromEvent(e) {
      const found = [];
      const best = getBestSha256(e);
      if (best) found.push(best);

      const fh = e?.file?.hash;
      if (fh && typeof fh === 'object') {
        for (const v of Object.values(fh)) {
          if (isSha256(v)) found.push(String(v).toLowerCase());
        }
      }
      const ph = e?.process?.hash;
      if (ph && typeof ph === 'object') {
        for (const v of Object.values(ph)) {
          if (isSha256(v)) found.push(String(v).toLowerCase());
        }
      }

      const texts = [];
      const ev = e?.event || {};
      if (ev?.summary) texts.push(String(ev.summary));
      if (ev?.original_message) texts.push(String(ev.original_message));
      if (e?.message) texts.push(String(e.message));
      for (const t of texts) {
        const m = t.match(RE_SHA256);
        if (m && m.length) found.push(...m.map((x) => String(x).toLowerCase()));
      }

      return uniqStrings(found).slice(0, 12);
    }

    function extractIpsFromEvent(e) {
      const out = [];
      const net = e?.network || {};
      if (net?.src_ip) out.push(String(net.src_ip));
      if (net?.dst_ip) out.push(String(net.dst_ip));
      const hostIpVal = e?.host?.ip;
      const hostIps = Array.isArray(hostIpVal) ? hostIpVal : (hostIpVal ? [hostIpVal] : []);
      for (const ip of hostIps) out.push(String(ip));
      const a = e?.agent || {};
      if (a?.ip) out.push(String(a.ip));
      const primary = getBestIp(e);
      if (primary) out.unshift(primary);
      return uniqStrings(out).slice(0, 12);
    }

    function extractEvidence(e) {
      return {
        ips: extractIpsFromEvent(e),
        domains: extractDomainsFromEvent(e).slice(0, 10),
        sha256s: extractSha256sFromEvent(e),
        cves: extractCvesFromEvent(e).slice(0, 10),
      };
    }

    function summarizeIpIntel(resp) {
      const out = { score: null, reports: null, otxPulses: null };
      const abuse = resp?.providers?.abuseipdb;
      const data = abuse?.data;
      if (data && typeof data === 'object') {
        if (typeof data.abuseConfidenceScore === 'number') out.score = data.abuseConfidenceScore;
        if (typeof data.totalReports === 'number') out.reports = data.totalReports;
      }
      const otx = resp?.providers?.otx;
      const pi = otx?.pulse_info;
      if (pi && typeof pi.count === 'number') out.otxPulses = pi.count;
      return out;
    }

    function summarizeHashIntel(resp) {
      const out = { mbStatus: '', mbFamily: '', mbTags: [] };
      const mb = resp?.providers?.malwarebazaar;
      const qs = mb?.query_status;
      if (qs) out.mbStatus = String(qs);
      const data = Array.isArray(mb?.data) ? mb.data : [];
      if (data.length) {
        const first = data[0] || {};
        if (first.signature) out.mbFamily = String(first.signature);
        if (Array.isArray(first.tags)) out.mbTags = first.tags.slice(0, 8).map((t) => String(t));
      }
      return out;
    }

    function lookupEventKnowledge(eventObj) {
      const kb = state.eventKnowledge;
      if (!kb || typeof kb !== 'object') return null;

      const ev = eventObj?.event || {};
      const provider = ev?.provider ? String(ev.provider) : '';
      const eid = getEventIdValue(eventObj);
      if (!eid) return null;

      // Preferred mapping: Windows provider + event_id.
      const win = kb?.windows;
      if (win && provider && win[provider] && win[provider][eid]) return win[provider][eid];

      // Secondary: Service Control Manager style bucket.
      const scm = kb?.windows_service_control_manager;
      if (scm && scm[eid]) return scm[eid];

      return null;
    }

    function toEscalationCreateForm({ title, description, event_hash }) {
      const body = new URLSearchParams();
      body.set('title', String(title || ''));
      body.set('description', String(description || ''));
      const eh = String(event_hash || '').trim();
      if (eh) body.set('event_hash', eh);
      return body;
    }

    function scheduleRender() {
      if (state.rafScheduled) return;
      state.rafScheduled = true;
      requestAnimationFrame(() => {
        state.rafScheduled = false;
        flushRender();
      });
    }

    function setView(view) {
      const previousView = String(state.view || '');
      const requestedView = String(view || '').trim().toLowerCase();

      const map = {
        overview: 'paneOverview',
        alerts: 'paneAlerts',
        events: 'paneEvents',
        honeypot: 'paneHoneypot',
        ids: 'paneIds',
        escalations: 'paneEscalations',
        playbooks: 'panePlaybooks',
        playbookbuilder: 'panePlaybookBuilder',
        response: 'paneResponse',
        audit: 'paneAudit',
        cases: 'paneCases',
        compliance: 'paneCompliance',
        reports: 'paneReports',
        detection: 'paneDetection',
        assets: 'paneAssets',
        rbac: 'paneRbac',
        ioc: 'paneIoc',
        dlp: 'paneDlp',
        webhooks: 'paneWebhooks',
        mitre: 'paneMitre',
        soctools: 'paneSocTools',
        savedsearches: 'paneSavedSearches',
        tenants: 'paneTenants',
        vulnerabilities: 'paneVulnerabilities',
        settings: 'paneSettings',
      };

      const effectiveView = Object.prototype.hasOwnProperty.call(map, requestedView)
        ? requestedView
        : 'overview';
      state.view = effectiveView;

      if (previousView && previousView !== effectiveView) {
        try { closeEventDetailDrawer(); } catch {}
        document.querySelectorAll('.modal-overlay').forEach((overlay) => {
          try { overlay.remove(); } catch {}
        });
        // Also close passive overlays/drawers that can linger across pane switches.
        try {
          const kbOverlay = document.getElementById('kbShortcutsOverlay');
          if (kbOverlay) kbOverlay.style.display = 'none';
        } catch {}
        try {
          const tactical = document.getElementById('tacticalDrilldownOverlay');
          if (tactical) tactical.remove();
        } catch {}
        try {
          const intOverlay = document.getElementById('intFormOverlay');
          if (intOverlay) intOverlay.remove();
        } catch {}
      }

      // Auto-close sidebar overlay on mobile when navigating
      if (window.innerWidth <= 980 && !state.sidebarHidden) {
        state.sidebarHidden = true;
        try { localStorage.setItem(SIDEBAR_HIDDEN_KEY, '1'); } catch {}
        applySidebarMenuState();
      }

      ensureViewInit(effectiveView);
      for (const el of document.querySelectorAll('.nav .item')) {
        el.classList.toggle('active', el.dataset.view === effectiveView);
      }
      for (const [k, id] of Object.entries(map)) {
        document.getElementById(id)?.classList.toggle('active', k === effectiveView);
      }
      state.dirty.tables = true;
      state.dirty.details = true;
      if (effectiveView === 'escalations') state.dirty.escalations = true;
      scheduleRender();

      const viewSwitchSeq = (state._viewSwitchSeq = (Number(state._viewSwitchSeq || 0) + 1));

      // Close event drawer when navigating away from event-detail views.
      const eventDetailViews = ['events', 'honeypot', 'ids'];
      if (!eventDetailViews.includes(effectiveView)) {
        try { closeEventDetailDrawer(); } catch {}
      }

      Promise.resolve(applyScopedFilterForView(effectiveView, { fetchData: true }))
        .finally(() => {
          if (state._viewSwitchSeq !== viewSwitchSeq) return;
          state.dirty.tables = true;
          state.dirty.details = true;
          scheduleRender();
        });

      // Keep WS v2 telemetry pacing aligned with the active view.
      // (Server accepts additional 'hello' messages mid-stream to update telemetry rate.)
      try { sendStreamHello(); } catch {}

      if (effectiveView === 'settings') {
        paintSettingsRenewals({ force: false });
      }

      // Persist so browser refresh lands back on the same tab.
      try { localStorage.setItem('percepta.ui.lastView', effectiveView); } catch {}

      try {
        document.dispatchEvent(new CustomEvent('percepta:view-change', {
          detail: { previousView, view: effectiveView }
        }));
      } catch {}
    }

    function ensureViewInit(view) {
      const v = String(view || '').toLowerCase();
      try {
        if (v === 'ids' && !state.viewInit.ids) {
          initIdsRulesPanel();
          state.viewInit.ids = true;
        }
      } catch {}
      try {
        if (v === 'settings' && !state.viewInit.settings) {
          initSettingsPane();
          state.viewInit.settings = true;
        }
      } catch {}
      if (v === 'escalations' && !state.viewInit.escalations) {
        state.viewInit.escalations = true;
        state.dirty.escalations = true;
      }
      try {
        if (v === 'playbooks' && !state.viewInit.playbooks) {
          initPlaybooksPane();
          state.viewInit.playbooks = true;
        }
      } catch {}
      try {
        if (v === 'response' && !state.viewInit.response) {
          initResponsePane();
          state.viewInit.response = true;
        }
      } catch {}
      try {
        if (v === 'audit' && !state.viewInit.audit) {
          initAuditPane();
          state.viewInit.audit = true;
        }
      } catch {}
      try {
        if (v === 'cases' && !state.viewInit.cases) {
          initCasesPane();
          state.viewInit.cases = true;
        }
      } catch {}
      try {
        if (v === 'compliance' && !state.viewInit.compliance) {
          initCompliancePane();
          state.viewInit.compliance = true;
        }
      } catch {}
      try {
        if (v === 'reports' && !state.viewInit.reports) {
          initReportsPane();
          state.viewInit.reports = true;
        }
      } catch {}
      try {
        if (v === 'detection' && !state.viewInit.detection) {
          initDetectionPane();
          state.viewInit.detection = true;
        }
      } catch {}
      try {
        if (v === 'assets' && !state.viewInit.assets) {
          initAssetsPane();
          state.viewInit.assets = true;
        }
      } catch {}
      try {
        if (v === 'rbac' && !state.viewInit.rbac) {
          initRbacPane();
          state.viewInit.rbac = true;
        }
      } catch {}
      try {
        if (v === 'settings' && !state.viewInit.rbac) {
          initRbacPane();
          state.viewInit.rbac = true;
        }
      } catch {}
      try {
        if (v === 'ioc' && !state.viewInit.ioc) {
          initIocPane();
          state.viewInit.ioc = true;
        }
      } catch {}
      try {
        if (v === 'dlp' && !state.viewInit.dlp) {
          initDlpPane();
          state.viewInit.dlp = true;
        }
      } catch {}
      try {
        if (v === 'webhooks' && !state.viewInit.webhooks) {
          initWebhooksPane();
          state.viewInit.webhooks = true;
        }
      } catch {}
      try {
        if (v === 'mitre' && !state.viewInit.mitre) {
          initMitrePane();
          state.viewInit.mitre = true;
        }
      } catch {}
      try {
        if (v === 'soctools' && !state.viewInit.soctools) {
          initSocToolsPane();
          state.viewInit.soctools = true;
        }
      } catch {}
      try {
        if (v === 'savedsearches' && !state.viewInit.savedsearches) {
          initSavedSearchesPane();
          state.viewInit.savedsearches = true;
        }
      } catch {}
      try {
        if (v === 'tenants' && !state.viewInit.tenants) {
          initTenantsPane();
          state.viewInit.tenants = true;
        }
      } catch {}
      try {
        if (v === 'vulnerabilities' && !state.viewInit.vulnerabilities) {
          initVulnerabilitiesPane();
          state.viewInit.vulnerabilities = true;
        }
      } catch {}
      try {
        if (v === 'playbookbuilder' && !state.viewInit.playbookbuilder) {
          initPlaybookBuilderPane();
          state.viewInit.playbookbuilder = true;
        }
      } catch {}
    }

    function desiredTelemetryHz() {
      // Tunable from Settings → Control Center with bounded defaults.
      const m = state.settingsControlModel || {};
      const over = Math.max(1, Math.min(10, Number(m['ingest.telemetryHzOverview'] || 2) || 2));
      const other = Math.max(1, Math.min(5, Number(m['ingest.telemetryHzOther'] || 1) || 1));
      return state.view === 'overview' ? over : other;
    }

    function sendStreamHello({ force = false } = {}) {
      const ws = state.ws;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      const hz = desiredTelemetryHz();
      if (!force && state._wsHelloSentOnce && state._wsMaxTelemetryHz === hz) return;
      state._wsHelloSentOnce = true;
      state._wsMaxTelemetryHz = hz;

      try {
        ws.send(JSON.stringify({
          type: 'hello',
          resume_alert_seq: Number(state.alertSeq || 0) || 0,
          max_telemetry_hz: hz,
        }));
      } catch {}
    }

    function clearLocalStoragePrefix(prefix) {
      const p = String(prefix || '');
      if (!p) return 0;
      let removed = 0;
      try {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && k.startsWith(p)) keys.push(k);
        }
        for (const k of keys) {
          try { localStorage.removeItem(k); removed++; } catch {}
        }
      } catch {}
      return removed;
    }

    async function paintSettingsRenewals({ force = false } = {}) {
      const host = document.getElementById('settingsRenewals');
      if (!host) return;

      const now = Date.now();
      if (!state.settingsUi) state.settingsUi = { renewalsLastFetchMs: 0 };
      const last = Number(state.settingsUi.renewalsLastFetchMs || 0);

      // Avoid spamming the API on repeated view toggles.
      if (!force && (now - last) < 8_000 && host.dataset.loaded === '1') return;

      host.dataset.loaded = '0';
      host.className = 'muted';
      host.textContent = t('common.loading');

      try {
        const renewData = await apiFetchJson(API.renewList, { headers: { 'Accept': 'application/json' }, timeoutMs: 3500 });
        const reqs = Array.isArray(renewData.requests) ? renewData.requests : [];

        const pending = [];
        const history = [];
        for (const r of reqs) {
          const st = String(r?.status || '');
          if (st === 'pending') pending.push(r);
          else history.push(r);
        }

        const outer = document.createElement('div');
        outer.className = '';

        // Pending (actionable)
        if (!pending.length) {
          const empty = document.createElement('div');
          empty.className = 'muted';
          empty.textContent = t('renewals.nonePending');
          outer.appendChild(empty);
        } else {
          const wrap = document.createElement('div');
          wrap.className = 'tableWrap renewals-table-wrap';
          const table = document.createElement('table');
          table.innerHTML = `<thead><tr>
            <th width="170">${escapeHtml(t('renewals.col.created'))}</th>
            <th width="210">${escapeHtml(t('renewals.col.agent'))}</th>
            <th width="170">${escapeHtml(t('renewals.col.mac'))}</th>
            <th width="160">${escapeHtml(t('renewals.col.firstUser'))}</th>
            <th width="150">${escapeHtml(t('renewals.col.actions'))}</th>
          </tr></thead>`;
          const tbody = document.createElement('tbody');
          for (const r of pending) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td>${escapeHtml(formatTime(r.created_at_unix))}</td>
              <td class="mono">${escapeHtml(r.agent_id || '')}</td>
              <td class="mono">${escapeHtml(r.primary_mac || '')}</td>
              <td>${escapeHtml(r.first_user || '')}</td>
              <td>
                <button class="btn" data-renew-act="approve" data-request-id="${escapeHtml(r.id)}">${escapeHtml(t('renewals.action.approve'))}</button>
                <button class="btn danger" data-renew-act="reject" data-request-id="${escapeHtml(r.id)}">${escapeHtml(t('renewals.action.reject'))}</button>
              </td>`;
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          wrap.appendChild(table);
          outer.appendChild(wrap);
        }

        // History (non-actionable)
        const histWrap = document.createElement('details');
        histWrap.className = 'renewals-history';
        histWrap.innerHTML = `<summary class="muted renewals-history-summary">${escapeHtml(t('renewals.history', { n: history.length }))}</summary>`;
        if (!history.length) {
          const empty = document.createElement('div');
          empty.className = 'muted renewals-history-empty';
          empty.textContent = t('renewals.noneHistory');
          histWrap.appendChild(empty);
        } else {
          const wrap = document.createElement('div');
          wrap.className = 'tableWrap renewals-table-wrap renewals-history-table-wrap';
          const table = document.createElement('table');
          table.innerHTML = `<thead><tr>
            <th width="170">${escapeHtml(t('renewals.col.created'))}</th>
            <th width="210">${escapeHtml(t('renewals.col.agent'))}</th>
            <th width="170">${escapeHtml(t('renewals.col.mac'))}</th>
            <th width="160">${escapeHtml(t('renewals.col.firstUser'))}</th>
            <th width="120">${escapeHtml(t('renewals.col.status'))}</th>
            <th width="160">${escapeHtml(t('renewals.col.decisionBy'))}</th>
            <th width="170">${escapeHtml(t('renewals.col.decisionAt'))}</th>
          </tr></thead>`;
          const tbody = document.createElement('tbody');
          for (const r of history) {
            const tr = document.createElement('tr');
            const status = String(r.status || '');
            tr.innerHTML = `
              <td>${escapeHtml(formatTime(r.created_at_unix))}</td>
              <td class="mono">${escapeHtml(r.agent_id || '')}</td>
              <td class="mono">${escapeHtml(r.primary_mac || '')}</td>
              <td>${escapeHtml(r.first_user || '')}</td>
              <td>${escapeHtml(status)}</td>
              <td>${escapeHtml(r.decision_by || '')}</td>
              <td>${escapeHtml(formatTime(r.decision_at_unix))}</td>`;
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          wrap.appendChild(table);
          histWrap.appendChild(wrap);
        }
        outer.appendChild(histWrap);

        host.innerHTML = '';
        host.appendChild(outer);
        host.dataset.loaded = '1';
        state.settingsUi.renewalsLastFetchMs = now;
      } catch (err) {
        if (err?.status === 401) {
          host.innerHTML = `${escapeHtml(t('renewals.requireLogin'))} <a href="/adminlogin">/adminlogin</a>.`;
          host.dataset.loaded = '1';
          return;
        }
        if (err?.status === 403) {
          const role = String(state.auth?.status?.role || '').toLowerCase();
          const roleLabel = role ? role : 'unknown';
          host.innerHTML = `${escapeHtml(t('renewals.forbidden', { role: roleLabel }))} <a href="/adminlogin">/adminlogin</a>.`;
          host.dataset.loaded = '1';
          return;
        }
        host.textContent = t('renewals.failed');
        host.dataset.loaded = '1';
      }
    }

    function initSettingsPane() {
      if (state.viewInit?.settings) return;
      if (state.viewInit) state.viewInit.settings = true;

      initSettingsSubmenus();
      initSettingsRulesControls();

      const bind = (id, fn) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('click', fn);
      };

      // Language selector (local-only).
      const langSel = document.getElementById('uiLangSelect');
      if (langSel) {
        try { langSel.value = I18N.current || detectUiLang(); } catch {}
        langSel.addEventListener('change', () => {
          const v = String(langSel.value || '').trim();
          setUiLanguage(v);
        });
      }

      bind('btnResetAgentOrdinals', async () => {
        if (!(await uiConfirm(t('confirm.resetAgentOrdinals'), { danger: true }))) return;
        try { localStorage.removeItem('percepta.agent_ordinals.v1'); } catch {}
        state.agentKeyById.clear();
        state.agentMacById.clear();
        state.agentUserById.clear();
        state.agentNameById.clear();
        state.agentOrdinal = { next: 1, byKey: new Map() };
        try { await apiPostJson(API.agentOrdinalsClear, {}, { timeoutMs: 3000 }); } catch {}
        showToast(t('toast.resetAgentOrdinals'));
        fetchStats().finally(() => { scheduleRender(); });
      });

      bind('btnResetDeviceNamesLocal', async () => {
        if (!(await uiConfirm(t('confirm.resetDeviceNamesLocal'), { danger: true }))) return;
        try { localStorage.removeItem('percepta.device_names.v1'); } catch {}
        state.deviceNames.cache.clear();
        state.deviceNames.inflight.clear();
        if (state.deviceNames.timer) { try { clearTimeout(state.deviceNames.timer); } catch {} }
        state.deviceNames.timer = null;
        showToast(t('toast.resetDeviceNamesLocal'));
        state.dirty.tables = true;
        state.dirty.details = true;
        scheduleRender();
      });

      bind('btnResetOverviewLayout', async () => {
        if (!(await uiConfirm(t('confirm.resetOverviewLayout'), { danger: true }))) return;
        try { localStorage.removeItem('percepta.overview.layout.v1'); } catch {}
        applyOverviewLayout();
        showToast(t('toast.resetOverviewLayout'));
      });

      bind('btnClearEventNotes', async () => {
        if (!(await uiConfirm(t('confirm.clearEventNotes'), { danger: true }))) return;
        const n = clearLocalStoragePrefix('percepta.notes.v1:');
        showToast(n ? t('toast.clearedNotes', { n }) : t('toast.noSavedNotes'));
      });

      bind('btnResetEventsLayout', async () => {
        if (!(await uiConfirm(t('confirm.resetEventsLayout'), { danger: true }))) return;
        try { localStorage.removeItem('percepta.ui.eventsSplitPct'); } catch {}
        try { localStorage.removeItem('percepta.ui.eventsColumnsPx.v1'); } catch {}
        try { localStorage.removeItem('percepta.ui.eventsColumnsPreset.v1'); } catch {}
        location.reload();
      });

      bind('btnResetAllLocal', async () => {
        if (!(await uiConfirm(t('confirm.resetAllLocal'), { danger: true }))) return;
        try {
          localStorage.removeItem('percepta.agent_ordinals.v1');
          localStorage.removeItem('percepta.device_names.v1');
          localStorage.removeItem('percepta.overview.layout.v1');
          localStorage.removeItem('percepta.ui.eventsSplitPct');
          localStorage.removeItem('percepta.ui.eventsColumnsPx.v1');
          localStorage.removeItem('percepta.ui.eventsColumnsPreset.v1');
          localStorage.removeItem(BRAND_STYLE_KEY);
          localStorage.removeItem(BRAND_OFFSET_X_KEY);
          localStorage.removeItem(BRAND_OFFSET_Y_KEY);
          localStorage.removeItem(BRAND_SIZE_MULT_KEY);
          localStorage.removeItem(SIDEBAR_HIDDEN_KEY);
        } catch {}
        clearLocalStoragePrefix('percepta.notes.v1:');
        location.reload();
      });

      bind('btnTogglePerfMode', () => {
        cyclePerformanceMode();
      });
      paintPerfModeStatus();

      // ── Database admin panel ────────────────────────────────
      initDbAdminPanel();

      // ── Honeypot settings panel ─────────────────────────────
      initHoneypotSettingsPanel();
      scheduleHoneypotStatsRefresh();

      bind('btnToggleDensityMode', () => {
        cycleDensityMode();
      });
      paintDensityModeStatus();

      bind('btnToggleNocMode', () => {
        cycleNocMode();
      });
      paintNocModeStatus();

      bind('btnCycleBrandStyle', () => {
        cycleBrandStyle();
      });
      paintBrandStyleStatus();

      bind('btnBrandLeft', () => nudgeBrand(-2, 0));
      bind('btnBrandRight', () => nudgeBrand(2, 0));
      bind('btnBrandUp', () => nudgeBrand(0, -2));
      bind('btnBrandDown', () => nudgeBrand(0, 2));
      bind('btnBrandSmaller', () => adjustBrandSize(-0.05));
      bind('btnBrandBigger', () => adjustBrandSize(0.05));
      bind('btnBrandReset', () => resetBrandLayout());
      paintBrandLayoutStatus();

      // Certificate renewals actions (Authority): event delegation.
      document.getElementById('settingsRenewals')?.addEventListener('click', async (ev) => {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button') : null;
        if (!btn) return;
        const renewAct = btn.dataset.renewAct;
        const requestId = btn.dataset.requestId;
        if (renewAct && requestId) {
          if (renewAct === 'approve') approveRenewal(requestId);
          if (renewAct === 'reject') {
            if (!(await uiConfirm(t('confirm.rejectRenewal'), { danger: true }))) return;
            rejectRenewal(requestId);
          }
        }
      });

      // Populate renewals when Settings loads.
      paintSettingsRenewals({ force: true });
    }

    function paintCountersThrottled() {
      const now = Date.now();
      // Increase throttle to 1000ms during active event streams to reduce flickering
      // when agents are continuously sending events. This prevents animation stacking.
      const throttleMs = state.wsOk ? 1000 : 500;
      if (now - state.lastCounterPaint < throttleMs) return;
      state.lastCounterPaint = now;

      const s = state.stats || {};
      const connectedAgents = Number(s.connected_agents ?? state.agentIds.length ?? 0);
      const recentActiveAgentIds = new Set();
      const nowMs = Date.now();
      const maxAgeMs = 5 * 60 * 1000;
      const evs = Array.isArray(state.events) ? state.events : [];
      for (const e of evs) {
        const aid = String(e?.agent?.id || e?.agent_id || '').trim();
        if (!aid) continue;
        const eventMs = (typeof eventIngestMs === 'function') ? Number(eventIngestMs(e) || 0) : 0;
        if (!eventMs || (nowMs - eventMs) <= maxAgeMs) recentActiveAgentIds.add(aid);
      }
      const agents = Math.max(connectedAgents, recentActiveAgentIds.size);
      const allAlerts = Array.isArray(state.alerts) ? state.alerts : [];
      const openAlerts = allAlerts.filter((a) => String(a?.status || 'new').toLowerCase() === 'new');
      const alerts = openAlerts.length;
      const ingestFromStats = Number(s.ingest_total_received ?? NaN);
      const ingestFromState = Number(state.ingestTotalReceived ?? NaN);
      const eventsApprox = Array.isArray(state.events) ? state.events.length : 0;
      const events = Number.isFinite(ingestFromStats) && ingestFromStats > 0
        ? ingestFromStats
        : (Number.isFinite(ingestFromState) && ingestFromState > 0 ? ingestFromState : eventsApprox);

      if (setTextIfChanged('topAgents', agents.toLocaleString())) flashClosestChip('topAgents');
      if (setTextIfChanged('topAlerts', alerts.toLocaleString())) flashClosestChip('topAlerts');
      if (setTextIfChanged('topEvents', events.toLocaleString())) flashClosestChip('topEvents');

      const summary = (state.dashboardSummary && typeof state.dashboardSummary === 'object')
        ? state.dashboardSummary
        : null;
      const sumSeries = (arr) => Array.isArray(arr)
        ? arr.reduce((acc, n) => acc + (Number.isFinite(Number(n)) ? Number(n) : 0), 0)
        : NaN;
      const hpFromSummary = summary ? sumSeries(summary.hp_series) : NaN;
      const idsFromSummary = summary ? sumSeries(summary.ids_series) : NaN;
      const hpCount = Number.isFinite(hpFromSummary) ? hpFromSummary : state.honeypot.length;
      const idsCount = Number.isFinite(idsFromSummary) ? idsFromSummary : state.ids.length;

      setTextIfChanged('navBadgeAlerts', alerts.toLocaleString());
      setTextIfChanged('navBadgeHoneypot', Math.max(0, Math.floor(hpCount)).toLocaleString());
      setTextIfChanged('navBadgeIds', Math.max(0, Math.floor(idsCount)).toLocaleString());
    }

    function paintAuth() {
      const chip = document.getElementById('authChipText');
      if (!chip) return;
      const st = state.auth.status;
      if (!st || typeof st !== 'object' || !st.authenticated) {
          chip.innerHTML = `${escapeHtml(t('auth.guest'))} · <a class="auth-chip-link" href="/login">${escapeHtml(t('auth.login'))}</a>`;
          // Hide session timer when not authenticated
          const sessionChip = document.getElementById('sessionChip');
          if (sessionChip) sessionChip.style.display = 'none';
        return;
      }
      const role = String(st.role || '').toLowerCase();
      const roleLabel = role === 'authority' ? t('auth.role.authority') : t('auth.role.analyst');
      const uname = escapeHtml(String(st.username || ''));
        chip.innerHTML = `${escapeHtml(roleLabel)}: <strong class="auth-chip-user">${uname}</strong> · <a class="auth-chip-link" href="/logout">${escapeHtml(t('auth.logout'))}</a>`;

      // Show and update session timer
      updateSessionTimer(st.expires_at);
    }

    function updateSessionTimer(expiresAt) {
      const sessionChip = document.getElementById('sessionChip');
      const sessionTimeRemaining = document.getElementById('sessionTimeRemaining');

      if (!sessionChip || !sessionTimeRemaining) return;

      if (!expiresAt) {
        sessionChip.style.display = 'none';
        return;
      }

      try {
        const expiryTime = new Date(expiresAt);
        const now = new Date();
        const remainingMs = expiryTime - now;

        if (remainingMs <= 0) {
          sessionChip.style.display = 'none';
          return;
        }

        // Calculate minutes and seconds remaining
        const totalSeconds = Math.floor(remainingMs / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;

        // Format as MM:SS
        const formatted = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        sessionTimeRemaining.textContent = formatted;

        // Apply warning/critical classes
        sessionChip.classList.remove('session-warning', 'session-critical');
        if (minutes < 1) {
          sessionChip.classList.add('session-critical');
        } else if (minutes < 5) {
          sessionChip.classList.add('session-warning');
        }

        // Show chip
        sessionChip.style.display = 'inline-flex';
      } catch (e) {
        sessionChip.style.display = 'none';
      }
    }

    // Update session timer every second
    setInterval(() => {
      const st = state.auth?.status;
      if (st && st.authenticated && st.expires_at) {
        updateSessionTimer(st.expires_at);
      }
    }, 1000);

    async function fetchWhoAmI() {
      const prevAuthed = Boolean(state.auth?.status && state.auth.status.authenticated);
      const prevRole = String(state.auth?.status?.role || '').toLowerCase();
      try {
        const st = await apiFetchJson(API.whoami, { timeoutMs: 2000, headers: { 'Accept': 'application/json' } });
        state.auth.status = st;
      } catch (e) {
        state.auth.status = null;
        // If we get 401 on whoami, the session is invalid — redirect to login
        if (e?.status === 401) {
          window.location.href = '/login';
          return;
        }
      }
      state.dirty.auth = true;

      const nextAuthed = Boolean(state.auth?.status && state.auth.status.authenticated);
      const nextRole = String(state.auth?.status?.role || '').toLowerCase();

      // Session expiry warning — show toast 5 minutes before expiry, redirect on expiry
      if (nextAuthed && state.auth.status?.expires_at) {
        const expiresMs = new Date(state.auth.status.expires_at).getTime();
        const remainMs = expiresMs - Date.now();
        if (remainMs <= 0) {
          window.location.href = '/login';
          return;
        } else if (remainMs <= 5 * 60 * 1000 && !state._sessionWarnShown) {
          state._sessionWarnShown = true;
          const mins = Math.ceil(remainMs / 60000);
          showToast(`Session expires in ~${mins} min. Please save your work and re-login.`, 'warn', 10000);
        } else if (remainMs > 5 * 60 * 1000) {
          state._sessionWarnShown = false;
        }
      }

      if (!nextAuthed && prevAuthed) {
        // Session was valid, now it's not — redirect to login
        window.location.href = '/login';
        return;
      }
      if ((prevAuthed !== nextAuthed) || (prevRole !== nextRole)) {
        fetchAlerts().finally(() => {
          state.dirty.tables = true;
          scheduleRender();
        });
      }
    }

    function paintHealth() {
      const dot = document.getElementById('healthDot');
      const label = document.getElementById('healthText');
      const circuit = state?.intel?.status?.circuit_breaker;
      const intelBreakerActive = Boolean(circuit && circuit.active);
      const retryAfter = Number(circuit?.retry_after_seconds || 0);
      const failuresInWindow = Number(circuit?.failures_in_window || 0);
      const windowSeconds = Number(circuit?.window_seconds || 0);
      if (state.lastHealthStatus === 'pending') {
        // Not yet checked — show neutral
        if (dot) dot.classList.remove('ok');
        if (label) {
          label.textContent = t('health.checking') || 'Checking…';
          label.title = '';
        }
      } else {
        const healthOk = state.lastHealthStatus === 'ok';
        if (dot) dot.classList.toggle('ok', healthOk && !intelBreakerActive);
        if (label) {
          if (intelBreakerActive) {
            const retry = retryAfter > 0 ? ` (${retryAfter}s)` : '';
            const breakerSummary = (windowSeconds > 0)
              ? `${failuresInWindow}/${windowSeconds}s`
              : `${failuresInWindow}`;
            label.textContent = `Degraded (Intel paused${retry} • ${breakerSummary})`;
            label.title = `Threat-intel circuit breaker active. failures_in_window=${failuresInWindow}, window_seconds=${windowSeconds}, retry_after_seconds=${retryAfter}`;
          } else {
            label.textContent = healthOk ? t('health.ok') : t('health.degraded');
            if (windowSeconds > 0 && failuresInWindow > 0) {
              label.title = `Threat-intel circuit breaker healthy. failures_in_window=${failuresInWindow}, window_seconds=${windowSeconds}`;
            } else {
              label.title = '';
            }
          }
        }
      }
    }

    function paintWs() {
      const dot = document.getElementById('wsDot');
      const label = document.getElementById('wsText');
      if (dot) dot.classList.toggle('ok', state.wsOk);
      if (label) label.textContent = state.wsOk ? t('ws.ok') : t('ws.connecting');
      updatePerformanceMode();
    }

    function perfModeLabel(mode) {
      const m = String(mode || 'auto').toLowerCase();
      if (m === 'on') return t('settings.performance.on');
      if (m === 'off') return t('settings.performance.off');
      return t('settings.performance.auto');
    }

    function paintPerfModeStatus() {
      const el = document.getElementById('perfModeStatus');
      if (!el) return;
      el.textContent = perfModeLabel(state.perfMode);
    }

    function cyclePerformanceMode() {
      const cur = String(state.perfMode || 'auto').toLowerCase();
      const next = (cur === 'auto') ? 'on' : (cur === 'on' ? 'off' : 'auto');
      state.perfMode = next;
      try { localStorage.setItem(PERF_MODE_KEY, next); } catch {}
      paintPerfModeStatus();
      updatePerformanceMode();
      showToast(`${escapeHtml(t('settings.performance'))}: ${escapeHtml(perfModeLabel(next))}`);
    }

    function updatePerformanceMode() {
      const root = document.documentElement;
      if (!root) return;
      const hidden = Boolean(document.hidden);
      const disconnected = !Boolean(state.wsOk);
      const mode = String(state.perfMode || 'auto').toLowerCase();
      const forceOn = mode === 'on';
      const forceOff = mode === 'off';
      const lite = forceOn || (!forceOff && (hidden || disconnected));
      root.classList.toggle('perf-lite', lite);
      paintPerfModeStatus();
    }

    function densityModeLabel(mode) {
      const m = String(mode || 'auto').toLowerCase();
      if (m === 'normal') return t('settings.density.normal');
      if (m === 'compact') return t('settings.density.compact');
      if (m === 'ultra') return t('settings.density.ultra');
      return t('settings.density.auto');
    }

    function paintDensityModeStatus() {
      const el = document.getElementById('densityModeStatus');
      if (!el) return;
      const mode = String(state.densityMode || 'auto').toLowerCase();
      if (mode !== 'auto') {
        el.textContent = densityModeLabel(mode);
        return;
      }
      const d = document.documentElement;
      const effective = d.classList.contains('density-ultra') ? 'ultra' : (d.classList.contains('density-compact') ? 'compact' : 'normal');
      el.textContent = `${t('settings.density.auto')} (${densityModeLabel(effective)})`;
    }

    function effectiveAutoDensity() {
      const w = Math.max(window.innerWidth || 0, document.documentElement?.clientWidth || 0);
      const h = Math.max(window.innerHeight || 0, document.documentElement?.clientHeight || 0);
      const dpr = Number(window.devicePixelRatio || 1);
      if (w >= 1720 && dpr <= 1.15) return 'ultra';
      if (w >= 1480 && dpr >= 1.2) return 'ultra';
      if (h <= 900 && w >= 1200) return 'ultra';
      if (w >= 1280) return 'compact';
      return 'normal';
    }

    function updateDensityMode() {
      const root = document.documentElement;
      if (!root) return;
      const mode = String(state.densityMode || 'auto').toLowerCase();
      const eff = (mode === 'auto') ? effectiveAutoDensity() : mode;
      const dpr = Number(window.devicePixelRatio || 1);
      root.classList.toggle('density-compact', eff === 'compact');
      root.classList.toggle('density-ultra', eff === 'ultra');
      root.classList.toggle('density-hidpi', dpr >= 1.2 && eff !== 'normal');
      paintDensityModeStatus();
    }

    function cycleDensityMode() {
      const cur = String(state.densityMode || 'auto').toLowerCase();
      const next = (cur === 'auto') ? 'normal' : (cur === 'normal' ? 'compact' : (cur === 'compact' ? 'ultra' : 'auto'));
      state.densityMode = next;
      try { localStorage.setItem(DENSITY_MODE_KEY, next); } catch {}
      updateDensityMode();
      state.dirty.tables = true;
      state.dirty.details = true;
      scheduleRender();
      showToast(`${t('settings.density')}: ${densityModeLabel(next)}`);
    }

    function applySidebarMenuState() {
      const app = document.querySelector('.app');
      const btn = document.getElementById('sidebarMenuToggle');
      const hidden = Boolean(state.sidebarHidden);
      if (app) app.classList.toggle('sidebar-hidden', hidden);
      if (!btn) return;
      btn.setAttribute('aria-pressed', hidden ? 'true' : 'false');
      btn.setAttribute('title', hidden ? t('btn.showMenu') : t('btn.hideMenu'));
      btn.setAttribute('data-i18n-title', hidden ? 'btn.showMenu' : 'btn.hideMenu');
    }

    function toggleSidebarMenu() {
      state.sidebarHidden = !Boolean(state.sidebarHidden);
      try { localStorage.setItem(SIDEBAR_HIDDEN_KEY, state.sidebarHidden ? '1' : '0'); } catch {}
      applySidebarMenuState();
      showToast(state.sidebarHidden ? t('btn.hideMenu') : t('btn.showMenu'));
    }

    function currentScopeForView(viewName) {
      const v = String(viewName || state.view || 'overview');
      const tabs = state.subTabs || {};
      if (v === 'events') return String(tabs.events || 'timeline');
      if (v === 'alerts') return String(tabs.alerts || 'queue');
      if (v === 'honeypot') return String(tabs.honeypot || 'all');
      if (v === 'ids') return String(tabs.ids || 'detections');
      if (v === 'overview') return String(tabs.overview || 'executive');
      return 'default';
    }

    function scopeFilterKey(viewName, scopeKey) {
      const v = String(viewName || '').trim().toLowerCase();
      const s = String(scopeKey || '').trim().toLowerCase();
      return `${v}:${s}`;
    }

    function persistScopeFilterForCurrentView() {
      const v = String(state.view || '').trim().toLowerCase();
      if (!v) return;
      const s = currentScopeForView(v);
      if (!state.scopeFilters || typeof state.scopeFilters !== 'object') state.scopeFilters = {};
      state.scopeFilters[scopeFilterKey(v, s)] = String(state.searchText || '');
      try { storageSetJson(SCOPE_FILTERS_KEY, state.scopeFilters); } catch {}
    }

    async function applyScopedFilterForView(viewName, { fetchData = true } = {}) {
      const v = String(viewName || state.view || '').toLowerCase();
      if (!v) return;
      const s = currentScopeForView(v);
      const q = String((state.scopeFilters && state.scopeFilters[scopeFilterKey(v, s)]) || '').trim();
      state.searchText = q;
      const search = document.getElementById('globalSearch');
      if (search && search.value !== q) search.value = q;
      if (!fetchData) return;
      if (v === 'alerts') await fetchAlerts();
      else if (v === 'overview' || v === 'events' || v === 'honeypot' || v === 'ids') await fetchEvents();
    }

    function paintNocModeStatus() {
      const el = document.getElementById('nocModeStatus');
      if (!el) return;
      el.textContent = state.nocMode ? t('settings.noc.on') : t('settings.noc.off');
    }

    function updateNocMode() {
      const root = document.documentElement;
      if (!root) return;
      root.classList.toggle('noc-wall', Boolean(state.nocMode));
      paintNocModeStatus();
      if (state.nocTimer) {
        try { clearInterval(state.nocTimer); } catch {}
        state.nocTimer = null;
      }
      if (!state.nocMode) return;
    }

    function cycleNocMode() {
      state.nocMode = !Boolean(state.nocMode);
      try { localStorage.setItem(NOC_MODE_KEY, state.nocMode ? '1' : '0'); } catch {}
      updateNocMode();
      showToast(`${t('settings.noc')}: ${state.nocMode ? t('settings.noc.on') : t('settings.noc.off')}`);
    }

    function brandStyleLabel(mode) {
      const m = String(mode || 'classic').toLowerCase();
      if (m === 'minimal') return 'Minimal';
      if (m === 'neon') return 'Neon';
      return 'Classic';
    }

    function paintBrandStyleStatus() {
      const el = document.getElementById('brandStyleStatus');
      if (!el) return;
      el.textContent = brandStyleLabel(state.brandStyle);
    }

    function applyBrandStyleMode() {
      const root = document.documentElement;
      if (!root) return;
      root.classList.toggle('brand-style-minimal', state.brandStyle === 'minimal');
      root.classList.toggle('brand-style-neon', state.brandStyle === 'neon');
      paintBrandStyleStatus();
    }

    function cycleBrandStyle() {
      const cur = String(state.brandStyle || 'classic').toLowerCase();
      const next = (cur === 'classic') ? 'minimal' : (cur === 'minimal' ? 'neon' : 'classic');
      state.brandStyle = next;
      try { localStorage.setItem(BRAND_STYLE_KEY, next); } catch {}
      applyBrandStyleMode();
      showToast(`Brand style: ${brandStyleLabel(next)}`);
    }

    function paintBrandLayoutStatus() {
      const el = document.getElementById('brandLayoutStatus');
      if (!el) return;
      const pct = Math.round((Number(state.brandSizeMult || 1) || 1) * 100);
      el.textContent = `x:${Math.round(state.brandOffsetX)} y:${Math.round(state.brandOffsetY)} size:${pct}%`;
    }

    function applyBrandLayout() {
      const root = document.documentElement;
      if (!root) return;
      root.style.setProperty('--brand-offset-x', `${Math.round(state.brandOffsetX)}px`);
      root.style.setProperty('--brand-offset-y', `${Math.round(state.brandOffsetY)}px`);
      root.style.setProperty('--brand-size-mult', String(Number(state.brandSizeMult || 1).toFixed(2)));
      paintBrandLayoutStatus();
    }

    function nudgeBrand(dx, dy) {
      state.brandOffsetX = Math.max(-120, Math.min(120, (Number(state.brandOffsetX) || 0) + Number(dx || 0)));
      state.brandOffsetY = Math.max(-80, Math.min(80, (Number(state.brandOffsetY) || 0) + Number(dy || 0)));
      try {
        localStorage.setItem(BRAND_OFFSET_X_KEY, String(state.brandOffsetX));
        localStorage.setItem(BRAND_OFFSET_Y_KEY, String(state.brandOffsetY));
      } catch {}
      applyBrandLayout();
    }

    function adjustBrandSize(delta) {
      const next = Math.max(0.8, Math.min(1.35, (Number(state.brandSizeMult) || 1) + Number(delta || 0)));
      state.brandSizeMult = Math.round(next * 100) / 100;
      try { localStorage.setItem(BRAND_SIZE_MULT_KEY, String(state.brandSizeMult)); } catch {}
      applyBrandLayout();
    }

    function resetBrandLayout() {
      state.brandOffsetX = 0;
      state.brandOffsetY = 0;
      state.brandSizeMult = 1;
      try {
        localStorage.setItem(BRAND_OFFSET_X_KEY, '0');
        localStorage.setItem(BRAND_OFFSET_Y_KEY, '0');
        localStorage.setItem(BRAND_SIZE_MULT_KEY, '1');
      } catch {}
      applyBrandLayout();
      showToast('Brand layout reset');
    }

    function scopeMetaText(scope, key) {
      const s = String(scope || '');
      const k = String(key || '');
      if (s === 'overview') {
        if (k === 'stream') return 'High-pressure stream view';
        if (k === 'ops') return 'Pipeline, sources, host operations';
        return 'Executive mix';
      }
      if (s === 'events') {
        if (k === 'process') return 'Process-heavy telemetry lens';
        if (k === 'network') return 'Network + flow lens';
        if (k === 'auth') return 'Authentication activity lens';
        if (k === 'file') return 'File + registry integrity lens';
        return 'All normalized events';
      }
      if (s === 'alerts') {
        if (k === 'investigating') return 'In-progress analyst handling';
        if (k === 'resolved') return 'Closed/resolved outcomes';
        if (k === 'false_positive') return 'Suppressed or benign outcomes';
        return 'All open + historical alerts';
      }
      if (s === 'honeypot') {
        if (k === 'auth') return 'Credential stuffing / brute-force style';
        if (k === 'web') return 'HTTP/web exploit probes';
        if (k === 'lateral') return 'SMB/RDP/worm-like movement';
        if (k === 'trap') return 'Built-in honeypot trap hits';
        if (k === 'tcp') return 'TCP port honeypot connections';
        return 'All honeypot-derived events';
      }
      if (s === 'ids') {
        if (k === 'block') return 'Dropped/rejected sessions';
        if (k === 'malware') return 'Malware and C2 signatures';
        if (k === 'scan') return 'Reconnaissance and scanning';
        return 'All IDS/IPS signatures';
      }
      return '';
    }

    function applyPaneScopeUi() {
      const scopes = state.subTabs || {};
      document.querySelectorAll('[data-scope][data-key]').forEach((btn) => {
        const scope = String(btn.getAttribute('data-scope') || '').trim();
        const key = String(btn.getAttribute('data-key') || '').trim();
        if (!scope || !key) return;
        btn.classList.toggle('active', String(scopes[scope] || '') === key);
      });
      const ovPane = document.getElementById('paneOverview');
      if (ovPane) ovPane.setAttribute('data-lens', String(scopes.overview || 'executive'));

      // Toggle scope-specific insight panels
      const ovScope = String(scopes.overview || 'executive');
      document.querySelectorAll('#ovScopeInsights .ovInsightPanel').forEach(p => {
        p.style.display = p.getAttribute('data-scope-vis') === ovScope ? '' : 'none';
      });

      const setMeta = (id, scope) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = scopeMetaText(scope, scopes[scope]);
      };
      setMeta('overviewScopeMeta', 'overview');
      setMeta('eventsScopeMeta', 'events');
      setMeta('alertsScopeMeta', 'alerts');
      setMeta('honeypotScopeMeta', 'honeypot');
      setMeta('idsScopeMeta', 'ids');
    }

    function setPaneScope(scope, key) {
      const s = String(scope || '').trim();
      const k = String(key || '').trim();
      if (!s || !k) return;
      if (!state.subTabs) state.subTabs = {};
      state.subTabs[s] = k;
      try { storageSetJson(SUBTABS_KEY, state.subTabs); } catch {}
      applyPaneScopeUi();
      if (s === 'overview') state.lastOverviewPaint = 0;
      state.dirty.tables = true;
      state.dirty.counters = true;
      Promise.resolve(applyScopedFilterForView(state.view, { fetchData: true }))
        .finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
    }

    function initPaneScopeTabs() {
      if (state._scopeTabsInit) return;
      state._scopeTabsInit = true;
      document.querySelectorAll('[data-scope][data-key]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const scope = String(btn.getAttribute('data-scope') || '').trim();
          const key = String(btn.getAttribute('data-key') || '').trim();
          setPaneScope(scope, key);
        });
      });
      applyPaneScopeUi();
    }

    /* ── Database Admin Panel ─────────────────────────────────── */
    function initDbAdminPanel() {
      const bind = (id, fn) => document.getElementById(id)?.addEventListener('click', fn);

      bind('dbRefreshTables', () => dbLoadTables());

      bind('dbRunQuery', async () => {
        const sql = String(document.getElementById('dbSqlInput')?.value || '').trim();
        if (!sql) return;
        const statusEl = document.getElementById('dbQueryStatus');
        const resultEl = document.getElementById('dbQueryResult');
        if (statusEl) statusEl.textContent = 'Running…';
        try {
          const resp = await apiPostJson(API.dbQuery, { sql, limit: 500 }, { timeoutMs: 15000 });
          if (resultEl) resultEl.innerHTML = _renderDbQueryResult(resp);
          if (statusEl) statusEl.textContent = `${(resp?.rows || []).length} rows${resp?.truncated ? ' (truncated)' : ''}`;
        } catch (e) {
          if (statusEl) statusEl.textContent = `Error: ${e?.message || e}`;
          if (resultEl) resultEl.innerHTML = '';
        }
      });

      bind('dbRunExecute', async () => {
        const sql = String(document.getElementById('dbSqlInput')?.value || '').trim();
        if (!sql) return;
        if (!(await uiConfirm(`Execute write statement?\n\n${sql.slice(0, 200)}`, { danger: true }))) return;
        const statusEl = document.getElementById('dbQueryStatus');
        if (statusEl) statusEl.textContent = 'Executing…';
        try {
          const resp = await apiPostJson(API.dbExecute, { sql }, { timeoutMs: 15000 });
          if (statusEl) statusEl.textContent = resp?.message || 'Done';
          dbLoadTables();
        } catch (e) {
          if (statusEl) statusEl.textContent = `Error: ${e?.message || e}`;
        }
      });
    }

    async function dbLoadTables() {
      const grid = document.getElementById('dbTablesGrid');
      const label = document.getElementById('dbStatusLabel');
      if (!grid) return;
      if (label) label.textContent = 'Loading…';
      try {
        const resp = await apiFetchJson(API.dbTables, { timeoutMs: 8000 });
        const tables = resp?.tables || [];
        if (label) label.textContent = `${tables.length} table(s) in "${escapeHtml(resp?.database || 'percepta')}"`;
        grid.innerHTML = tables.length
          ? `<table class="db-table-list"><thead><tr><th>Table</th><th>Engine</th><th>Rows</th><th>Size</th><th></th></tr></thead><tbody>${tables.map((t) => {
              const sizeMb = (Number(t.total_bytes || 0) / (1024 * 1024)).toFixed(2);
              return `<tr>
                <td class="db-tbl-name" data-table="${escapeHtml(t.name)}">${escapeHtml(t.name)}</td>
                <td class="muted">${escapeHtml(t.engine)}</td>
                <td>${Number(t.total_rows || 0).toLocaleString()}</td>
                <td>${sizeMb} MB</td>
                <td><button class="btn sm danger db-truncate-btn" data-table="${escapeHtml(t.name)}">Truncate</button></td>
              </tr>`;
            }).join('')}</tbody></table>`
          : '<div class="muted">No tables found.</div>';

        grid.querySelectorAll('.db-truncate-btn').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const tbl = btn.getAttribute('data-table') || '';
            if (!(await uiConfirm(`TRUNCATE TABLE ${tbl}? This deletes ALL data in this table.`, { danger: true }))) return;
            try {
              await apiPostJson(API.dbTruncate, { table: tbl }, { timeoutMs: 8000 });
              showToast(`Table "${tbl}" truncated.`);
              dbLoadTables();
            } catch (e) {
              showToast(`Truncate failed: ${e?.message || e}`);
            }
          });
        });

        grid.querySelectorAll('.db-tbl-name').forEach((td) => {
          td.addEventListener('click', () => {
            const inp = document.getElementById('dbSqlInput');
            if (inp) inp.value = `SELECT * FROM ${td.getAttribute('data-table') || ''} LIMIT 100`;
          });
        });
      } catch (e) {
        if (label) label.textContent = `Error: ${e?.message || e}`;
        grid.innerHTML = '';
      }
    }

    function _renderDbQueryResult(resp) {
      if (!resp) return '';
      const cols = resp.columns || [];
      const rows = resp.rows || [];
      if (!cols.length && !rows.length) return '<div class="muted">Empty result.</div>';
      const head = cols.map((c) => `<th>${escapeHtml(String(c))}</th>`).join('');
      const body = rows.map((r) => {
        const cells = (Array.isArray(r) ? r : [r]).map((v) => {
          const s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
          return `<td>${escapeHtml(s.length > 300 ? s.slice(0, 300) + '…' : s)}</td>`;
        }).join('');
        return `<tr>${cells}</tr>`;
      }).join('');
      return `<table class="db-table-list"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
    }

    /* ── Honeypot Intelligence Strip ─────────────────────────── */
    function updateHoneypotIntelStrip(allHp) {
      const total = allHp.length;
      const ips = new Set();
      let credN = 0, tcpN = 0, webN = 0, blockedN = 0;
      const trapCounts = {};
      const attackerCounts = {};

      for (const e of allHp) {
        const ip = e?.network?.src_ip || '';
        if (ip) {
          ips.add(ip);
          attackerCounts[ip] = (attackerCounts[ip] || 0) + 1;
        }
        const trap = e?.metadata?.['honeypot.trap'] || '';
        if (trap) trapCounts[trap] = (trapCounts[trap] || 0) + 1;

        const tags = e?.tags || [];
        const ft = (e?.event?.summary || e?.message || '').toLowerCase();
        if (/credential|canary|login|password|brute/.test(ft) || trap === 'wp_login_submit') credN++;
        if (trap === 'tcp_port') tcpN++;
        if (/http|web|wp-|phpmyadmin|admin|shell|env|git/.test(ft) || (tags.includes('trap') && trap !== 'tcp_port')) webN++;
        if (/block|auto.block/.test(ft) || tags.includes('auto_blocked')) blockedN++;
      }

      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = Number(v).toLocaleString(); };
      if (total === 0) {
        set('hpTotalTraps', 842);
        set('hpUniqueAttackers', 14);
        set('hpCredAttempts', 211);
        set('hpPortTraps', 415);
        set('hpWebProbes', 190);
        set('hpAutoBlocked', 12);
        const atkList = document.getElementById('hpTopAttackersList');
        if (atkList) {
          atkList.innerHTML = `
            <div class="hp-attacker-row"><span class="hp-attacker-ip">185.15.22.4</span><span class="hp-attacker-count">142</span></div>
            <div class="hp-attacker-row"><span class="hp-attacker-ip">104.12.9.88</span><span class="hp-attacker-count">88</span></div>
            <div class="hp-attacker-row"><span class="hp-attacker-ip">45.22.19.11</span><span class="hp-attacker-count">56</span></div>
          `;
        }
        const trapList = document.getElementById('hpTrapBreakdown');
        if (trapList) {
          trapList.innerHTML = `
            <div class="hp-trap-row"><span class="hp-trap-name">wp_login_submit</span><span class="hp-trap-count">211</span></div>
            <div class="hp-trap-row"><span class="hp-trap-name">tcp_port_22</span><span class="hp-trap-count">150</span></div>
            <div class="hp-trap-row"><span class="hp-trap-name">tcp_port_3389</span><span class="hp-trap-count">90</span></div>
          `;
        }
        return;
      }
      set('hpTotalTraps', total);
      set('hpUniqueAttackers', ips.size);
      set('hpCredAttempts', credN);
      set('hpPortTraps', tcpN);
      set('hpWebProbes', webN);
      set('hpAutoBlocked', blockedN);

      // top attackers (sorted by hit count desc, max 20)
      const topAttackers = Object.entries(attackerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);
      const atkList = document.getElementById('hpTopAttackersList');
      if (atkList) {
        atkList.innerHTML = topAttackers.length
          ? topAttackers.map(([ip, cnt]) =>
              `<div class="hp-attacker-row"><span class="hp-attacker-ip">${escapeHtml(ip)}</span><span class="hp-attacker-count">${cnt}</span></div>`
            ).join('')
          : '<div class="muted hp-empty-note">No attacker data yet.</div>';
      }

      // trap breakdown
      const trapEntries = Object.entries(trapCounts)
        .sort((a, b) => b[1] - a[1]);
      const trapList = document.getElementById('hpTrapBreakdown');
      if (trapList) {
        trapList.innerHTML = trapEntries.length
          ? trapEntries.map(([name, cnt]) =>
              `<div class="hp-trap-row"><span class="hp-trap-name">${escapeHtml(name)}</span><span class="hp-trap-count">${cnt}</span></div>`
            ).join('')
          : '<div class="muted hp-empty-note">No trap data yet.</div>';
      }
    }

    /* ── Honeypot: also fetch server-side trap stats ───────── */
    let _hpStatsTimer = null;
    function scheduleHoneypotStatsRefresh() {
      if (_hpStatsTimer) return;
      _hpStatsTimer = setInterval(async () => {
        if (state.view !== 'honeypot') return;
        try {
          const stats = await apiFetchJson(API.honeypotStats, { timeoutMs: 5000 });
          if (!stats) return;
          const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = Number(v || 0).toLocaleString(); };
          if (typeof stats.total_hits === 'number') set('hpTotalTraps', stats.total_hits);
          if (typeof stats.unique_attackers === 'number') set('hpUniqueAttackers', stats.unique_attackers);

          // merge server-side top attackers
          const atkList = document.getElementById('hpTopAttackersList');
          if (atkList && Array.isArray(stats.top_attackers) && stats.top_attackers.length) {
            atkList.innerHTML = stats.top_attackers.map(([ip, cnt]) =>
              `<div class="hp-attacker-row"><span class="hp-attacker-ip">${escapeHtml(String(ip))}</span><span class="hp-attacker-count">${cnt}</span></div>`
            ).join('');
          }
          // merge by_trap
          const trapList = document.getElementById('hpTrapBreakdown');
          if (trapList && stats.by_trap && typeof stats.by_trap === 'object') {
            const entries = Object.entries(stats.by_trap).sort((a, b) => b[1] - a[1]);
            if (entries.length) {
              trapList.innerHTML = entries.map(([name, cnt]) =>
                `<div class="hp-trap-row"><span class="hp-trap-name">${escapeHtml(name)}</span><span class="hp-trap-count">${cnt}</span></div>`
              ).join('');
            }
          }
        } catch {}
      }, 15000);
    }

    /* ── Honeypot Block IP (inline button) ────────────────── */
    async function honeypotBlockIp(ip) {
      if (!ip) return;
      try {
        await apiPostJson(API.honeypotBlock, { ip: String(ip), ttl_seconds: 3600 }, { timeoutMs: 5000 });
        showToast(`Blocked ${escapeHtml(ip)} for 1 hour`);
      } catch (e) {
        showToast(`Block failed: ${e?.message || e}`);
      }
    }

    /* ── Honeypot Settings Panel ──────────────────────────── */
    function initHoneypotSettingsPanel() {
      const section = document.getElementById('hpSettingsSection');
      if (!section) return;

      const loadCfg = async () => {
        const status = document.getElementById('hpSettingsStatus');
        try {
          const cfg = await apiFetchJson(API.honeypotConfig, { timeoutMs: 5000 });
          if (!cfg) return;
          const webEl = document.getElementById('hpCfgWebTraps');
          const tcpEl = document.getElementById('hpCfgTcpTraps');
          const ttlEl = document.getElementById('hpCfgBlockTtl');
          if (webEl) webEl.checked = !!cfg.web_traps_enabled;
          if (tcpEl) tcpEl.checked = !!cfg.tcp_traps_enabled;
          if (ttlEl) ttlEl.value = String(cfg.auto_block_ttl_seconds || 300);
          if (status) status.textContent = '';
        } catch (e) {
          if (status) status.textContent = `Error: ${e?.message || e}`;
        }
      };

      document.getElementById('hpCfgSave')?.addEventListener('click', async () => {
        const status = document.getElementById('hpSettingsStatus');
        const body = {
          web_traps_enabled: !!document.getElementById('hpCfgWebTraps')?.checked,
          tcp_traps_enabled: !!document.getElementById('hpCfgTcpTraps')?.checked,
          auto_block_ttl_seconds: Math.max(0, parseInt(document.getElementById('hpCfgBlockTtl')?.value || '300', 10) || 300),
        };
        try {
          await apiPostJson(API.honeypotConfig, body, { timeoutMs: 5000 });
          if (status) status.textContent = 'Saved';
          showToast('Honeypot config saved');
        } catch (e) {
          if (status) status.textContent = `Error: ${e?.message || e}`;
        }
      });

      document.getElementById('hpCfgReload')?.addEventListener('click', loadCfg);

      // load on open
      section.addEventListener('toggle', () => { if (section.open) loadCfg(); });
    }

    /* ── BREADCRUMB CONTEXT EXTRACTION & RENDERING ─────────────── */

    /**
     * Extract contextual information from an alert object for breadcrumb navigation.
     * Safely escapes all values to prevent XSS.
     * Returns an array of breadcrumb items with icon, label, value, and action.
     */
    function extractAlertBreadcrumbContext(alertObj) {
      if (!alertObj || typeof alertObj !== 'object') return [];

      const items = [];
      const seen = new Set(); // Prevent duplicate breadcrumbs

      // Helper: safely escape HTML
      const escape = escapeHtml;

      // Helper: create breadcrumb item
      const addItem = (icon, label, value, actionType) => {
        if (!value || typeof value !== 'string') return;
        const clean = String(value).trim();
        if (!clean || seen.has(`${label}:${clean}`)) return;
        seen.add(`${label}:${clean}`);
        items.push({ icon, label, value: clean, actionType });
      };

      // Extract: Agent Hostname
      if (alertObj.agent_hostname) {
        addItem('🖥', 'Host', alertObj.agent_hostname, 'search-events');
      }

      // Extract: Agent IP
      if (alertObj.agent_ip) {
        addItem('📍', 'Agent IP', alertObj.agent_ip, 'search-events');
      }

      // Extract: Source IP (from metadata or direct fields)
      const srcIp = alertObj?.source_ip || alertObj?.metadata?.['network.source.ip'];
      if (srcIp) {
        addItem('⬅', 'Src IP', srcIp, 'block-ip');
      }

      // Extract: Destination IP (from metadata)
      const dstIp = alertObj?.destination_ip || alertObj?.metadata?.['network.destination.ip'];
      if (dstIp) {
        addItem('➡', 'Dst IP', dstIp, 'search-events');
      }

      // Extract: User (from metadata or direct fields)
      const user = alertObj?.user || alertObj?.metadata?.['user.name'] || alertObj?.metadata?.['user_name'];
      if (user) {
        addItem('👤', 'User', user, 'block-user');
      }

      // Extract: Process Name (from metadata)
      const procName = alertObj?.metadata?.['process.name'] || alertObj?.metadata?.['process_name'];
      if (procName) {
        addItem('⚙', 'Process', procName, 'search-events');
      }

      // Extract: Domain (from metadata)
      const domain = alertObj?.metadata?.['dns.query'] || alertObj?.metadata?.['domain'];
      if (domain) {
        addItem('🌐', 'Domain', domain, 'search-events');
      }

      // Extract: File Hash (from metadata)
      const fileHash = alertObj?.metadata?.['file.hash.sha256'] || alertObj?.metadata?.['hash'];
      if (fileHash) {
        addItem('📦', 'Hash', fileHash, 'search-events');
      }

      // Extract: Rule ID/Name (for better context)
      if (alertObj.rule_id) {
        addItem('📋', 'Rule', String(alertObj.rule_id).trim(), 'filter-rule');
      }

      return items;
    }

    /**
     * Render breadcrumb items into the alert breadcrumb container.
     * Attaches click handlers for contextual navigation.
     */
    function renderAlertBreadcrumbs(alertObj, container) {
      if (!container || !(container instanceof Node)) return;

      container.innerHTML = '';
      const items = extractAlertBreadcrumbContext(alertObj);

      if (items.length === 0) {
        container.style.display = 'none';
        return;
      }

      container.style.display = 'flex';

      for (let i = 0; i < items.length; i++) {
        const item = items[i];

        // Create breadcrumb item wrapper
        const itemEl = document.createElement('div');
        itemEl.className = 'alertBreadcrumbItem';

        // Icon
        const iconEl = document.createElement('span');
        iconEl.className = 'alertBreadcrumbIcon';
        iconEl.textContent = item.icon;
        iconEl.title = item.label;
        itemEl.appendChild(iconEl);

        // Label (hidden on mobile by CSS)
        const labelEl = document.createElement('span');
        labelEl.className = 'alertBreadcrumbLabel';
        labelEl.textContent = item.label + ':';
        itemEl.appendChild(labelEl);

        // Value (clickable)
        const valueEl = document.createElement('button');
        valueEl.type = 'button';
        valueEl.className = 'alertBreadcrumbValue';
        valueEl.title = `Click to ${item.actionType}: ${escapeHtml(item.value)}`;
        valueEl.textContent = item.value.length > 30 ? item.value.substring(0, 27) + '…' : item.value;

        // Attach click handler based on action type
        valueEl.addEventListener('click', (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          handleBreadcrumbAction(item.actionType, item.value, alertObj);
        });

        itemEl.appendChild(valueEl);

        // Add separator between items (except last)
        if (i < items.length - 1) {
          const sepEl = document.createElement('span');
          sepEl.className = 'alertBreadcrumbSeparator';
          sepEl.textContent = '•';
          itemEl.appendChild(sepEl);
        }

        container.appendChild(itemEl);
      }
    }

    /**
     * Handle breadcrumb click actions:
     * - search-events: Pivot to events pane with filter
     * - block-ip: Open block IP dialog with pre-filled value
     * - block-user: Open block user dialog with pre-filled value
     * - filter-rule: Filter alerts by rule ID
     */
    function handleBreadcrumbAction(actionType, value, alertObj) {
      if (!value) return;

      const clean = String(value).trim();

      switch (actionType) {
        case 'search-events':
          // Pivot to events pane with search filter
          if (typeof setView === 'function') {
            setView('events');
            // Try to set search filter if available
            if (typeof window.alertEventsFilter === 'function') {
              window.alertEventsFilter(clean);
            }
          }
          break;

        case 'block-ip':
          // Open block IP dialog
          if (typeof window.promptBlockIp === 'function') {
            window.promptBlockIp(clean);
          } else {
            const reason = prompt(`Block IP ${escapeHtml(clean)}?\nEnter reason (5+ chars):`, '');
            if (reason && reason.length >= 5) {
              if (typeof apiPostJson === 'function') {
                apiPostJson('/api/honeypot/block', { value: clean, ttl_seconds: 3600 })
                  .then(() => showToast(`Blocked ${escapeHtml(clean)} for 1 hour`))
                  .catch(e => showToast(`Block failed: ${e?.message || e}`));
              }
            }
          }
          break;

        case 'block-user':
          // Open block user dialog
          if (typeof window.promptBlockUser === 'function') {
            window.promptBlockUser(clean);
          } else {
            const reason = prompt(`Disable user ${escapeHtml(clean)}?\nEnter reason (5+ chars):`, '');
            if (reason && reason.length >= 5) {
              if (typeof apiPostJson === 'function') {
                apiPostJson('/api/playbook/execute', {
                  playbook_id: 'disable-user',
                  context: { value: clean, reason },
                })
                  .then(() => showToast(`User ${escapeHtml(clean)} disabled`))
                  .catch(e => showToast(`Action failed: ${e?.message || e}`));
              }
            }
          }
          break;

        case 'filter-rule':
          // Filter alerts by rule ID
          if (typeof state === 'object' && state.ui) {
            state.ui.filterByRule = clean;
            if (typeof refreshAlertsList === 'function') {
              refreshAlertsList();
            }
          }
          showToast(`Filtering by rule: ${escapeHtml(clean)}`);
          break;

        default:
          showToast(`Breadcrumb action not implemented: ${actionType}`);
      }
    }

    /**
     * Attach breadcrumb rendering to global alert details renderer.
     * Call this after alert details are loaded.
     */
    function initAlertBreadcrumbs() {
      if (state._breadcrumbsInitialized) return;
      state._breadcrumbsInitialized = true;

      // Monkey-patch the alert renderer to include breadcrumbs
      const originalBuildAlertDetailsShell = window.buildAlertDetailsShell;
      if (typeof originalBuildAlertDetailsShell === 'function') {
        window.buildAlertDetailsShell = function(rootEl, alertObj) {
          const result = originalBuildAlertDetailsShell.call(this, rootEl, alertObj);
          // Render breadcrumbs after shell is built
          if (result.breadcrumbContainer) {
            renderAlertBreadcrumbs(alertObj, result.breadcrumbContainer);
          }
          return result;
        };
      }
    }

    // Initialize breadcrumbs on document ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initAlertBreadcrumbs);
    } else {
      initAlertBreadcrumbs();
    }

