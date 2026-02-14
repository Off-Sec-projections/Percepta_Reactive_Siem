    function setIdsRulesStatus(msg, isError = false) {
      const el = document.getElementById('idsRulesStatus');
      if (!el) return;
      el.textContent = String(msg || '');
      el.style.color = isError ? 'var(--danger, #ff6b6b)' : '';
    }

    function setSettingsRulesStatus(msg, isError = false) {
      const el = document.getElementById('settingsRulesStatus');
      if (!el) return;
      el.textContent = String(msg || '');
      el.style.color = isError ? 'var(--danger, #ff6b6b)' : '';
    }

    /* ── Settings nav label map ── */
    const _settingsNavLabels = {
      general: '⚙ General',
      agents: '📡 Agents',
      rules: '🛡 Rules',
      advanced: '🔬 Advanced',
      integrations: '🔌 Integrations',
    };

    function applySettingsSubTabsUi() {
      const tab = String(state.settingsSubTab || 'general');
      const _isAdmin = String(state.auth?.status?.role || '').toLowerCase() === 'authority';
      document.querySelectorAll('[data-settings-tab]').forEach((btn) => {
        const t = String(btn.getAttribute('data-settings-tab') || '');
        if (t === 'integrations') btn.style.display = _isAdmin ? '' : 'none';
        btn.classList.toggle('active', t === tab);
      });
      document.querySelectorAll('[data-settings-pane]').forEach((pane) => {
        pane.classList.toggle('active', String(pane.getAttribute('data-settings-pane') || '') === tab);
      });
      /* Update toggle label */
      const label = document.getElementById('settingsNavLabel');
      if (label) label.textContent = _settingsNavLabels[tab] || tab;
      /* Close the menu after selecting */
      _closeSettingsNav();
    }

    function _closeSettingsNav() {
      const menu = document.getElementById('settingsNavMenu');
      const toggle = document.getElementById('settingsNavToggle');
      if (menu) menu.classList.add('hidden');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }

    function setSettingsSubTab(tab) {
      const t0 = String(tab || '').trim().toLowerCase();
      const t = ['general', 'control', 'agents', 'rules', 'advanced', 'integrations'].includes(t0) ? t0 : 'general';
      state.settingsSubTab = t;
      try { localStorage.setItem(SETTINGS_SUBTAB_KEY, t); } catch {}
      applySettingsSubTabsUi();
      if (t === 'control') {
        void syncRuntimeSettingsIntoControlModel().finally(() => renderSettingsControlCenter());
      }
      if (t === 'agents') { paintSettingsAgentsThrottled(); loadFimConfig(); }
      if (t === 'rules') {
        initSettingsRulesControls();
      }
      if (t === 'integrations') {
        const _isAdmin = String(state.auth?.status?.role || '').toLowerCase() === 'authority';
        if (!_isAdmin) { state.settingsSubTab = 'general'; applySettingsSubTabsUi(); return; }
        if (typeof loadIntegrations === 'function') loadIntegrations();
      }
    }

    function settingsControlSchema() {
      return [
        {
          id: 'global-ui',
          domain: 'global',
          scope: 'global',
          group: 'core',
          priority: 'high',
          title: 'Global UI & operator defaults',
          desc: 'Startup view, language, density, and wallboard mode.',
          collapsed: false,
          fields: [
            { key: 'ui.defaultView', label: 'Startup view', type: 'select', live: true, tags: 'startup landing page view', options: [
              { value: 'overview', label: 'Overview' }, { value: 'alerts', label: 'Alerts' }, { value: 'events', label: 'Events' }, { value: 'honeypot', label: 'Honeypot' }, { value: 'ids', label: 'IDS' }, { value: 'escalations', label: 'Escalations' }, { value: 'settings', label: 'Settings' },
            ] },
            { key: 'ui.language', label: 'Default language', type: 'select', live: true, tags: 'locale i18n', options: [
              { value: 'en', label: 'English' }, { value: 'ur', label: 'اردو' },
            ] },
            { key: 'ui.densityMode', label: 'Density profile', type: 'select', live: true, tags: 'compact display zoom', options: [
              { value: 'auto', label: 'Auto' }, { value: 'normal', label: 'Normal' }, { value: 'compact', label: 'Compact' }, { value: 'ultra', label: 'Ultra' },
            ] },
            { key: 'ui.nocWall', label: 'NOC wall mode default', type: 'bool', live: true, tags: 'wallboard monitor display' },
          ],
        },
        {
          id: 'global-ui-advanced',
          domain: 'global',
          scope: 'global',
          group: 'core',
          priority: 'low',
          title: 'Advanced UI preferences',
          desc: 'Secondary UI knobs — performance, default sub-tab, sidebar.',
          collapsed: true,
          fields: [
            { key: 'ui.defaultSettingsTab', label: 'Default settings sub-tab', type: 'select', live: true, tags: 'tab startup', options: [
              { value: 'general', label: 'General' }, { value: 'agents', label: 'Agents' }, { value: 'rules', label: 'Rules' }, { value: 'advanced', label: 'Advanced' }, { value: 'integrations', label: 'Integrations' },
            ] },
            { key: 'ui.perfMode', label: 'Performance mode', type: 'select', live: true, tags: 'low power gpu rendering', options: [
              { value: 'auto', label: 'Auto' }, { value: 'on', label: 'On (low-power)' }, { value: 'off', label: 'Off (full effects)' },
            ] },
            { key: 'ui.sidebarHidden', label: 'Sidebar hidden default', type: 'bool', live: true, tags: 'menu collapse' },
          ],
        },
        {
          id: 'ingestion-core',
          domain: 'ingestion',
          scope: 'domain',
          group: 'pipeline',
          priority: 'high',
          title: 'Ingestion & paging',
          desc: 'Event/alert buffer sizes and page sizes for table views.',
          collapsed: false,
          fields: [
            { key: 'ingest.maxEvents', label: 'Max in-memory events', type: 'number', min: 100, max: 5000, step: 50, live: true, tags: 'buffer limit capacity' },
            { key: 'ingest.maxAlerts', label: 'Max in-memory alerts', type: 'number', min: 100, max: 10000, step: 50, live: true, tags: 'buffer limit capacity' },
            { key: 'ingest.eventsPageSize', label: 'Events page size', type: 'number', min: 25, max: 1000, step: 25, live: true, tags: 'pagination rows table' },
            { key: 'ingest.alertsPageSize', label: 'Alerts page size', type: 'number', min: 25, max: 1000, step: 25, live: true, tags: 'pagination rows table' },
          ],
        },
        {
          id: 'ingestion-tuning',
          domain: 'ingestion',
          scope: 'domain',
          group: 'pipeline',
          priority: 'low',
          title: 'Telemetry & rendering tuning',
          desc: 'Cadence, Hz, and row-height tweaks for high-volume SOC.',
          collapsed: true,
          fields: [
            { key: 'ingest.telemetryHzOverview', label: 'Overview telemetry Hz', type: 'number', min: 1, max: 10, step: 1, live: true, tags: 'refresh rate frequency' },
            { key: 'ingest.telemetryHzOther', label: 'Non-overview telemetry Hz', type: 'number', min: 1, max: 5, step: 1, live: true, tags: 'refresh rate frequency' },
            { key: 'ingest.virtualRowHeightEvents', label: 'Events row height (px)', type: 'number', min: 26, max: 64, step: 1, live: true, tags: 'table display row pixels' },
            { key: 'ingest.virtualRowHeightAlerts', label: 'Alerts row height (px)', type: 'number', min: 26, max: 64, step: 1, live: true, tags: 'table display row pixels' },
          ],
        },
        {
          id: 'detection-engine',
          domain: 'detection',
          scope: 'domain',
          group: 'security',
          priority: 'high',
          title: 'Detection & rules',
          desc: 'Rule workflows, suppression defaults, and detection posture.',
          collapsed: false,
          fields: [
            { key: 'detection.defaultRuleAction', label: 'Default new-rule action', type: 'select', live: false, tags: 'ids action alert drop', options: [
              { value: 'alert', label: 'alert' }, { value: 'drop', label: 'drop' }, { value: 'reject', label: 'reject' }, { value: 'pass', label: 'pass' },
            ] },
            { key: 'detection.defaultSuppressionHours', label: 'Default suppression hours', type: 'number', min: 1, max: 168, step: 1, live: false, tags: 'mute silence' },
            { key: 'detection.autoLoadRulesOnOpen', label: 'Auto-load rules when opening Rules tab', type: 'bool', live: true, tags: 'autoload startup' },
            { key: 'detection.autoOpenRulesWorkspace', label: 'Open IDS workspace from rules sub-tab', type: 'bool', live: false, tags: 'workspace ids editor' },
            { key: 'detection.playbookRunsDefaultLimit', label: 'Playbook runs default limit', type: 'number', min: 1, max: 500, step: 1, live: true, tags: 'playbook automation' },
          ],
        },
        {
          id: 'response-controls',
          domain: 'response',
          scope: 'specific',
          group: 'security',
          priority: 'high',
          title: 'Reactive response & blocks',
          desc: 'SOC response defaults for block durations and command guardrails.',
          collapsed: false,
          fields: [
            { key: 'response.defaultBlockMinutes', label: 'Default block minutes', type: 'number', min: 1, max: 525600, step: 1, live: true, tags: 'block firewall duration' },
            { key: 'response.analystMaxBlockMinutes', label: 'Analyst max block minutes', type: 'number', min: 1, max: 525600, step: 1, live: true, tags: 'limit cap analyst' },
            { key: 'response.requireConfirmDestructive', label: 'Require confirmation for destructive actions', type: 'bool', live: false, tags: 'safety confirm dangerous' },
          ],
        },
        {
          id: 'response-advanced',
          domain: 'response',
          scope: 'specific',
          group: 'security',
          priority: 'low',
          title: 'Response tuning (advanced)',
          desc: 'Script block defaults, dispatch TTL, and platform-specific settings.',
          collapsed: true,
          fields: [
            { key: 'response.windowsScriptBlockMinutes', label: 'Windows script default block minutes', type: 'number', min: 1, max: 43200, step: 1, live: true, tags: 'windows script powershell' },
            { key: 'response.defaultDispatchTimeoutSec', label: 'Command timeout (seconds, 1-3600)', type: 'number', min: 1, max: 3600, step: 1, live: true, tags: 'timeout ttl dispatch command' },
          ],
        },
        {
          id: 'storage-retention',
          domain: 'storage',
          scope: 'specific',
          group: 'infrastructure',
          priority: 'low',
          title: 'Storage & persistence',
          desc: 'Browser-side cache budget and local persistence toggles.',
          collapsed: true,
          fields: [
            { key: 'storage.persistScopeFilters', label: 'Persist scoped filters', type: 'bool', live: false, tags: 'remember save filters' },
            { key: 'storage.persistEventNotes', label: 'Persist event notes', type: 'bool', live: false, tags: 'notes annotation save' },
            { key: 'storage.maxDeviceNameCache', label: 'Device-name cache budget', type: 'number', min: 100, max: 50000, step: 100, live: false, tags: 'cache budget memory' },
          ],
        },
        {
          id: 'dr-automation',
          domain: 'storage',
          scope: 'domain',
          group: 'infrastructure',
          priority: 'low',
          title: 'Disaster recovery automation',
          desc: 'DR verification cadence and restore drill scheduling.',
          collapsed: true,
          fields: [
            { key: 'dr.enabledOverride', label: 'DR automation enabled', type: 'bool', live: true, tags: 'backup disaster recovery' },
            { key: 'dr.verifyIntervalSecs', label: 'DR verify interval (sec)', type: 'number', min: 60, max: 86400, step: 60, live: true, tags: 'backup check frequency' },
            { key: 'dr.restoreDrillEnabled', label: 'Restore drill enabled', type: 'bool', live: true, tags: 'backup test exercise' },
            { key: 'dr.restoreDrillIntervalSecs', label: 'Restore drill interval (sec)', type: 'number', min: 300, max: 2592000, step: 300, live: true, tags: 'backup test frequency' },
          ],
        },
        {
          id: 'access-governance',
          domain: 'access',
          scope: 'global',
          group: 'security',
          priority: 'low',
          title: 'Access governance',
          desc: 'Operator-role defaults and renewal workflow policy.',
          collapsed: true,
          fields: [
            { key: 'access.defaultRoleLanding', label: 'Default role landing', type: 'select', live: false, tags: 'role analyst authority', options: [
              { value: 'analyst', label: 'Analyst' }, { value: 'authority', label: 'Authority' },
            ] },
            { key: 'access.requireAdminForRenewals', label: 'Require authority access for renewals', type: 'bool', live: false, tags: 'admin permission renew' },
          ],
        },
        {
          id: 'integration-controls',
          domain: 'integrations',
          scope: 'domain',
          group: 'infrastructure',
          priority: 'high',
          title: 'Integrations & enrichment',
          desc: 'Enrichment lookups, threat intel, and signal expansion toggles.',
          collapsed: false,
          fields: [
            { key: 'integrations.geoipLookupEnabled', label: 'GeoIP enrichment enabled', type: 'bool', live: false, tags: 'geo location ip' },
            { key: 'integrations.relatedSignalsEnabled', label: 'Related-signals enrichment enabled', type: 'bool', live: false, tags: 'correlated context signals' },
            { key: 'integrations.intelLookupEnabled', label: 'Threat intel lookups enabled', type: 'bool', live: false, tags: 'threat intelligence ioc feed' },
          ],
        },
      ];
    }

    function applySettingsControlDomainScopeUi() {
      const domain = normalizeSettingsControlDomain(state.settingsControlDomain);
      const scope = normalizeSettingsControlScope(state.settingsControlScope);
      document.querySelectorAll('[data-settings-domain]').forEach((btn) => {
        btn.classList.toggle('active', String(btn.getAttribute('data-settings-domain') || '') === domain);
      });
      document.querySelectorAll('[data-settings-scope]').forEach((btn) => {
        btn.classList.toggle('active', String(btn.getAttribute('data-settings-scope') || '') === scope);
      });
    }

    let _uiSnapshotPushTimer = null;
    function scheduleUiSnapshotPush() {
      if (typeof pushUiSnapshotToServer !== 'function') return;
      clearTimeout(_uiSnapshotPushTimer);
      _uiSnapshotPushTimer = setTimeout(() => {
        pushUiSnapshotToServer({ force: false });
      }, 400);
    }

    function setSettingsControlDomain(v) {
      state.settingsControlDomain = normalizeSettingsControlDomain(v);
      try { localStorage.setItem(SETTINGS_CONTROL_DOMAIN_KEY, state.settingsControlDomain); } catch {}
      applySettingsControlDomainScopeUi();
      renderSettingsControlCenter();
      scheduleUiSnapshotPush();
    }

    function setSettingsControlScope(v) {
      state.settingsControlScope = normalizeSettingsControlScope(v);
      try { localStorage.setItem(SETTINGS_CONTROL_SCOPE_KEY, state.settingsControlScope); } catch {}
      applySettingsControlDomainScopeUi();
      renderSettingsControlCenter();
      scheduleUiSnapshotPush();
    }

    function parseSettingsControlValue(field, raw) {
      if (!field || typeof field !== 'object') return raw;
      if (field.type === 'bool') return Boolean(raw);
      if (field.type === 'number') {
        let n = Number(raw);
        if (!Number.isFinite(n)) n = Number(field.min || 0) || 0;
        if (Number.isFinite(field.min)) n = Math.max(Number(field.min), n);
        if (Number.isFinite(field.max)) n = Math.min(Number(field.max), n);
        const step = Number(field.step || 1) || 1;
        n = Math.round(n / step) * step;
        return n;
      }
      return String(raw ?? '');
    }

    function persistSettingsControlModel() {
      try { storageSetJson(SETTINGS_CONTROL_MODEL_KEY, state.settingsControlModel || getDefaultSettingsControlModel()); } catch {}
      scheduleUiSnapshotPush();
    }

    function applyRuntimeSettingsResponseToModel(resp) {
      if (!resp || typeof resp !== 'object') return;
      if (!state.settingsControlModel || typeof state.settingsControlModel !== 'object') {
        state.settingsControlModel = getDefaultSettingsControlModel();
      }
      const tuning = (resp.tuning && typeof resp.tuning === 'object') ? resp.tuning : {};
      const dr = (resp.dr_effective && typeof resp.dr_effective === 'object') ? resp.dr_effective : {};

      if (Number.isFinite(Number(tuning.reactive_default_ttl_secs))) {
        state.settingsControlModel['response.defaultBlockMinutes'] = Math.max(1, Math.round(Number(tuning.reactive_default_ttl_secs) / 60));
      }
      if (Number.isFinite(Number(tuning.reactive_analyst_max_ttl_secs))) {
        state.settingsControlModel['response.analystMaxBlockMinutes'] = Math.max(1, Math.round(Number(tuning.reactive_analyst_max_ttl_secs) / 60));
      }
      if (Number.isFinite(Number(tuning.reactive_windows_script_ttl_secs))) {
        state.settingsControlModel['response.windowsScriptBlockMinutes'] = Math.max(1, Math.round(Number(tuning.reactive_windows_script_ttl_secs) / 60));
      }
      if (Number.isFinite(Number(tuning.reactive_dispatch_default_ttl_secs))) {
        state.settingsControlModel['response.defaultDispatchTimeoutSec'] = Math.max(0, Math.round(Number(tuning.reactive_dispatch_default_ttl_secs)));
      }
      if (Number.isFinite(Number(tuning.playbooks_default_runs_limit))) {
        state.settingsControlModel['detection.playbookRunsDefaultLimit'] = Math.max(1, Math.round(Number(tuning.playbooks_default_runs_limit)));
      }

      if (typeof dr.enabled === 'boolean') {
        state.settingsControlModel['dr.enabledOverride'] = dr.enabled;
      }
      if (Number.isFinite(Number(dr.verify_interval_secs))) {
        state.settingsControlModel['dr.verifyIntervalSecs'] = Math.max(60, Math.round(Number(dr.verify_interval_secs)));
      }
      if (typeof dr.restore_drill_enabled === 'boolean') {
        state.settingsControlModel['dr.restoreDrillEnabled'] = dr.restore_drill_enabled;
      }
      if (Number.isFinite(Number(dr.restore_drill_interval_secs))) {
        state.settingsControlModel['dr.restoreDrillIntervalSecs'] = Math.max(300, Math.round(Number(dr.restore_drill_interval_secs)));
      }
    }

    async function syncRuntimeSettingsIntoControlModel() {
      const resp = await fetchRuntimeSettingsFromServer();
      if (!resp) return false;
      applyRuntimeSettingsResponseToModel(resp);
      persistSettingsControlModel();
      return true;
    }

    function applyLiveSettingsControlChange(key, value) {
      const k = String(key || '');
      const m = state.settingsControlModel || {};
      if (k === 'ui.language') {
        setUiLanguage(value);
        return true;
      }
      if (k === 'ui.defaultSettingsTab') {
        const v = ['general', 'control', 'agents', 'rules', 'advanced', 'integrations'].includes(String(value || '')) ? String(value) : 'general';
        state.settingsSubTab = v;
        try { localStorage.setItem(SETTINGS_SUBTAB_KEY, v); } catch {}
        applySettingsSubTabsUi();
        scheduleUiSnapshotPush();
        return true;
      }
      if (k === 'ui.perfMode') {
        state.perfMode = ['auto', 'on', 'off'].includes(String(value || '')) ? String(value) : 'auto';
        try { localStorage.setItem(PERF_MODE_KEY, state.perfMode); } catch {}
        updatePerformanceMode();
        scheduleUiSnapshotPush();
        return true;
      }
      if (k === 'ui.densityMode') {
        state.densityMode = ['auto', 'normal', 'compact', 'ultra'].includes(String(value || '')) ? String(value) : 'auto';
        try { localStorage.setItem(DENSITY_MODE_KEY, state.densityMode); } catch {}
        updateDensityMode();
        state.dirty.tables = true;
        state.dirty.details = true;
        scheduleRender();
        scheduleUiSnapshotPush();
        return true;
      }
      if (k === 'ui.nocWall') {
        state.nocMode = Boolean(value);
        try { localStorage.setItem(NOC_MODE_KEY, state.nocMode ? '1' : '0'); } catch {}
        updateNocMode();
        scheduleUiSnapshotPush();
        return true;
      }
      if (k === 'ui.sidebarHidden') {
        state.sidebarHidden = Boolean(value);
        try { localStorage.setItem(SIDEBAR_HIDDEN_KEY, state.sidebarHidden ? '1' : '0'); } catch {}
        applySidebarMenuState();
        scheduleUiSnapshotPush();
        return true;
      }
      if (k === 'ingest.maxEvents') {
        LIMITS.maxEvents = Math.max(100, Math.min(5000, Number(value || 200) || 200));
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.maxAlerts') {
        LIMITS.maxAlerts = Math.max(100, Math.min(10000, Number(value || 500) || 500));
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.eventsPageSize') {
        state.pagination.events.pageSize = Math.max(25, Math.min(LIMITS.maxEvents, Number(value || 100) || 100));
        state.pagination.events.page = 1;
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.alertsPageSize') {
        state.pagination.alerts.pageSize = Math.max(25, Math.min(LIMITS.maxAlerts, Number(value || 100) || 100));
        state.pagination.alerts.page = 1;
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.virtualRowHeightEvents') {
        VIRTUAL_TABLES.tblEvents.rowHeight = Math.max(26, Math.min(64, Number(value || 34) || 34));
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.virtualRowHeightAlerts') {
        VIRTUAL_TABLES.tblAlerts.rowHeight = Math.max(26, Math.min(64, Number(value || 34) || 34));
        state.dirty.tables = true;
        scheduleRender();
        return true;
      }
      if (k === 'ingest.telemetryHzOverview' || k === 'ingest.telemetryHzOther') {
        sendStreamHello({ force: true });
        return true;
      }
      if (k === 'detection.autoLoadRulesOnOpen') {
        if (state.settingsSubTab === 'rules' && value) loadIdsRules();
        return true;
      }
      if (k === 'response.defaultBlockMinutes') {
        void pushRuntimeSettingsPatch({ reactive_default_ttl_secs: Math.max(30, Math.round(Number(value || 15) * 60)) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'response.analystMaxBlockMinutes') {
        void pushRuntimeSettingsPatch({ reactive_analyst_max_ttl_secs: Math.max(30, Math.round(Number(value || 15) * 60)) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'response.windowsScriptBlockMinutes') {
        void pushRuntimeSettingsPatch({ reactive_windows_script_ttl_secs: Math.max(30, Math.round(Number(value || 15) * 60)) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'response.defaultDispatchTimeoutSec') {
        void pushRuntimeSettingsPatch({ reactive_dispatch_default_ttl_secs: Math.max(1, Math.min(3600, Math.round(Number(value || 30)))) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'detection.playbookRunsDefaultLimit') {
        void pushRuntimeSettingsPatch({ playbooks_default_runs_limit: Math.max(1, Math.round(Number(value || 100))) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'dr.enabledOverride') {
        void pushRuntimeSettingsPatch({ dr_enabled_override: Boolean(value) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'dr.verifyIntervalSecs') {
        void pushRuntimeSettingsPatch({ dr_verify_interval_secs: Math.max(60, Math.round(Number(value || 3600))) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'dr.restoreDrillEnabled') {
        void pushRuntimeSettingsPatch({ dr_restore_drill_enabled: Boolean(value) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'dr.restoreDrillIntervalSecs') {
        void pushRuntimeSettingsPatch({ dr_restore_drill_interval_secs: Math.max(300, Math.round(Number(value || 86400))) })
          .then((resp) => {
            if (resp) {
              applyRuntimeSettingsResponseToModel(resp);
              persistSettingsControlModel();
              renderSettingsControlCenter();
            }
          });
        return true;
      }
      if (k === 'ui.defaultView') {
        if (state.view === 'settings') {
          // Keep operator in current pane; startup default is applied at boot.
        }
        return true;
      }
      if (k in m) {
        return false;
      }
      return false;
    }

    function applySettingsControlModel({ silent = true } = {}) {
      if (!state.settingsControlModel || typeof state.settingsControlModel !== 'object') {
        state.settingsControlModel = getDefaultSettingsControlModel();
      }
      const schema = settingsControlSchema();
      for (const card of schema) {
        const fields = Array.isArray(card.fields) ? card.fields : [];
        for (const field of fields) {
          const key = String(field.key || '');
          if (!key) continue;
          const v = parseSettingsControlValue(field, state.settingsControlModel[key]);
          state.settingsControlModel[key] = v;
          if (field.live) applyLiveSettingsControlChange(key, v);
        }
      }
      persistSettingsControlModel();
      if (!silent) showToast('Settings control profile applied.');
    }

    function setSettingsControlValue(field, rawValue) {
      if (!field || typeof field !== 'object') return;
      const key = String(field.key || '');
      if (!key) return;
      if (!state.settingsControlModel || typeof state.settingsControlModel !== 'object') {
        state.settingsControlModel = getDefaultSettingsControlModel();
      }
      const value = parseSettingsControlValue(field, rawValue);
      state.settingsControlModel[key] = value;
      persistSettingsControlModel();
      if (field.live) applyLiveSettingsControlChange(key, value);
    }

    function renderSettingsControlSummary(cards) {
      const host = document.getElementById('settingsControlSummary');
      if (!host) return;
      const allFields = cards.flatMap((c) => Array.isArray(c.fields) ? c.fields : []);
      const total = allFields.length;
      const live = allFields.filter((f) => Boolean(f.live)).length;
      const profileOnly = total - live;
      host.innerHTML = `
        <div class="miniStat"><div class="k">Domain</div><div class="v">${escapeHtml(state.settingsControlDomain || 'global')}</div></div>
        <div class="miniStat"><div class="k">Scope</div><div class="v">${escapeHtml(state.settingsControlScope || 'global')}</div></div>
        <div class="miniStat"><div class="k">Tunables</div><div class="v">${total.toLocaleString()}</div></div>
        <div class="miniStat"><div class="k">Live Apply</div><div class="v">${live.toLocaleString()} <span class="muted text-12">/ ${profileOnly.toLocaleString()} local-only</span></div></div>
      `;
    }

    function _scFieldMatchesSearch(field, q) {
      if (!q) return true;
      const hay = [String(field.label || ''), String(field.key || ''), String(field.tags || '')].join(' ').toLowerCase();
      return q.split(/\s+/).every((w) => hay.includes(w));
    }

    function _scCardMatchesSearch(card, q) {
      if (!q) return true;
      const cardHay = [String(card.title || ''), String(card.desc || ''), String(card.domain || ''), String(card.group || '')].join(' ').toLowerCase();
      if (q.split(/\s+/).every((w) => cardHay.includes(w))) return true;
      return (Array.isArray(card.fields) ? card.fields : []).some((f) => _scFieldMatchesSearch(f, q));
    }

    function renderSettingsControlCenter() {
      const host = document.getElementById('settingsControlGrid');
      if (!host) return;
      applySettingsControlDomainScopeUi();
      const domain = normalizeSettingsControlDomain(state.settingsControlDomain);
      const scope = normalizeSettingsControlScope(state.settingsControlScope);
      const q = String(state._scSearchQuery || '').trim().toLowerCase();

      const allCards = settingsControlSchema();
      const cards = allCards.filter((card) => {
        const d = String(card.domain || 'global');
        const s = String(card.scope || 'global');
        const domainOk = (domain === 'global') ? true : d === domain;
        const scopeOk = scope === 'global' ? true : s === scope;
        if (!domainOk || !scopeOk) return false;
        if (q && !_scCardMatchesSearch(card, q)) return false;
        return true;
      });

      renderSettingsControlSummary(cards);

      if (!cards.length) {
        host.innerHTML = q
          ? `<div class="muted ta-center p-24">No settings match <strong>"${escapeHtml(q)}"</strong>. Try a different search term.</div>`
          : '<div class="muted ta-center p-24">No controls for this selection.</div>';
        return;
      }

      /* Group cards: high priority first, then low priority collapsed */
      const groups = [
        { label: '', cards: cards.filter((c) => c.priority !== 'low') },
        { label: 'More settings', cards: cards.filter((c) => c.priority === 'low'), startCollapsed: !q },
      ].filter((g) => g.cards.length > 0);

      host.innerHTML = groups.map((grp) => {
        const cardsHtml = grp.cards.map((card) => _renderControlCard(card, q)).join('');
        if (!grp.label) return `<div class="sc-group-cards">${cardsHtml}</div>`;
        return `
          <details class="sc-group-collapsible" ${grp.startCollapsed ? '' : 'open'}>
            <summary class="sc-group-summary">
              <span class="sc-group-chevron">▸</span>
              <span>${escapeHtml(grp.label)}</span>
              <span class="sc-group-count">${grp.cards.length}</span>
            </summary>
            <div class="sc-group-cards">${cardsHtml}</div>
          </details>
        `;
      }).join('');
    }

    function _renderControlCard(card, q) {
      const fields = Array.isArray(card.fields) ? card.fields : [];
      const isCollapsed = !q && card.collapsed;
      const fieldHtml = fields.filter((f) => !q || _scFieldMatchesSearch(f, q)).map((field) => {
        const key = String(field.key || '');
        const value = state.settingsControlModel?.[key];
        let input = '';
        if (field.type === 'bool') {
          input = `<label class="settingsToggleRow"><span class="muted text-12">Enable</span><input type="checkbox" data-sc-key="${escapeHtml(key)}" ${value ? 'checked' : ''}></label>`;
        } else if (field.type === 'number') {
          input = `<input class="field sm" type="number" data-sc-key="${escapeHtml(key)}" min="${Number(field.min ?? 0)}" max="${Number(field.max ?? 999999)}" step="${Number(field.step ?? 1)}" value="${Number(value ?? field.min ?? 0)}">`;
        } else if (field.type === 'select') {
          const opts = (Array.isArray(field.options) ? field.options : []).map((opt) => {
            const ov = String(opt?.value ?? '');
            const ol = String(opt?.label ?? ov);
            const selected = String(value ?? '') === ov ? 'selected' : '';
            return `<option value="${escapeHtml(ov)}" ${selected}>${escapeHtml(ol)}</option>`;
          }).join('');
          input = `<select class="field sm" data-sc-key="${escapeHtml(key)}">${opts}</select>`;
        } else {
          input = `<input class="field sm" type="text" data-sc-key="${escapeHtml(key)}" value="${escapeHtml(String(value ?? ''))}">`;
        }
        return `
          <div class="settingsControlField" data-sc-field="${escapeHtml(key)}">
            <div class="settingsControlFieldHead">
              <span>${escapeHtml(String(field.label || key))}</span>
              <span class="settingsModeBadge ${field.live ? 'live' : ''}" title="${field.live ? 'Applies immediately (may update runtime/server settings).' : 'Stored in local browser profile only (no immediate server write-back).'}">${field.live ? 'Live' : 'Local profile'}</span>
            </div>
            ${input}
          </div>
        `;
      }).join('');

      const priTag = card.priority === 'low' ? '<span class="sc-pri-tag low">optional</span>' : '';

      return `
        <details class="settingsControlCard" data-sc-card="${escapeHtml(String(card.id || 'card'))}" ${isCollapsed ? '' : 'open'}>
          <summary class="sc-card-header">
            <span class="sc-card-chevron">▸</span>
            <div class="sc-card-header-text">
              <div class="settingsControlTitle">${escapeHtml(String(card.title || 'Settings'))} ${priTag}</div>
              <div class="settingsControlDesc">${escapeHtml(String(card.desc || ''))}</div>
            </div>
            <span class="settingsModeBadge">${escapeHtml(String(card.scope || 'global'))}</span>
          </summary>
          <div class="bd">${fieldHtml}</div>
        </details>
      `;
    }

    function applySettingsAgentsCategoryUi() {
      const cat = String(state.settingsAgentsCategory || 'all');
      document.querySelectorAll('[data-agents-cat]').forEach((btn) => {
        btn.classList.toggle('active', String(btn.getAttribute('data-agents-cat') || '') === cat);
      });
    }

    function setSettingsAgentsCategory(cat) {
      const c0 = String(cat || '').trim().toLowerCase();
      const c = ['all', 'connected', 'stale', 'offline'].includes(c0) ? c0 : 'all';
      state.settingsAgentsCategory = c;
      try { localStorage.setItem(SETTINGS_AGENTS_CAT_KEY, c); } catch {}
      applySettingsAgentsCategoryUi();
      paintSettingsAgents();
    }

    function initSettingsSubmenus() {
      if (state._settingsSubmenusInit) return;
      state._settingsSubmenusInit = true;

      /* ── Settings nav dropdown toggle ── */
      const settingsToggle = document.getElementById('settingsNavToggle');
      const settingsMenu = document.getElementById('settingsNavMenu');
      if (settingsToggle && settingsMenu) {
        settingsToggle.addEventListener('click', (e) => {
          e.stopPropagation();
          const open = settingsMenu.classList.toggle('hidden');
          settingsToggle.setAttribute('aria-expanded', !open ? 'true' : 'false');
        });
      }

      /* Close any open settings/rules nav on outside click */
      document.addEventListener('click', () => {
        _closeSettingsNav();
        _closeRulesWsMenu();
      });
      /* Prevent menu content clicks from closing themselves prematurely */
      document.getElementById('settingsNavMenu')?.addEventListener('click', (e) => e.stopPropagation());
      document.getElementById('rulesWsMenu')?.addEventListener('click', (e) => e.stopPropagation());

      document.querySelectorAll('[data-settings-tab]').forEach((btn) => {
        btn.addEventListener('click', () => setSettingsSubTab(btn.getAttribute('data-settings-tab')));
      });
      document.querySelectorAll('[data-agents-cat]').forEach((btn) => {
        btn.addEventListener('click', () => setSettingsAgentsCategory(btn.getAttribute('data-agents-cat')));
      });
      document.querySelectorAll('[data-settings-domain]').forEach((btn) => {
        btn.addEventListener('click', () => setSettingsControlDomain(btn.getAttribute('data-settings-domain')));
      });
      document.querySelectorAll('[data-settings-scope]').forEach((btn) => {
        btn.addEventListener('click', () => setSettingsControlScope(btn.getAttribute('data-settings-scope')));
      });

      /* ── Search bar ── */
      const scSearchInput = document.getElementById('scSearchInput');
      const scSearchClear = document.getElementById('scSearchClear');
      if (scSearchInput) {
        let _scSearchTimer = null;
        scSearchInput.addEventListener('input', () => {
          clearTimeout(_scSearchTimer);
          _scSearchTimer = setTimeout(() => {
            state._scSearchQuery = String(scSearchInput.value || '').trim();
            if (scSearchClear) scSearchClear.classList.toggle('hidden', !state._scSearchQuery);
            renderSettingsControlCenter();
          }, 180);
        });
      }
      if (scSearchClear) {
        scSearchClear.addEventListener('click', () => {
          state._scSearchQuery = '';
          if (scSearchInput) scSearchInput.value = '';
          scSearchClear.classList.add('hidden');
          renderSettingsControlCenter();
        });
      }

      const scGrid = document.getElementById('settingsControlGrid');
      if (scGrid) {
        scGrid.addEventListener('change', (ev) => {
          const target = ev.target;
          if (!target || !target.getAttribute) return;
          const key = String(target.getAttribute('data-sc-key') || '');
          if (!key) return;
          const field = settingsControlSchema().flatMap((c) => c.fields || []).find((f) => String(f.key || '') === key);
          if (!field) return;
          const raw = (target.type === 'checkbox') ? Boolean(target.checked) : target.value;
          setSettingsControlValue(field, raw);
          renderSettingsControlSummary(settingsControlSchema().filter((card) => {
            const domain = normalizeSettingsControlDomain(state.settingsControlDomain);
            const scope = normalizeSettingsControlScope(state.settingsControlScope);
            const d = String(card.domain || 'global');
            const s = String(card.scope || 'global');
            const domainOk = (domain === 'global') ? true : d === domain;
            const scopeOk = scope === 'global' ? true : s === scope;
            return domainOk && scopeOk;
          }));
        });
      }

      document.getElementById('settingsControlExport')?.addEventListener('click', async () => {
        const payload = JSON.stringify(state.settingsControlModel || getDefaultSettingsControlModel(), null, 2);
        const copied = await copyTextToClipboard(payload);
        if (copied) showToast('Local control profile copied to clipboard.');
        else showToast('Copy failed. You can still export from browser console: window.__PERCEPTA_SETTINGS_PROFILE');
        try { window.__PERCEPTA_SETTINGS_PROFILE = payload; } catch {}
      });

      document.getElementById('settingsControlImport')?.addEventListener('click', async () => {
        const raw = await uiPrompt('Paste settings profile JSON', '', { title: 'Import settings profile', confirmLabel: 'Import' });
        if (raw == null) return;
        const txt = String(raw || '').trim();
        if (!txt) return;
        try {
          const parsed = JSON.parse(txt);
          state.settingsControlModel = mergeSettingsControlModel(parsed);
          applySettingsControlModel({ silent: true });
          renderSettingsControlCenter();
          showToast('Local settings profile imported.');
        } catch {
          showToast('Invalid JSON profile.');
        }
      });

      document.getElementById('settingsControlReset')?.addEventListener('click', async () => {
        if (!(await uiConfirm('Reset settings control profile to defaults?', { danger: true }))) return;
        state.settingsControlModel = getDefaultSettingsControlModel();
        applySettingsControlModel({ silent: true });
        renderSettingsControlCenter();
        showToast('Local settings control profile reset.');
      });

      applySettingsSubTabsUi();
      applySettingsAgentsCategoryUi();
      applySettingsControlDomainScopeUi();
      applySettingsControlModel({ silent: true });
      void syncRuntimeSettingsIntoControlModel().then((ok) => {
        if (ok && state.settingsSubTab === 'control') renderSettingsControlCenter();
      });
      if (state.settingsSubTab === 'agents') paintSettingsAgentsThrottled();
      if (state.settingsSubTab === 'rules') syncSettingsRulesVersionSelect();
      if (state.settingsSubTab === 'control') renderSettingsControlCenter();
    }

    function applyIdsRulesSubTabUi() {
      const tab = String(state.idsRulesUi?.tab || 'editor');
      document.querySelectorAll('[data-ids-rules-tab]').forEach((btn) => {
        btn.classList.toggle('active', String(btn.getAttribute('data-ids-rules-tab') || '') === tab);
      });
      document.querySelectorAll('[data-ids-rules-pane]').forEach((pane) => {
        pane.classList.toggle('active', String(pane.getAttribute('data-ids-rules-pane') || '') === tab);
      });
    }

    function setIdsRulesSubTab(tab) {
      const t0 = String(tab || '').trim().toLowerCase();
      const t = ['editor', 'visual', 'extension', 'suppressions'].includes(t0) ? t0 : 'editor';
      if (!state.idsRulesUi) state.idsRulesUi = { tab: 'editor', selectedLineNo: -1, filter: '', sourceLines: [], parsedRules: [] };
      state.idsRulesUi.tab = t;
      applyIdsRulesSubTabUi();
      if (t === 'visual') renderIdsRulesGrid();
      if (t === 'suppressions') loadIdsSuppressions();
    }

    function parseSuricataRuleLine(line, lineNo) {
      const m = String(line || '').match(/^(\s*#\s*)?(alert|drop|reject|pass)\s+(\S+)\s+(.+?)\s+->\s+(.+?)\s*\((.*)\)\s*$/i);
      if (!m) return null;
      const disabledPrefix = Boolean(m[1]);
      const action = String(m[2] || 'alert').toLowerCase();
      const proto = String(m[3] || 'tcp').toLowerCase();
      const src = String(m[4] || 'any any').trim();
      const dst = String(m[5] || 'any any').trim();
      const rawOptions = String(m[6] || '').trim();

      const getOpt = (key) => {
        const r = new RegExp(`${key}\\s*:\\s*([^;]+);`, 'i');
        const hit = rawOptions.match(r);
        if (!hit) return '';
        return String(hit[1] || '').trim();
      };

      const msgRaw = getOpt('msg').replace(/^"|"$/g, '');
      const sidRaw = getOpt('sid');
      const revRaw = getOpt('rev');
      const classRaw = getOpt('classtype');

      return {
        lineNo,
        enabled: !disabledPrefix,
        action,
        proto,
        src,
        dst,
        rawOptions,
        msg: msgRaw,
        sid: sidRaw,
        rev: revRaw,
        classtype: classRaw,
      };
    }

    function setRuleOpt(rawOptions, key, value, quote = false) {
      let opts = String(rawOptions || '').trim();
      const escaped = quote ? `"${String(value || '').replaceAll('"', '\\"')}"` : String(value || '');
      const re = new RegExp(`${key}\\s*:\\s*[^;]*;`, 'i');
      if (!value) {
        opts = opts.replace(re, '').replace(/\s{2,}/g, ' ').trim();
        return opts;
      }
      if (re.test(opts)) {
        opts = opts.replace(re, `${key}:${escaped};`);
      } else {
        opts = opts.endsWith(';') ? `${opts} ${key}:${escaped};` : `${opts}; ${key}:${escaped};`;
      }
      return opts.trim();
    }

    function buildSuricataRuleLine(rule) {
      const r = rule || {};
      let opts = String(r.rawOptions || '').trim();
      opts = setRuleOpt(opts, 'msg', r.msg || '', true);
      opts = setRuleOpt(opts, 'sid', r.sid || '');
      opts = setRuleOpt(opts, 'rev', r.rev || '1');
      opts = setRuleOpt(opts, 'classtype', r.classtype || '');
      if (opts && !opts.endsWith(';')) opts = `${opts};`;
      const prefix = r.enabled ? '' : '# ';
      return `${prefix}${String(r.action || 'alert')} ${String(r.proto || 'tcp')} ${String(r.src || 'any any')} -> ${String(r.dst || 'any any')} (${opts})`;
    }

    function syncIdsRulesUiFromEditor({ keepSelection = true } = {}) {
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      if (!state.idsRulesUi) state.idsRulesUi = { tab: 'editor', selectedLineNo: -1, filter: '', sourceLines: [], parsedRules: [] };
      const prev = Number(state.idsRulesUi.selectedLineNo || -1);
      const src = String(editor.value || '').replaceAll('\r\n', '\n').split('\n');
      const parsed = [];
      for (let i = 0; i < src.length; i++) {
        const p = parseSuricataRuleLine(src[i], i);
        if (p) parsed.push(p);
      }
      state.idsRulesUi.sourceLines = src;
      state.idsRulesUi.parsedRules = parsed;
      if (keepSelection && parsed.some((x) => x.lineNo === prev)) state.idsRulesUi.selectedLineNo = prev;
      else if (!parsed.length) state.idsRulesUi.selectedLineNo = -1;
      else state.idsRulesUi.selectedLineNo = parsed[0].lineNo;
      renderIdsRulesGrid();
      syncSettingsRulesVersionSelect();
    }

    function ruleFilterText() {
      return String(document.getElementById('idsRulesFilter')?.value || state.idsRulesUi?.filter || '').trim().toLowerCase();
    }

    function filteredParsedRules() {
      const all = Array.isArray(state.idsRulesUi?.parsedRules) ? state.idsRulesUi.parsedRules : [];
      const q = ruleFilterText();
      if (!q) return all;
      return all.filter((r) => `${r.sid} ${r.msg} ${r.action} ${r.proto} ${r.src} ${r.dst} ${r.classtype}`.toLowerCase().includes(q));
    }

    function renderIdsRulesGrid() {
      const host = document.getElementById('idsRulesGrid');
      if (!host) return;
      const rows = filteredParsedRules();
      if (!rows.length) {
        host.innerHTML = '<div class="muted p-12">No parsed rules match this filter.</div>';
        return;
      }
      const selected = Number(state.idsRulesUi?.selectedLineNo || -1);
      const wrap = document.createElement('div');
      const table = document.createElement('table');
      table.innerHTML = `<thead><tr>
        <th width="80">State</th>
        <th width="110">Action</th>
        <th width="110">Proto</th>
        <th width="130">SID</th>
        <th width="90">Rev</th>
        <th width="180">Classtype</th>
        <th>Message</th>
      </tr></thead>`;
      const tbody = document.createElement('tbody');
      for (const r of rows.slice(0, 1500)) {
        const tr = document.createElement('tr');
        tr.classList.toggle('active', r.lineNo === selected);
        const badge = `<span class="ruleBadge ${r.enabled ? '' : 'off'}">${r.enabled ? 'on' : 'off'}</span>`;
        tr.innerHTML = `<td>${badge}</td><td>${escapeHtml(r.action)}</td><td>${escapeHtml(r.proto)}</td><td class="mono">${escapeHtml(r.sid || '—')}</td><td>${escapeHtml(r.rev || '1')}</td><td>${escapeHtml(r.classtype || '—')}</td><td>${escapeHtml(r.msg || '—')}</td>`;
        tr.addEventListener('click', () => {
          state.idsRulesUi.selectedLineNo = r.lineNo;
          renderIdsRulesGrid();
        });
        tr.addEventListener('dblclick', () => {
          updateRuleByLineNo(r.lineNo, (x) => { x.enabled = !x.enabled; });
        });
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      wrap.appendChild(table);
      host.innerHTML = '';
      host.appendChild(wrap);
    }

    function updateRuleByLineNo(lineNo, mutate) {
      const idx = state.idsRulesUi.parsedRules.findIndex((r) => r.lineNo === lineNo);
      if (idx < 0) return;
      const rule = { ...state.idsRulesUi.parsedRules[idx] };
      try { mutate(rule); } catch { return; }
      const nextLine = buildSuricataRuleLine(rule);
      if (!Array.isArray(state.idsRulesUi.sourceLines)) return;
      if (lineNo < 0 || lineNo >= state.idsRulesUi.sourceLines.length) return;
      state.idsRulesUi.sourceLines[lineNo] = nextLine;
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      editor.value = state.idsRulesUi.sourceLines.join('\n');
      syncIdsRulesUiFromEditor();
    }

    function bulkSetFilteredRulesEnabled(enabled) {
      const rows = filteredParsedRules();
      if (!rows.length) return;
      const lineSet = new Set(rows.map((r) => r.lineNo));
      const nextLines = Array.isArray(state.idsRulesUi.sourceLines) ? [...state.idsRulesUi.sourceLines] : [];
      for (const p of state.idsRulesUi.parsedRules) {
        if (!lineSet.has(p.lineNo)) continue;
        const r = { ...p, enabled: Boolean(enabled) };
        nextLines[p.lineNo] = buildSuricataRuleLine(r);
      }
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      editor.value = nextLines.join('\n');
      syncIdsRulesUiFromEditor();
    }

    function nextRuleSid() {
      let maxSid = 1_000_000;
      for (const r of (state.idsRulesUi?.parsedRules || [])) {
        const sid = Number(String(r.sid || '').trim());
        if (Number.isFinite(sid) && sid > maxSid) maxSid = sid;
      }
      return String(maxSid + 1);
    }

    function appendRuleTemplate({ action = 'alert', proto = 'tcp', src = 'any any', dst = 'any any', msg = 'Custom extension rule', classtype = 'trojan-activity' } = {}) {
      const sid = nextRuleSid();
      const line = `${action} ${proto} ${src} -> ${dst} (msg:"${String(msg || '').replaceAll('"', '\\"')}"; sid:${sid}; rev:1; classtype:${classtype};)`;
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      const body = String(editor.value || '').trimEnd();
      editor.value = body ? `${body}\n${line}\n` : `${line}\n`;
      syncIdsRulesUiFromEditor();
      const extStatus = document.getElementById('idsRulesExtensionStatus');
      if (extStatus) extStatus.textContent = `Extension rule appended (sid:${sid}). Save rules to publish.`;
      setSettingsRulesStatus(`Extension rule appended (sid:${sid}).`, false);
    }

    function initIdsRulesAdvancedUi() {
      if (state._idsRulesAdvancedUiInit) return;
      state._idsRulesAdvancedUiInit = true;

      document.querySelectorAll('[data-ids-rules-tab]').forEach((btn) => {
        btn.addEventListener('click', () => setIdsRulesSubTab(btn.getAttribute('data-ids-rules-tab')));
      });
      applyIdsRulesSubTabUi();

      const editor = document.getElementById('idsRulesEditor');
      editor?.addEventListener('input', () => {
        if (state._idsRulesSyncTimer) clearTimeout(state._idsRulesSyncTimer);
        state._idsRulesSyncTimer = setTimeout(() => syncIdsRulesUiFromEditor(), 140);
      });

      document.getElementById('idsRulesFilter')?.addEventListener('input', (ev) => {
        state.idsRulesUi.filter = String(ev?.target?.value || '');
        renderIdsRulesGrid();
      });

      document.getElementById('idsRulesEnableFiltered')?.addEventListener('click', () => bulkSetFilteredRulesEnabled(true));
      document.getElementById('idsRulesDisableFiltered')?.addEventListener('click', () => bulkSetFilteredRulesEnabled(false));

      document.getElementById('idsRulesAddTemplate')?.addEventListener('click', () => {
        appendRuleTemplate({
          action: String(document.getElementById('idsExtAction')?.value || 'alert'),
          proto: String(document.getElementById('idsExtProto')?.value || 'tcp'),
          src: String(document.getElementById('idsExtSrc')?.value || 'any any'),
          dst: String(document.getElementById('idsExtDst')?.value || 'any any'),
          msg: String(document.getElementById('idsExtMsg')?.value || 'Custom extension rule'),
          classtype: String(document.getElementById('idsExtClass')?.value || 'trojan-activity'),
        });
      });
      document.getElementById('idsRulesAddDnsTemplate')?.addEventListener('click', () => {
        appendRuleTemplate({
          action: 'alert',
          proto: 'udp',
          src: 'any any',
          dst: 'any 53',
          msg: 'Potential DNS tunneling pattern',
          classtype: 'bad-unknown',
        });
      });
      document.getElementById('idsRulesAddLateralTemplate')?.addEventListener('click', () => {
        appendRuleTemplate({
          action: 'alert',
          proto: 'tcp',
          src: '$HOME_NET any',
          dst: '$HOME_NET 445',
          msg: 'Potential SMB lateral movement spike',
          classtype: 'attempted-admin',
        });
      });
    }

    function syncSettingsRulesVersionSelect() {
      const idsSel = document.getElementById('idsRulesVersionSelect');
      const stSel = document.getElementById('rulesVersionSelect');
      if (!idsSel || !stSel) return;
      const options = Array.from(idsSel.options || []);
      stSel.innerHTML = '';
      const opt0 = document.createElement('option');
      opt0.value = '';
      opt0.textContent = 'Select version…';
      stSel.appendChild(opt0);
      for (const o of options) {
        if (!o.value) continue;
        const opt = document.createElement('option');
        opt.value = o.value;
        opt.textContent = o.textContent || o.value;
        stSel.appendChild(opt);
      }
      stSel.value = idsSel.value || '';
    }

    /* ── Rules Workspace Tab Management ── */

    const _rulesWsToggleLabels = {
      editor: '📝 Rule Editor',
      visual: '🔧 Visual Tuning',
      builder: '➕ Rule Builder',
      config: '📁 Config Files',
      suppressions: '🚫 Suppressions',
      versions: '📋 Versions',
    };

    function _closeRulesWsMenu() {
      const menu = document.getElementById('rulesWsMenu');
      const toggle = document.getElementById('rulesWsToggle');
      if (menu) menu.classList.add('hidden');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }

    function applyRulesWorkspaceTabUi() {
      const tab = String(state.rulesWorkspace?.tab || 'editor');
      document.querySelectorAll('[data-rules-tab]').forEach((btn) => {
        btn.classList.toggle('active', String(btn.getAttribute('data-rules-tab') || '') === tab);
      });
      document.querySelectorAll('[data-rules-pane]').forEach((pane) => {
        pane.classList.toggle('active', String(pane.getAttribute('data-rules-pane') || '') === tab);
      });
      const labels = {
        editor: 'IDS Rule Editor · Full access to Suricata rules files',
        visual: 'Visual Tuning · Enable/disable/filter rules in a table view',
        builder: 'Rule Builder · Create custom IDS/IPS rules with guided fields',
        config: 'Config Files · Edit parsers.yaml, rules.yaml, and integrations',
        suppressions: 'Suppressions · Manage IDS alert suppression entries',
        versions: 'Version History · Rollback to previous rule snapshots',
      };
      const meta = document.getElementById('rulesWorkspaceMeta');
      if (meta) meta.textContent = labels[tab] || '';
      /* Update toggle label */
      const wsLabel = document.getElementById('rulesWsLabel');
      if (wsLabel) wsLabel.textContent = _rulesWsToggleLabels[tab] || tab;
      _closeRulesWsMenu();
    }

    function setRulesWorkspaceTab(tab) {
      const t0 = String(tab || '').trim().toLowerCase();
      const valid = ['editor', 'visual', 'builder', 'config', 'suppressions', 'versions'];
      const t = valid.includes(t0) ? t0 : 'editor';
      if (!state.rulesWorkspace) state.rulesWorkspace = { tab: 'editor', configFiles: [], activeConfigFile: null, configOriginal: '', versions: [] };
      state.rulesWorkspace.tab = t;
      applyRulesWorkspaceTabUi();
      if (t === 'visual') renderRulesVisualGrid();
      if (t === 'suppressions') loadRulesSuppressions();
      if (t === 'versions') loadRulesVersions();
      if (t === 'config' && !state.rulesWorkspace.configFiles.length) loadRulesConfigFileList();
      if (t === 'builder') updateRuleBuilderPreview();
    }

    /* ── Rules KPI ── */

    function updateRulesKpi() {
      const parsed = Array.isArray(state.idsRulesUi?.parsedRules) ? state.idsRulesUi.parsedRules : [];
      const enabled = parsed.filter((r) => r.enabled).length;
      const disabled = parsed.length - enabled;
      const versions = Array.isArray(state.rulesWorkspace?.versions) ? state.rulesWorkspace.versions.length : 0;
      const hasRules = parsed.length > 0;
      document.getElementById('rulesKpiTotal').textContent = hasRules ? parsed.length : '—';
      document.getElementById('rulesKpiEnabled').textContent = hasRules ? enabled : '—';
      document.getElementById('rulesKpiDisabled').textContent = hasRules ? disabled : '—';
      document.getElementById('rulesKpiVersions').textContent = versions;
    }

    /* ── Rule Editor Tab ── */

    function syncRulesEditorFromHidden() {
      const hidden = document.getElementById('idsRulesEditor');
      const editor = document.getElementById('rulesEditorArea');
      if (!hidden || !editor) return;
      editor.value = hidden.value || '';
      updateRulesEditorLineNumbers();
      syncIdsRulesUiFromEditor();
      updateRulesKpi();
    }

    function syncHiddenFromRulesEditor() {
      const hidden = document.getElementById('idsRulesEditor');
      const editor = document.getElementById('rulesEditorArea');
      if (!hidden || !editor) return;
      hidden.value = editor.value;
      syncIdsRulesUiFromEditor();
      updateRulesKpi();
    }

    function updateRulesEditorLineNumbers() {
      const editor = document.getElementById('rulesEditorArea');
      const nums = document.getElementById('rulesLineNumbers');
      const countEl = document.getElementById('rulesEditorLineCount');
      if (!editor || !nums) return;
      const lines = (editor.value || '').split('\n');
      const count = lines.length;
      let html = '';
      for (let i = 1; i <= count; i++) html += i + '\n';
      nums.textContent = html;
      if (countEl) countEl.textContent = `${count} line${count !== 1 ? 's' : ''}`;
    }

    function rulesEditorSearchHighlight() {
      const q = String(document.getElementById('rulesEditorSearch')?.value || '').trim().toLowerCase();
      const editor = document.getElementById('rulesEditorArea');
      if (!editor || !q) return;
      const text = editor.value || '';
      const idx = text.toLowerCase().indexOf(q);
      if (idx >= 0) {
        editor.focus();
        editor.setSelectionRange(idx, idx + q.length);
        // Scroll to selection
        const linesBefore = text.substring(0, idx).split('\n').length - 1;
        const lineHeight = parseFloat(getComputedStyle(editor).lineHeight) || 18;
        editor.scrollTop = Math.max(0, linesBefore * lineHeight - 80);
      }
    }

    function setRulesEditorStatus(msg, isError = false) {
      const el = document.getElementById('rulesEditorStatus');
      if (!el) return;
      el.textContent = String(msg || '');
      el.style.color = isError ? 'var(--danger, #ff6b6b)' : '';
    }

    /* ── Visual Tuning Tab ── */

    function rulesVisualFilteredRules() {
      const all = Array.isArray(state.idsRulesUi?.parsedRules) ? state.idsRulesUi.parsedRules : [];
      const q = String(document.getElementById('rulesVisualFilter')?.value || '').trim().toLowerCase();
      const actionFilter = String(document.getElementById('rulesVisualActionFilter')?.value || '');
      const stateFilter = String(document.getElementById('rulesVisualStateFilter')?.value || '');
      return all.filter((r) => {
        if (q && !`${r.sid} ${r.msg} ${r.action} ${r.proto} ${r.src} ${r.dst} ${r.classtype}`.toLowerCase().includes(q)) return false;
        if (actionFilter && r.action !== actionFilter) return false;
        if (stateFilter === 'enabled' && !r.enabled) return false;
        if (stateFilter === 'disabled' && r.enabled) return false;
        return true;
      });
    }

    function renderRulesVisualGrid() {
      const host = document.getElementById('rulesVisualGrid');
      if (!host) return;
      const rows = rulesVisualFilteredRules();
      const countEl = document.getElementById('rulesVisualCount');
      const total = Array.isArray(state.idsRulesUi?.parsedRules) ? state.idsRulesUi.parsedRules.length : 0;
      if (countEl) countEl.textContent = `${rows.length} of ${total} rules`;
      if (!rows.length) {
        host.innerHTML = '<div class="muted p-16 ta-center">No rules match the current filters. Load rules first.</div>';
        return;
      }
      const selected = Number(state.idsRulesUi?.selectedLineNo || -1);
      const table = document.createElement('table');
      table.innerHTML = `<thead><tr>
        <th width="70">State</th>
        <th width="90">Action</th>
        <th width="70">Proto</th>
        <th width="100">SID</th>
        <th width="60">Rev</th>
        <th width="150">Classtype</th>
        <th>Message</th>
        <th width="70">Toggle</th>
      </tr></thead>`;
      const tbody = document.createElement('tbody');
      for (const r of rows.slice(0, 2000)) {
        const tr = document.createElement('tr');
        tr.classList.toggle('active', r.lineNo === selected);
        const badge = `<span class="ruleBadge ${r.enabled ? '' : 'off'}">${r.enabled ? 'ON' : 'OFF'}</span>`;
        const actionBadge = `<span class="ids-action-badge ${r.action}">${escapeHtml(r.action)}</span>`;
        const protoBadge = `<span class="ids-proto-badge">${escapeHtml(r.proto)}</span>`;
        tr.innerHTML = `<td>${badge}</td><td>${actionBadge}</td><td>${protoBadge}</td><td class="mono">${escapeHtml(r.sid || '—')}</td><td>${escapeHtml(r.rev || '1')}</td><td>${escapeHtml(r.classtype || '—')}</td><td>${escapeHtml(r.msg || '—')}</td><td><button class="btn sm">⇄</button></td>`;
        tr.addEventListener('click', () => {
          state.idsRulesUi.selectedLineNo = r.lineNo;
          renderRulesVisualGrid();
        });
        tr.querySelector('button')?.addEventListener('click', (ev) => {
          ev.stopPropagation();
          updateRuleByLineNo(r.lineNo, (x) => { x.enabled = !x.enabled; });
          syncRulesEditorFromHidden();
          renderRulesVisualGrid();
        });
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      host.innerHTML = '';
      host.appendChild(table);
    }

    /* ── Rule Builder Tab ── */

    const RULE_TEMPLATES = {
      'dns-tunnel': { action: 'alert', proto: 'udp', srcAddr: 'any', srcPort: 'any', dstAddr: 'any', dstPort: '53', dir: '->', msg: 'PERCEPTA Potential DNS tunneling detected', classtype: 'bad-unknown', content: 'content:"|00 00 ff 00 01|";', flow: '', extra: 'threshold:type both, track by_src, count 10, seconds 60;' },
      'lateral-smb': { action: 'alert', proto: 'tcp', srcAddr: '$HOME_NET', srcPort: 'any', dstAddr: '$HOME_NET', dstPort: '445', dir: '->', msg: 'PERCEPTA Potential SMB lateral movement', classtype: 'attempted-admin', content: '', flow: 'established,to_server', extra: 'threshold:type both, track by_src, count 5, seconds 120;' },
      'ssh-brute': { action: 'alert', proto: 'tcp', srcAddr: 'any', srcPort: 'any', dstAddr: '$HOME_NET', dstPort: '22', dir: '->', msg: 'PERCEPTA SSH brute force attempt', classtype: 'attempted-admin', content: '', flow: 'to_server', extra: 'threshold:type both, track by_src, count 5, seconds 60;' },
      'c2-beacon': { action: 'alert', proto: 'tcp', srcAddr: '$HOME_NET', srcPort: 'any', dstAddr: '$EXTERNAL_NET', dstPort: 'any', dir: '->', msg: 'PERCEPTA Suspicious periodic C2-like beacon', classtype: 'trojan-activity', content: '', flow: 'established,to_server', extra: 'threshold:type both, track by_src, count 30, seconds 300;' },
      'data-exfil': { action: 'alert', proto: 'tcp', srcAddr: '$HOME_NET', srcPort: 'any', dstAddr: '$EXTERNAL_NET', dstPort: 'any', dir: '->', msg: 'PERCEPTA Large outbound transfer — possible data exfiltration', classtype: 'bad-unknown', content: '', flow: 'established,to_server', extra: 'dsize:>10000;' },
      'port-scan': { action: 'alert', proto: 'tcp', srcAddr: 'any', srcPort: 'any', dstAddr: '$HOME_NET', dstPort: 'any', dir: '->', msg: 'PERCEPTA Horizontal port scan detected', classtype: 'network-scan', content: '', flow: '', extra: 'flags:S,12; threshold:type both, track by_src, count 25, seconds 10;' },
      'web-shell': { action: 'alert', proto: 'http', srcAddr: '$EXTERNAL_NET', srcPort: 'any', dstAddr: '$HOME_NET', dstPort: 'any', dir: '->', msg: 'PERCEPTA Possible web shell access pattern', classtype: 'web-application-attack', content: 'content:"cmd="; content:"exec(";', flow: 'established,to_server', extra: '' },
      'crypto-mine': { action: 'alert', proto: 'tcp', srcAddr: '$HOME_NET', srcPort: 'any', dstAddr: '$EXTERNAL_NET', dstPort: 'any', dir: '->', msg: 'PERCEPTA Possible cryptocurrency mining communication', classtype: 'trojan-activity', content: 'content:"stratum+tcp://";', flow: 'established,to_server', extra: '' },
    };

    function updateRuleBuilderPreview() {
      const preview = document.getElementById('ruleBuilderPreview');
      if (!preview) return;
      const action = document.getElementById('ruleBuilderAction')?.value || 'alert';
      const proto = document.getElementById('ruleBuilderProto')?.value || 'tcp';
      const srcAddr = document.getElementById('ruleBuilderSrcAddr')?.value?.trim() || 'any';
      const srcPort = document.getElementById('ruleBuilderSrcPort')?.value?.trim() || 'any';
      const dir = document.getElementById('ruleBuilderDir')?.value || '->';
      const dstAddr = document.getElementById('ruleBuilderDstAddr')?.value?.trim() || 'any';
      const dstPort = document.getElementById('ruleBuilderDstPort')?.value?.trim() || 'any';
      const msg = document.getElementById('ruleBuilderMsg')?.value?.trim() || '';
      const classtype = document.getElementById('ruleBuilderClass')?.value || 'trojan-activity';
      const content = document.getElementById('ruleBuilderContent')?.value?.trim() || '';
      const flow = document.getElementById('ruleBuilderFlow')?.value || '';
      const extra = document.getElementById('ruleBuilderExtra')?.value?.trim() || '';
      const sid = nextRuleSid();

      let opts = `msg:"${msg.replaceAll('"', '\\"')}"; sid:${sid}; rev:1; classtype:${classtype};`;
      if (flow) opts += ` flow:${flow};`;
      if (content) opts += ` ${content.endsWith(';') ? content : content + ';'}`;
      if (extra) opts += ` ${extra.endsWith(';') ? extra : extra + ';'}`;

      const rule = `${action} ${proto} ${srcAddr} ${srcPort} ${dir} ${dstAddr} ${dstPort} (${opts})`;
      preview.textContent = rule;
      return rule;
    }

    function applyRuleBuilderTemplate(tplKey) {
      const tpl = RULE_TEMPLATES[tplKey];
      if (!tpl) return;
      const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
      setVal('ruleBuilderAction', tpl.action);
      setVal('ruleBuilderProto', tpl.proto);
      setVal('ruleBuilderSrcAddr', tpl.srcAddr);
      setVal('ruleBuilderSrcPort', tpl.srcPort);
      setVal('ruleBuilderDir', tpl.dir);
      setVal('ruleBuilderDstAddr', tpl.dstAddr);
      setVal('ruleBuilderDstPort', tpl.dstPort);
      setVal('ruleBuilderMsg', tpl.msg);
      setVal('ruleBuilderClass', tpl.classtype);
      setVal('ruleBuilderContent', tpl.content);
      setVal('ruleBuilderFlow', tpl.flow);
      setVal('ruleBuilderExtra', tpl.extra);
      updateRuleBuilderPreview();
    }

    function resetRuleBuilderForm() {
      const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
      setVal('ruleBuilderAction', 'alert');
      setVal('ruleBuilderProto', 'tcp');
      setVal('ruleBuilderSrcAddr', 'any');
      setVal('ruleBuilderSrcPort', 'any');
      setVal('ruleBuilderDir', '->');
      setVal('ruleBuilderDstAddr', 'any');
      setVal('ruleBuilderDstPort', 'any');
      setVal('ruleBuilderMsg', '');
      setVal('ruleBuilderClass', 'trojan-activity');
      setVal('ruleBuilderContent', '');
      setVal('ruleBuilderFlow', '');
      setVal('ruleBuilderExtra', '');
      updateRuleBuilderPreview();
    }

    /* ── Config Files Tab ── */

    async function loadRulesConfigFileList() {
      const host = document.getElementById('rulesConfigFileList');
      if (!host) return;
      host.innerHTML = '<div class="muted text-xs p-12">Loading…</div>';
      try {
        const files = await apiFetchJson(API.configFiles, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        const list = Array.isArray(files) ? files : [];
        state.rulesWorkspace.configFiles = list;
        host.innerHTML = '';
        for (const f of list) {
          const item = document.createElement('div');
          item.className = 'rules-config-file-item';
          item.dataset.configName = f.name;
          const sizeStr = f.size_bytes > 1024 ? `${(f.size_bytes / 1024).toFixed(1)} KB` : `${f.size_bytes} B`;
          item.innerHTML = `<div class="rules-config-file-name">${escapeHtml(f.name)}</div><div class="rules-config-file-label">${escapeHtml(f.label)}${f.writable ? '' : ' <em>(read-only)</em>'}</div><div class="rules-config-file-size">${sizeStr}</div>`;
          item.addEventListener('click', () => loadRulesConfigFile(f.name));
          host.appendChild(item);
        }
      } catch (e) {
        host.innerHTML = '<div class="muted text-xs p-12 text-danger">Failed to load file list</div>';
      }
    }

    async function loadRulesConfigFile(name) {
      const editor = document.getElementById('rulesConfigEditor');
      const fnEl = document.getElementById('rulesConfigFileName');
      const statusEl = document.getElementById('rulesConfigStatus');
      const saveBtn = document.getElementById('rulesConfigSave');
      const revertBtn = document.getElementById('rulesConfigRevert');
      if (!editor) return;
      if (fnEl) fnEl.textContent = name;
      if (statusEl) statusEl.textContent = 'Loading…';
      editor.value = '';
      editor.readOnly = true;
      try {
        const url = `${API.configFile}?name=${encodeURIComponent(name)}`;
        const data = await apiFetchJson(url, { timeoutMs: 8000, headers: { 'Accept': 'application/json' } });
        editor.value = data.content || '';
        state.rulesWorkspace.activeConfigFile = name;
        state.rulesWorkspace.configOriginal = data.content || '';
        const writable = (state.rulesWorkspace.configFiles || []).find((f) => f.name === name)?.writable !== false;
        editor.readOnly = !writable;
        if (saveBtn) {
          saveBtn.disabled = !writable;
          saveBtn.textContent = writable ? '💾 Save' : 'Read-only';
          saveBtn.title = writable ? 'Save this file' : 'This file is read-only and cannot be saved from dashboard.';
        }
        if (revertBtn) {
          revertBtn.disabled = !writable;
          revertBtn.title = writable ? 'Revert unsaved changes' : 'Read-only file has no editable buffer to revert.';
        }
        if (statusEl) {
          statusEl.textContent = writable
            ? `Loaded — ${data.size_bytes} bytes`
            : `Loaded read-only — ${data.size_bytes} bytes`;
        }
        // Highlight active file in sidebar
        document.querySelectorAll('.rules-config-file-item').forEach((el) => {
          el.classList.toggle('active', el.dataset.configName === name);
        });
      } catch (e) {
        if (statusEl) statusEl.textContent = 'Failed to load file.';
        editor.value = '';
      }
    }

    async function saveRulesConfigFile() {
      const editor = document.getElementById('rulesConfigEditor');
      const statusEl = document.getElementById('rulesConfigStatus');
      const name = state.rulesWorkspace?.activeConfigFile;
      if (!editor || !name) return;
      if (editor.readOnly) {
        if (statusEl) statusEl.textContent = 'Read-only file cannot be saved from dashboard.';
        showToast('Selected file is read-only.', 'warn');
        return;
      }
      if (statusEl) statusEl.textContent = 'Saving…';
      try {
        await apiPostJson(API.configFile, { name, content: editor.value }, { timeoutMs: 8000 });
        state.rulesWorkspace.configOriginal = editor.value;
        if (statusEl) statusEl.textContent = 'Saved successfully ✓';
        showToast(`${name} saved.`);
      } catch (e) {
        if (statusEl) statusEl.textContent = 'Save failed — check permissions.';
        showToast('Failed to save config file.');
      }
    }

    function revertRulesConfigFile() {
      const editor = document.getElementById('rulesConfigEditor');
      const statusEl = document.getElementById('rulesConfigStatus');
      if (!editor) return;
      editor.value = state.rulesWorkspace?.configOriginal || '';
      if (statusEl) statusEl.textContent = 'Reverted to last saved version.';
    }

    /* ── Suppressions Tab ── */

    async function loadRulesSuppressions() {
      const host = document.getElementById('rulesSuppList');
      if (!host) return;
      host.innerHTML = '<div class="muted p-16 ta-center">Loading…</div>';
      try {
        const list = await apiFetchJson(API.idsSuppressions, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        const rows = Array.isArray(list) ? list : [];
        const suppCountEl = document.getElementById('rulesKpiSupps');
        if (suppCountEl) suppCountEl.textContent = rows.length || '—';
        if (!rows.length) {
          host.innerHTML = '<div class="muted p-16 ta-center">No active suppressions. IDS alerts are flowing unfiltered.</div>';
          return;
        }
        const filterQ = String(document.getElementById('rulesSuppFilter')?.value || '').trim().toLowerCase();
        const filtered = filterQ ? rows.filter((r) => `${r.key} ${r.reason}`.toLowerCase().includes(filterQ)) : rows;
        const table = document.createElement('table');
        table.innerHTML = `<thead><tr>
          <th width="220">Key</th>
          <th width="170">Expires</th>
          <th>Reason</th>
          <th width="100">Action</th>
        </tr></thead>`;
        const tbody = document.createElement('tbody');
        for (const r of filtered.slice(0, 500)) {
          const tr = document.createElement('tr');
          const until = r.until_unix ? formatTime(r.until_unix) : 'Permanent';
          tr.innerHTML = `
            <td class="mono">${escapeHtml(r.key || '')}</td>
            <td>${escapeHtml(until)}</td>
            <td>${escapeHtml(r.reason || '—')}</td>
            <td><button class="btn sm danger">Remove</button></td>
          `;
          tr.querySelector('button')?.addEventListener('click', async () => {
            try {
              await apiPostJson(API.idsSuppressionsRemove, { key: r.key }, { timeoutMs: 4000 });
              showToast('Suppression removed.');
              loadRulesSuppressions();
            } catch {
              showToast('Failed to remove suppression.');
            }
          });
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        host.innerHTML = '';
        host.appendChild(table);
      } catch (e) {
          host.innerHTML = '<div class="muted text-danger p-16 ta-center">Failed to load suppressions.</div>';
      }
    }

    async function addRulesSuppression() {
      const keyEl = document.getElementById('rulesSuppNewKey');
      const hoursEl = document.getElementById('rulesSuppNewHours');
      const reasonEl = document.getElementById('rulesSuppNewReason');
      const key = String(keyEl?.value || '').trim();
      if (!key) { showToast('Suppression key is required (e.g. sid:2100498).'); return; }
      const hours = Math.max(1, Math.min(720, Number(hoursEl?.value || 24)));
      const reason = String(reasonEl?.value || 'Dashboard suppression').trim();
      try {
        await apiPostJson(API.idsSuppressions, { key, seconds: hours * 3600, reason }, { timeoutMs: 4000 });
        showToast(`Suppression added: ${key} for ${hours}h.`);
        if (keyEl) keyEl.value = '';
        if (reasonEl) reasonEl.value = '';
        loadRulesSuppressions();
      } catch (e) {
        showToast('Failed to add suppression.');
      }
    }

    /* ── Versions Tab ── */

    async function loadRulesVersions() {
      const host = document.getElementById('rulesVersionTimeline');
      if (!host) return;
      host.innerHTML = '<div class="muted p-16 ta-center">Loading…</div>';
      try {
        const list = await apiFetchJson(API.idsRulesVersions, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        const versions = Array.isArray(list) ? list : [];
        state.rulesWorkspace.versions = versions;
        updateRulesKpi();
        syncSettingsRulesVersionSelect();
        if (!versions.length) {
          host.innerHTML = '<div class="muted p-16 ta-center">No saved versions yet. Save rules to create the first snapshot.</div>';
          return;
        }
        host.innerHTML = '';
        for (let i = 0; i < versions.length; i++) {
          const v = versions[i];
          const item = document.createElement('div');
          item.className = 'rules-version-item';
          item.dataset.versionId = v.id;
          const label = i === 0 ? 'Latest version' : `Version ${versions.length - i}`;
          // Parse timestamp from id (format: 20250120T143000Z)
          let timeStr = v.id;
          const tm = v.id.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
          if (tm) timeStr = `${tm[1]}-${tm[2]}-${tm[3]} ${tm[4]}:${tm[5]}:${tm[6]} UTC`;
          item.innerHTML = `
            <div class="rules-version-dot"></div>
            <div>
              <div class="rules-version-id">${escapeHtml(timeStr)}</div>
              <div class="rules-version-label">${escapeHtml(label)} · ${escapeHtml(v.filename || '')}</div>
            </div>
            <div class="rules-version-actions">
              <button class="btn sm" title="Rollback to this version">⏪ Rollback</button>
            </div>
          `;
          item.addEventListener('click', () => {
            document.querySelectorAll('.rules-version-item').forEach((el) => el.classList.remove('active'));
            item.classList.add('active');
            const sel = document.getElementById('rulesVersionSelect');
            if (sel) sel.value = v.id;
          });
          item.querySelector('button')?.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            if (!(await uiConfirm(`Rollback rules to ${timeStr}?`))) return;
            const idsSel = document.getElementById('idsRulesVersionSelect');
            if (idsSel) idsSel.value = v.id;
            await rollbackIdsRules();
            syncRulesEditorFromHidden();
            setRulesEditorStatus('Rolled back ✓', false);
            showToast(`Rules rolled back to ${v.id}`);
            loadRulesVersions();
          });
          host.appendChild(item);
        }
      } catch (e) {
        host.innerHTML = '<div class="muted text-danger p-16 ta-center">Failed to load version history.</div>';
      }
    }

    /* ── Rules Workspace Initialization ── */

    function initSettingsRulesControls() {
      if (state._settingsRulesControlsInit) return;
      state._settingsRulesControlsInit = true;

      /* ── Rules workspace nav dropdown toggle ── */
      const wsToggle = document.getElementById('rulesWsToggle');
      const wsMenu = document.getElementById('rulesWsMenu');
      if (wsToggle && wsMenu) {
        wsToggle.addEventListener('click', (e) => {
          e.stopPropagation();
          const open = wsMenu.classList.toggle('hidden');
          wsToggle.setAttribute('aria-expanded', !open ? 'true' : 'false');
        });
      }

      // Workspace tabs
      document.querySelectorAll('[data-rules-tab]').forEach((btn) => {
        btn.addEventListener('click', () => setRulesWorkspaceTab(btn.getAttribute('data-rules-tab')));
      });
      applyRulesWorkspaceTabUi();
      initSigmaImport();

      // Rule Editor tab
      const editorArea = document.getElementById('rulesEditorArea');
      if (editorArea) {
        editorArea.addEventListener('input', () => {
          updateRulesEditorLineNumbers();
          if (state._rulesEditorSyncTimer) clearTimeout(state._rulesEditorSyncTimer);
          state._rulesEditorSyncTimer = setTimeout(() => {
            syncHiddenFromRulesEditor();
            updateRulesKpi();
          }, 200);
        });
        editorArea.addEventListener('scroll', () => {
          const nums = document.getElementById('rulesLineNumbers');
          if (nums) nums.scrollTop = editorArea.scrollTop;
        });
        editorArea.addEventListener('keydown', (ev) => {
          // Tab key inserts spaces
          if (ev.key === 'Tab') {
            ev.preventDefault();
            const start = editorArea.selectionStart;
            const end = editorArea.selectionEnd;
            editorArea.value = editorArea.value.substring(0, start) + '  ' + editorArea.value.substring(end);
            editorArea.selectionStart = editorArea.selectionEnd = start + 2;
          }
        });
      }

      document.getElementById('rulesEditorLoad')?.addEventListener('click', async () => {
        setRulesEditorStatus('Loading…');
        await loadIdsRules();
        syncRulesEditorFromHidden();
        const parsed = Array.isArray(state.idsRulesUi?.parsedRules) ? state.idsRulesUi.parsedRules : [];
        if (parsed.length) {
          setRulesEditorStatus('Rules loaded ✓', false);
        } else {
          setRulesEditorStatus('No rules loaded — check server logs', true);
        }
      });

      document.getElementById('rulesEditorSave')?.addEventListener('click', async () => {
        syncHiddenFromRulesEditor();
        setRulesEditorStatus('Saving…');
        await saveIdsRules();
        setRulesEditorStatus('Rules saved ✓', false);
        showToast('IDS rules saved.');
      });

      document.getElementById('rulesEditorFormat')?.addEventListener('click', () => {
        const editor = document.getElementById('rulesEditorArea');
        if (!editor) return;
        const lines = editor.value.split('\n');
        const formatted = lines.map((l) => l.trimEnd()).filter((l, i, a) => !(l === '' && i > 0 && a[i - 1] === '')).join('\n');
        editor.value = formatted;
        syncHiddenFromRulesEditor();
        updateRulesEditorLineNumbers();
        setRulesEditorStatus('Formatted.', false);
      });

      document.getElementById('rulesEditorSearch')?.addEventListener('input', () => {
        rulesEditorSearchHighlight();
      });
      document.getElementById('rulesEditorSearch')?.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') rulesEditorSearchHighlight();
      });

      // Visual Tuning tab
      document.getElementById('rulesVisualFilter')?.addEventListener('input', () => renderRulesVisualGrid());
      document.getElementById('rulesVisualActionFilter')?.addEventListener('change', () => renderRulesVisualGrid());
      document.getElementById('rulesVisualStateFilter')?.addEventListener('change', () => renderRulesVisualGrid());
      document.getElementById('rulesVisualEnableAll')?.addEventListener('click', () => {
        bulkSetFilteredRulesEnabled(true);
        syncRulesEditorFromHidden();
        renderRulesVisualGrid();
        showToast('Filtered rules enabled.');
      });
      document.getElementById('rulesVisualDisableAll')?.addEventListener('click', () => {
        bulkSetFilteredRulesEnabled(false);
        syncRulesEditorFromHidden();
        renderRulesVisualGrid();
        showToast('Filtered rules disabled.');
      });

      // Rule Builder tab
      const builderInputIds = ['ruleBuilderAction', 'ruleBuilderProto', 'ruleBuilderSrcAddr', 'ruleBuilderSrcPort', 'ruleBuilderDir', 'ruleBuilderDstAddr', 'ruleBuilderDstPort', 'ruleBuilderMsg', 'ruleBuilderClass', 'ruleBuilderContent', 'ruleBuilderFlow', 'ruleBuilderExtra'];
      for (const id of builderInputIds) {
        document.getElementById(id)?.addEventListener('input', () => updateRuleBuilderPreview());
        document.getElementById(id)?.addEventListener('change', () => updateRuleBuilderPreview());
      }
      document.getElementById('ruleBuilderAppend')?.addEventListener('click', () => {
        const rule = updateRuleBuilderPreview();
        if (!rule) return;
        const msg = document.getElementById('ruleBuilderMsg')?.value?.trim();
        if (!msg) { showToast('Message field is required.'); return; }
        const editor = document.getElementById('idsRulesEditor');
        if (!editor) return;
        const body = String(editor.value || '').trimEnd();
        editor.value = body ? `${body}\n${rule}\n` : `${rule}\n`;
        syncRulesEditorFromHidden();
        setRulesEditorStatus('Rule appended. Save to publish.', false);
        showToast('Rule appended to editor. Save to publish.');
      });
      document.getElementById('ruleBuilderCopy')?.addEventListener('click', async () => {
        const rule = updateRuleBuilderPreview();
        if (!rule) return;
        const ok = await copyTextToClipboard(rule);
        showToast(ok ? 'Rule copied to clipboard.' : 'Copy failed.');
      });
      document.getElementById('ruleBuilderReset')?.addEventListener('click', () => resetRuleBuilderForm());
      document.querySelectorAll('.rules-tpl-btn').forEach((btn) => {
        btn.addEventListener('click', () => applyRuleBuilderTemplate(btn.dataset.tpl));
      });

      // Config Files tab
      document.getElementById('rulesConfigReload')?.addEventListener('click', () => loadRulesConfigFileList());
      document.getElementById('rulesConfigSave')?.addEventListener('click', () => saveRulesConfigFile());
      document.getElementById('rulesConfigRevert')?.addEventListener('click', () => revertRulesConfigFile());

      // Suppressions tab
      document.getElementById('rulesSuppRefresh')?.addEventListener('click', () => loadRulesSuppressions());
      document.getElementById('rulesSuppAdd')?.addEventListener('click', () => addRulesSuppression());
      document.getElementById('rulesSuppFilter')?.addEventListener('input', () => loadRulesSuppressions());

      // Versions tab
      document.getElementById('rulesVersionsRefresh')?.addEventListener('click', () => loadRulesVersions());
      document.getElementById('rulesVersionRollback')?.addEventListener('click', async () => {
        const sel = document.getElementById('rulesVersionSelect');
        const id = String(sel?.value || '').trim();
        if (!id) { showToast('Select a version first.'); return; }
        if (!(await uiConfirm(`Rollback rules to version ${id}?`))) return;
        const idsSel = document.getElementById('idsRulesVersionSelect');
        if (idsSel) idsSel.value = id;
        await rollbackIdsRules();
        syncRulesEditorFromHidden();
        setRulesEditorStatus('Rolled back ✓', false);
        showToast(`Rules rolled back to ${id}`);
        loadRulesVersions();
      });
      document.getElementById('rulesVersionPreview')?.addEventListener('click', async () => {
        const sel = document.getElementById('rulesVersionSelect');
        const id = String(sel?.value || '').trim();
        if (!id) { showToast('Select a version to preview.'); return; }
        showToast('Preview loading…');
        // Fetch the version content via rollback dry-read
        try {
          const url = `${API.idsRulesVersions}`;
          // We'll load the version and show it in the editor temporarily
          const idsSel = document.getElementById('idsRulesVersionSelect');
          const prevVal = idsSel?.value || '';
          if (idsSel) idsSel.value = id;
          await rollbackIdsRules();
          syncRulesEditorFromHidden();
          setRulesWorkspaceTab('editor');
          setRulesEditorStatus(`Previewing version ${id} — save to keep, or load latest to revert.`, false);
        } catch {
          showToast('Failed to preview version.');
        }
      });

      // Auto-load rules on first visit
      loadIdsRules().then(() => {
        syncRulesEditorFromHidden();
        updateRulesKpi();
      });
      loadIdsRuleVersions().then(() => {
        syncSettingsRulesVersionSelect();
      });
    }

    async function loadIdsRules() {
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      setIdsRulesStatus(t('common.loading'));
      try {
        const payload = await apiFetchJson(API.idsRules, { timeoutMs: 6000, headers: { 'Accept': 'application/json' } });
        editor.value = String(payload?.rules || '');
        syncIdsRulesUiFromEditor();
        const ts = payload?.updated_at_unix ? formatTime(payload.updated_at_unix) : '';
        setIdsRulesStatus(ts ? `Loaded ${ts}` : 'Loaded');
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          setIdsRulesStatus('Login required to load rules.', true);
        } else {
          setIdsRulesStatus('Failed to load rules.', true);
        }
      }
    }

    async function saveIdsRules() {
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      setIdsRulesStatus(t('common.loading'));
      try {
        const payload = await apiPostJson(API.idsRules, { rules: String(editor.value || '') }, { timeoutMs: 8000 });
        const ts = payload?.updated_at_unix ? formatTime(payload.updated_at_unix) : '';
        setIdsRulesStatus(ts ? `Saved ${ts}` : 'Saved');
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          setIdsRulesStatus('Login required to save rules.', true);
        } else {
          setIdsRulesStatus('Failed to save rules.', true);
        }
      }
    }

    function initIdsRulesPanel() {
      const editor = document.getElementById('idsRulesEditor');
      if (!editor) return;
      document.getElementById('idsRulesLoad')?.addEventListener('click', () => loadIdsRules());
      document.getElementById('idsRulesSave')?.addEventListener('click', () => saveIdsRules());
      document.getElementById('idsRulesRollback')?.addEventListener('click', () => rollbackIdsRules());
      initIdsRulesAdvancedUi();
      initSettingsRulesControls();
      if (editor.value.trim() === '') {
        loadIdsRules();
      }
      loadIdsRuleVersions();
      loadIdsSuppressions();
    }

    async function loadIdsRuleVersions() {
      const sel = document.getElementById('idsRulesVersionSelect');
      const status = document.getElementById('idsRulesVersionsStatus');
      if (!sel) return;
      try {
        const list = await apiFetchJson(API.idsRulesVersions, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        sel.innerHTML = '';
        const opt0 = document.createElement('option');
        opt0.value = '';
        opt0.textContent = 'Select version…';
        sel.appendChild(opt0);
        for (const v of (Array.isArray(list) ? list : [])) {
          const opt = document.createElement('option');
          opt.value = v.id;
          opt.textContent = v.id;
          sel.appendChild(opt);
        }
        syncSettingsRulesVersionSelect();
        if (status) status.textContent = '';
      } catch (e) {
        if (status) status.textContent = 'Failed to load versions.';
      }
    }

    async function rollbackIdsRules() {
      const sel = document.getElementById('idsRulesVersionSelect');
      const status = document.getElementById('idsRulesVersionsStatus');
      const id = String(sel?.value || '').trim();
      if (!id) return;
      try {
        await apiPostJson(API.idsRulesRollback, { id }, { timeoutMs: 8000 });
        if (status) status.textContent = `Rolled back to ${id}`;
        loadIdsRules();
        loadIdsRuleVersions();
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          if (status) status.textContent = 'Login required to rollback.';
        } else if (status) {
          status.textContent = 'Rollback failed.';
        }
      }
    }

    async function loadIdsSuppressions() {
      const host = document.getElementById('idsSuppressionsList');
      if (!host) return;
      host.textContent = t('common.loading');
      try {
        const list = await apiFetchJson(API.idsSuppressions, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        const rows = Array.isArray(list) ? list : [];
        if (!rows.length) {
          host.textContent = t('common.none');
          return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'tableWrap';
        const table = document.createElement('table');
        table.innerHTML = `<thead><tr>
          <th width="220">Key</th>
          <th width="160">Until</th>
          <th>Reason</th>
          <th width="120">Action</th>
        </tr></thead>`;
        const tbody = document.createElement('tbody');
        for (const r of rows.slice(0, 200)) {
          const tr = document.createElement('tr');
          const until = r.until_unix ? formatTime(r.until_unix) : '';
          tr.innerHTML = `
            <td class="mono">${escapeHtml(r.key || '')}</td>
            <td>${escapeHtml(until)}</td>
            <td>${escapeHtml(r.reason || '')}</td>
            <td><button class="btn sm">Remove</button></td>
          `;
          tr.querySelector('button')?.addEventListener('click', async () => {
            try {
              await apiPostJson(API.idsSuppressionsRemove, { key: r.key }, { timeoutMs: 4000 });
              loadIdsSuppressions();
            } catch {}
          });
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        host.innerHTML = '';
        host.appendChild(wrap);
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          host.textContent = 'Login required.';
        } else {
          host.textContent = 'Failed to load suppressions.';
        }
      }
    }

    async function suppressSignatureForEvent(ev) {
      const meta = ev?.metadata || {};
      const sid = String(meta?.['ids.sid'] || meta?.['suricata.sid'] || meta?.sid || '').trim();
      const sig = String(meta?.['ids.signature'] || meta?.['suricata.signature'] || meta?.signature || '').trim();
      const key = sid ? `sid:${sid}` : (sig ? `sig:${sig.toLowerCase()}` : '');
      if (!key) return;
      try {
        await apiPostJson(API.idsSuppressions, { key, seconds: 24 * 3600, reason: 'dashboard suppression' }, { timeoutMs: 4000 });
        showToast('Suppression added (24h).');
        loadIdsSuppressions();
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          showToast('Login required to suppress.');
        } else {
          showToast('Failed to add suppression.');
        }
      }
    }

    // ── Sigma Rule Import ──────────────────────────────────────────────────────

    const SIGMA_SAMPLE = `title: Suspicious PowerShell Encoded Command
id: d7c49196-1e4e-4a65-8a4a-c3ac76a8d098
status: experimental
description: Detects suspicious use of PowerShell with encoded command argument
author: Percepta
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
falsepositives:
    - Administrative scripts
level: high
`;

    function initSigmaImport() {
      const dropZone = document.getElementById('sigmaDropZone');
      const fileInput = document.getElementById('sigmaFileInput');
      const yamlInput = document.getElementById('sigmaYamlInput');
      const importBtn = document.getElementById('sigmaImportBtn');
      const clearBtn = document.getElementById('sigmaClearBtn');
      const sampleBtn = document.getElementById('sigmaSampleBtn');
      if (!dropZone) return;

      dropZone.addEventListener('click', () => fileInput && fileInput.click());
      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--accent, #48bb78)';
        dropZone.style.background = 'rgba(72,187,120,0.08)';
      });
      dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = '';
        dropZone.style.background = '';
      });
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '';
        dropZone.style.background = '';
        const files = Array.from(e.dataTransfer?.files || [])
          .filter((f) => f.name.endsWith('.yml') || f.name.endsWith('.yaml') || f.name.endsWith('.txt'));
        if (files.length) readSigmaFile(files[0]);
      });

      fileInput?.addEventListener('change', (e) => {
        const f = e.target.files?.[0];
        if (f) readSigmaFile(f);
        e.target.value = '';
      });

      clearBtn?.addEventListener('click', () => {
        if (yamlInput) yamlInput.value = '';
        setSigmaStatus('');
        setSigmaPreview('');
      });

      sampleBtn?.addEventListener('click', () => {
        if (yamlInput) yamlInput.value = SIGMA_SAMPLE;
        setSigmaStatus('Sample loaded — click Import to convert and add to editor.', 'info');
        renderSigmaPreview(SIGMA_SAMPLE);
      });

      yamlInput?.addEventListener('input', () => {
        const v = yamlInput.value.trim();
        if (v.length > 20) renderSigmaPreview(v);
      });

      importBtn?.addEventListener('click', () => doSigmaImport());
    }

    function setSigmaStatus(msg, type) {
      const el = document.getElementById('sigmaImportStatus');
      if (!el) return;
      el.textContent = msg;
      el.style.color = type === 'error' ? 'var(--red,#fc8181)' : type === 'success' ? 'var(--green,#68d391)' : 'var(--text-muted,#a0aec0)';
    }

    function setSigmaPreview(html) {
      const el = document.getElementById('sigmaImportPreview');
      if (el) el.innerHTML = html;
    }

    function readSigmaFile(file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result || '';
        const area = document.getElementById('sigmaYamlInput');
        if (area) area.value = text;
        setSigmaStatus(`Loaded: ${escapeHtml(file.name)}`, 'info');
        renderSigmaPreview(text);
      };
      reader.readAsText(file);
    }

    /**
     * Minimal flat-YAML parser sufficient for Sigma rules.
     * Handles: string scalars, quoted scalars, inline lists [...], block lists (- item).
     */
    function parseSigmaYaml(text) {
      const result = {};
      const lines = text.split('\n');
      let i = 0;

      function parseValue(raw) {
        raw = raw.trim();
        if (!raw) return null;
        if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
          return raw.slice(1, -1);
        }
        if (raw.startsWith('[') && raw.endsWith(']')) {
          return raw.slice(1, -1).split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, ''));
        }
        return raw;
      }

      function countIndent(line) {
        let n = 0;
        while (n < line.length && line[n] === ' ') n++;
        return n;
      }

      function parseBlock(baseIndent) {
        const obj = {};
        while (i < lines.length) {
          const line = lines[i];
          if (line.trim() === '' || line.trim().startsWith('#')) { i++; continue; }
          const indent = countIndent(line);
          if (indent < baseIndent) break;
          const trimmed = line.trim();

          if (trimmed.startsWith('- ')) {
            // list item at this level — return array
            const arr = [];
            while (i < lines.length) {
              const l = lines[i];
              if (l.trim() === '' || l.trim().startsWith('#')) { i++; continue; }
              const ind = countIndent(l);
              if (ind < baseIndent) break;
              if (l.trim().startsWith('- ')) {
                arr.push(parseValue(l.trim().slice(2)));
                i++;
              } else break;
            }
            return arr;
          }

          const colonIdx = trimmed.indexOf(':');
          if (colonIdx <= 0) { i++; continue; }
          const key = trimmed.slice(0, colonIdx).trim();
          const rest = trimmed.slice(colonIdx + 1).trim();

          i++;
          if (rest !== '') {
            obj[key] = parseValue(rest);
          } else {
            // Look ahead
            if (i < lines.length) {
              const next = lines[i];
              const nextIndent = countIndent(next);
              if (next.trim().startsWith('- ')) {
                obj[key] = parseBlock(nextIndent);
              } else if (nextIndent > indent) {
                obj[key] = parseBlock(nextIndent);
              } else {
                obj[key] = null;
              }
            }
          }
        }
        return obj;
      }

      return parseBlock(0);
    }

    /**
     * Convert parsed Sigma rule object to Percepta YAML rule string.
     */
    function convertSigmaToPercept(sigmaText) {
      const sigma = parseSigmaYaml(sigmaText);

      const title = String(sigma.title || 'Imported Sigma Rule').trim();
      const id = String(sigma.id || crypto.randomUUID?.() || Date.now().toString(36)).trim();
      const description = String(sigma.description || '').replace(/\n/g, ' ').trim();
      const level = String(sigma.level || 'medium').toLowerCase();
      const severityMap = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info', info: 'Info' };
      const severity = severityMap[level] || 'Medium';

      // Extract MITRE tags
      const tags = Array.isArray(sigma.tags) ? sigma.tags : [];
      const mitreAttack = tags.filter((t) => typeof t === 'string' && t.startsWith('attack.t')).map((t) => t.replace('attack.', '').toUpperCase());
      const mitreTactics = tags.filter((t) => typeof t === 'string' && t.startsWith('attack.') && !t.match(/\.t\d/)).map((t) => t.replace('attack.', ''));

      // Derive category from logsource
      const ls = sigma.logsource || {};
      const lsCat = String(ls.category || '').toLowerCase();
      const lsProd = String(ls.product || '').toLowerCase();
      let category = 'process';
      if (lsCat.includes('network') || lsCat.includes('dns') || lsCat.includes('firewall')) category = 'network';
      else if (lsCat.includes('web') || lsCat.includes('proxy')) category = 'web';
      else if (lsCat.includes('auth') || lsCat.includes('logon')) category = 'auth';
      else if (lsCat.includes('file')) category = 'file';
      else if (lsCat.includes('registry')) category = 'registry';
      else if (lsCat.includes('process')) category = 'process';

      // Build condition lines from detection.selection
      const detection = sigma.detection || {};
      const conditions = [];
      const selectionObj = detection.selection || {};
      if (typeof selectionObj === 'object' && !Array.isArray(selectionObj)) {
        for (const [rawField, rawVal] of Object.entries(selectionObj)) {
          const fieldParts = rawField.split('|');
          const field = fieldParts[0];
          const mod = fieldParts[1] || '';
          const vals = Array.isArray(rawVal) ? rawVal : [rawVal];
          for (const v of vals) {
            if (v == null) continue;
            const vStr = String(v);
            let condLine = '';
            if (mod === 'endswith') condLine = `event.${field.toLowerCase()} endswith ${JSON.stringify(vStr)}`;
            else if (mod === 'startswith') condLine = `event.${field.toLowerCase()} startswith ${JSON.stringify(vStr)}`;
            else if (mod === 'contains') condLine = `event.${field.toLowerCase()} contains ${JSON.stringify(vStr)}`;
            else if (mod === 're') condLine = `event.${field.toLowerCase()} matches ${JSON.stringify(vStr)}`;
            else condLine = `event.${field.toLowerCase()} == ${JSON.stringify(vStr)}`;
            conditions.push(`  - ${condLine}`);
          }
        }
      }

      const falsepositives = Array.isArray(sigma.falsepositives) ? sigma.falsepositives.map((fp) => `  - "${fp}"`).join('\n') : '';
      const author = String(sigma.author || 'sigma-import').trim();
      const refDate = String(sigma.date || new Date().toISOString().slice(0, 10)).trim();

      let yaml = `- id: "${id}"\n`;
      yaml += `  name: "${title.replace(/"/g, "'")}"\n`;
      yaml += `  severity: ${severity}\n`;
      yaml += `  category: ${category}\n`;
      yaml += `  enabled: true\n`;
      if (description) yaml += `  description: "${description.replace(/"/g, "'")}"\n`;
      if (author) yaml += `  author: "${author}"\n`;
      yaml += `  # Imported from Sigma rule — date: ${refDate}\n`;
      if (mitreAttack.length) yaml += `  mitre_attack: [${mitreAttack.join(', ')}]\n`;
      if (mitreTactics.length) yaml += `  mitre_tactics: [${mitreTactics.join(', ')}]\n`;
      if (conditions.length) {
        yaml += `  conditions:\n`;
        yaml += conditions.join('\n') + '\n';
      } else {
        yaml += `  conditions: []\n`;
      }
      if (falsepositives) {
        yaml += `  false_positives:\n${falsepositives}\n`;
      }

      return yaml;
    }

    function renderSigmaPreview(sigmaText) {
      try {
        const converted = convertSigmaToPercept(sigmaText);
        setSigmaPreview(`<pre style="background:var(--bg-card,#1a202c);padding:12px;border-radius:6px;font-size:0.78em;overflow:auto;max-height:260px;color:var(--text,#e2e8f0);white-space:pre-wrap">${escapeHtml(converted)}</pre>`);
      } catch (e) {
        setSigmaPreview(`<span style="color:var(--red,#fc8181)">Preview error: ${escapeHtml(String(e))}</span>`);
      }
    }

    async function doSigmaImport() {
      const area = document.getElementById('sigmaYamlInput');
      const text = area?.value?.trim() || '';
      if (!text) { showToast('Paste or drop a Sigma rule first.', 'warn'); return; }

      let converted;
      try {
        converted = convertSigmaToPercept(text);
      } catch (e) {
        setSigmaStatus(`Parse error: ${String(e)}`, 'error');
        return;
      }

      // Append to rules editor (hidden textarea) and rules editor area
      const hiddenEditor = document.getElementById('idsRulesEditor');
      const visibleEditor = document.getElementById('rulesEditorArea');

      const appendTo = (el) => {
        if (!el) return;
        const cur = String(el.value || '').trimEnd();
        el.value = cur ? `${cur}\n\n${converted}` : converted;
      };
      appendTo(hiddenEditor);
      appendTo(visibleEditor);

      syncHiddenFromRulesEditor();
      updateRulesEditorLineNumbers?.();
      updateRulesKpi?.();

      setSigmaStatus('Rule imported to editor. Switch to Editor tab and press Save to publish.', 'success');
      renderSigmaPreview(text);
      setRulesWorkspaceTab('editor');
      showToast('Sigma rule converted and added to editor.');
    }

    // ── End Sigma Rule Import ──────────────────────────────────────────────────

    async function apiRequestJson(url, { method = 'GET', bodyObj = null, timeoutMs = 4000, headers = {} } = {}) {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const init = {
          method,
          signal: ctrl.signal,
          credentials: 'same-origin',
          headers: { ...headers },
        };
        if (bodyObj !== null) {
          init.headers = { 'Content-Type': 'application/json', ...init.headers };
          init.body = JSON.stringify(bodyObj ?? {});
        }

        const res = await fetch(url, init);
        const ct = res.headers.get('content-type') || '';
        if (!res.ok) {
          const body = await res.text().catch(() => '');
          const err = new Error(`HTTP ${res.status}`);
          err.status = res.status;
          err.body = body;
          throw err;
        }
        if (!ct.includes('application/json')) {
          const body = await res.text().catch(() => '');
          const err = new Error('Unexpected response');
          err.status = res.status;
          err.body = body;
          throw err;
        }
        return await res.json();
      } finally {
        clearTimeout(to);
      }
    }

    // ── FIM Configuration ──────────────────────────────────────────────
    async function loadFimConfig() {
      try {
        const res = await fetch('/api/settings/fim', {
          headers: { 'Authorization': 'Bearer ' + (state.auth?.token || '') },
        });
        if (!res.ok) return;
        const cfg = await res.json();
        const el = document.getElementById('fimPathsInput');
        if (el) el.value = (cfg.paths || []).join('\n');
        const rec = document.getElementById('fimRecursiveCheck');
        if (rec) rec.checked = cfg.recursive !== false;
        const deb = document.getElementById('fimDebounceInput');
        if (deb) deb.value = cfg.debounce_ms || 250;
      } catch (e) {
        console.warn('Failed to load FIM config:', e);
      }
    }

    async function saveFimConfig() {
      const el = document.getElementById('fimPathsInput');
      const rec = document.getElementById('fimRecursiveCheck');
      const deb = document.getElementById('fimDebounceInput');
      const status = document.getElementById('fimSaveStatus');
      if (!el) return;
      const paths = el.value.split('\n').map(s => s.trim()).filter(Boolean);
      const body = {
        paths,
        recursive: rec ? rec.checked : true,
        debounce_ms: deb ? parseInt(deb.value, 10) || 250 : 250,
      };
      try {
        const res = await fetch('/api/settings/fim', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + (state.auth?.token || ''),
          },
          body: JSON.stringify(body),
        });
        if (res.ok) {
          if (status) { status.textContent = '✓ Saved'; status.style.color = 'var(--ok, #4caf50)'; }
        } else {
          if (status) { status.textContent = '✗ Failed'; status.style.color = 'var(--danger, #ff6b6b)'; }
        }
        setTimeout(() => { if (status) status.textContent = ''; }, 3000);
      } catch (e) {
        if (status) { status.textContent = '✗ Error'; status.style.color = 'var(--danger, #ff6b6b)'; }
        console.error('Failed to save FIM config:', e);
      }
    }

