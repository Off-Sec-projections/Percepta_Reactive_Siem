    const API = {
      stats: '/api/stats',
      dashboardSummary: '/api/dashboard/summary',
      alerts: '/api/alerts',
      alertsManual: '/api/alerts/manual',
      search: '/api/search',
      relatedSignals: '/api/related_signals',
      idsRules: '/api/ids/suricata/rules',
      idsRulesVersions: '/api/ids/suricata/rules/versions',
      idsRulesRollback: '/api/ids/suricata/rules/rollback',
      idsSuppressions: '/api/ids/suppressions',
      idsSuppressionsRemove: '/api/ids/suppressions/remove',
      configFiles: '/api/config/files',
      configFile: '/api/config/file',
      healthz: '/healthz',
      escalations: '/api/escalations',
      stream: '/api/stream',
      streamV2: '/api/stream/v2',
      whoami: '/api/whoami',
      renewList: '/api/renew/requests',
      renewApprove: '/api/renew/approve',
      renewReject: '/api/renew/reject',
      geoipBatch: '/api/geoip/batch',
      lanTopology: '/api/lan/topology',
      settingsRuntime: '/api/settings/runtime',
      settingsUiSnapshot: '/api/settings/ui_snapshot',
      deviceLookup: '/api/device/lookup',
      deviceSet: '/api/device/set',
      deviceClear: '/api/device/clear',
      agentOrdinals: '/api/agent_ordinals',
      agentOrdinalsClear: '/api/agent_ordinals/clear',
      dbTables: '/api/db/tables',
      dbSchema: '/api/db/schema',
      dbQuery: '/api/db/query',
      dbExecute: '/api/db/execute',
      dbTruncate: '/api/db/truncate',
      honeypotStats: '/api/honeypot/stats',
      honeypotConfig: '/api/honeypot/config',
      honeypotBlock: '/api/honeypot/block',
    };

    const LIMITS = { maxAlerts: 500, maxEvents: 200 };

    const PERF_MODE_KEY = 'percepta.ui.perfMode.v1';
    const DENSITY_MODE_KEY = 'percepta.ui.densityMode.v1';
    const SCOPE_FILTERS_KEY = 'percepta.ui.scopeFilters.v1';
    const SUBTABS_KEY = 'percepta.ui.subTabs.v1';
    const NOC_MODE_KEY = 'percepta.ui.nocWall.v1';
    const BRAND_STYLE_KEY = 'percepta.ui.brandStyle.v1';
    const BRAND_OFFSET_X_KEY = 'percepta.ui.brandOffsetX.v1';
    const BRAND_OFFSET_Y_KEY = 'percepta.ui.brandOffsetY.v1';
    const BRAND_SIZE_MULT_KEY = 'percepta.ui.brandSizeMult.v1';
    const SIDEBAR_HIDDEN_KEY = 'percepta.ui.sidebarHidden.v1';
    const SETTINGS_SUBTAB_KEY = 'percepta.ui.settingsSubtab.v1';
    const SETTINGS_AGENTS_CAT_KEY = 'percepta.ui.settingsAgentsCat.v1';
    const SETTINGS_CONTROL_DOMAIN_KEY = 'percepta.ui.settingsDomain.v1';
    const SETTINGS_CONTROL_SCOPE_KEY = 'percepta.ui.settingsScope.v1';
    const SETTINGS_CONTROL_MODEL_KEY = 'percepta.ui.settingsControlModel.v1';
    const UI_SNAPSHOT_UPDATED_KEY = 'percepta.ui.snapshot.updatedAt.v1';

    function getDefaultSettingsControlModel() {
      let savedPerf = 'auto';
      let savedDensity = 'auto';
      let savedNoc = false;
      let savedSidebarHidden = false;
      try {
        const p = String(localStorage.getItem(PERF_MODE_KEY) || 'auto').trim().toLowerCase();
        savedPerf = (p === 'on' || p === 'off' || p === 'auto') ? p : 'auto';
      } catch {}
      try {
        const d = String(localStorage.getItem(DENSITY_MODE_KEY) || 'auto').trim().toLowerCase();
        savedDensity = (d === 'auto' || d === 'normal' || d === 'compact' || d === 'ultra') ? d : 'auto';
      } catch {}
      try { savedNoc = String(localStorage.getItem(NOC_MODE_KEY) || '0') === '1'; } catch {}
      try { savedSidebarHidden = String(localStorage.getItem(SIDEBAR_HIDDEN_KEY) || '0') === '1'; } catch {}

      return {
        'ui.defaultView': 'overview',
        'ui.defaultSettingsTab': 'general',
        'ui.language': detectUiLang(),
        'ui.perfMode': savedPerf,
        'ui.densityMode': savedDensity,
        'ui.nocWall': savedNoc,
        'ui.sidebarHidden': savedSidebarHidden,

        'ingest.maxEvents': 200,
        'ingest.maxAlerts': 500,
        'ingest.eventsPageSize': 100,
        'ingest.alertsPageSize': 100,
        'ingest.telemetryHzOverview': 2,
        'ingest.telemetryHzOther': 1,
        'ingest.virtualRowHeightEvents': 34,
        'ingest.virtualRowHeightAlerts': 34,

        'detection.autoOpenRulesWorkspace': false,
        'detection.autoLoadRulesOnOpen': true,
        'detection.defaultSuppressionHours': 24,
        'detection.defaultRuleAction': 'alert',

        'response.defaultBlockMinutes': 15,
        'response.analystMaxBlockMinutes': 15,
        'response.windowsScriptBlockMinutes': 15,
        'response.requireConfirmDestructive': true,
        'response.defaultDispatchTimeoutSec': 180,

        'detection.playbookRunsDefaultLimit': 100,

        'storage.persistScopeFilters': true,
        'storage.persistEventNotes': true,
        'storage.maxDeviceNameCache': 5000,

        'access.defaultRoleLanding': 'analyst',
        'access.requireAdminForRenewals': true,

        'integrations.geoipLookupEnabled': true,
        'integrations.relatedSignalsEnabled': true,
        'integrations.intelLookupEnabled': true,

        'dr.enabledOverride': true,
        'dr.verifyIntervalSecs': 3600,
        'dr.restoreDrillEnabled': false,
        'dr.restoreDrillIntervalSecs': 86400,
      };
    }

    function normalizeSettingsControlDomain(v) {
      const x = String(v || '').trim().toLowerCase();
      return ['global', 'ingestion', 'detection', 'response', 'storage', 'access', 'integrations'].includes(x) ? x : 'global';
    }

    function normalizeSettingsControlScope(v) {
      const x = String(v || '').trim().toLowerCase();
      return ['global', 'domain', 'specific'].includes(x) ? x : 'global';
    }

    function mergeSettingsControlModel(raw) {
      const fallback = getDefaultSettingsControlModel();
      if (!raw || typeof raw !== 'object') return { ...fallback };
      return { ...fallback, ...raw };
    }

    const VIRTUAL_TABLES = {
      tblEvents: { rowHeight: 34, overscan: 10, view: 'events' },
      tblAlerts: { rowHeight: 34, overscan: 12, view: 'alerts' },
      tblHoneypot: { rowHeight: 34, overscan: 10, view: 'honeypot' },
      tblIds: { rowHeight: 34, overscan: 10, view: 'ids' },
    };


    const DEDUPE = {
      // Keep more keys than rendered rows to dedupe across refreshes/reconnects.
      maxEventKeys: 50_000,
      maxAlertKeys: 10_000,
    };

    const state = {
      view: 'overview',
      ws: null,
      wsOk: false,
      uiLoadingCleared: false,
      stats: { agents_total: 0, agents_connected: 0, events_total: 0, alerts_total: 0 },
      dashboardSummary: { health: 'unknown', alerts_critical: 0, alerts_high: 0, events_received: 0, agents_status: {} },
      ingestTotalReceived: 0,
      agentIds: [],
      alerts: [],
      events: [],
      honeypot: [],
      ids: [],

      // Stream v2 resume cursor (best-effort). Persisted so reconnects can replay missed alerts.
      alertSeq: (() => {
        try { return Number(localStorage.getItem('percepta_alert_seq') || 0) || 0; } catch { return 0; }
      })(),

      telemetry: { timestamp: 0, agents: [], events_per_sec: 0, alerts_per_sec: 0 },

      // Fast dedupe indexes (key -> lastSeenMs). Map preserves insertion order for eviction.
      eventIndex: new Map(),
      alertIndex: new Map(),

      // Client-side "clear" watermark: ignore events ingested before this time.
      // This prevents cleared events from reappearing via polling/refresh without deleting server database rows.
      minIngestMs: 0,
      selected: { type: 'event', key: null },
      selectedAlertKey: null,
      selectedAlertKeys: new Set(),
      searchText: '',

      deviceLookup: '/api/device/lookup',
      deviceSet: '/api/device/set',
      deviceClear: '/api/device/clear',
      agentNameById: new Map(),
      agentMacById: new Map(),
      agentUserById: new Map(),
      agentKeyById: new Map(),
      agentOrdinal: { next: 1, byKey: new Map() },
      lastHealthStatus: 'pending',  // 'pending' | 'ok' | 'degraded' | 'offline'
      pollTimer: null,
      rafScheduled: false,
      perfMode: (() => {
        try {
          const v = String(localStorage.getItem(PERF_MODE_KEY) || 'auto').trim().toLowerCase();
          return (v === 'on' || v === 'off' || v === 'auto') ? v : 'auto';
        } catch {
          return 'auto';
        }
      })(),
      densityMode: (() => {
        try {
          const v = String(localStorage.getItem(DENSITY_MODE_KEY) || 'auto').trim().toLowerCase();
          return (v === 'auto' || v === 'normal' || v === 'compact' || v === 'ultra') ? v : 'auto';
        } catch {
          return 'auto';
        }
      })(),
      subTabs: (() => {
        const fallback = { overview: 'executive', alerts: 'queue', events: 'timeline', honeypot: 'all', ids: 'detections' };
        try {
          const v = storageGetJson(SUBTABS_KEY, fallback);
          if (!v || typeof v !== 'object') return fallback;
          return {
            overview: String(v.overview || fallback.overview),
            alerts: String(v.alerts || fallback.alerts),
            events: String(v.events || fallback.events),
            honeypot: String(v.honeypot || fallback.honeypot),
            ids: String(v.ids || fallback.ids),
          };
        } catch {
          return fallback;
        }
      })(),
      scopeFilters: (() => {
        try {
          const v = storageGetJson(SCOPE_FILTERS_KEY, {});
          return (v && typeof v === 'object') ? v : {};
        } catch {
          return {};
        }
      })(),
      nocMode: (() => {
        try { return String(localStorage.getItem(NOC_MODE_KEY) || '0') === '1'; } catch { return false; }
      })(),
      brandStyle: (() => {
        try {
          const v = String(localStorage.getItem(BRAND_STYLE_KEY) || 'classic').trim().toLowerCase();
          return ['classic', 'minimal', 'neon'].includes(v) ? v : 'classic';
        } catch {
          return 'classic';
        }
      })(),
      brandOffsetX: (() => {
        try { return Math.max(-120, Math.min(120, Number(localStorage.getItem(BRAND_OFFSET_X_KEY) || 0) || 0)); } catch { return 0; }
      })(),
      brandOffsetY: (() => {
        try { return Math.max(-80, Math.min(80, Number(localStorage.getItem(BRAND_OFFSET_Y_KEY) || 0) || 0)); } catch { return 0; }
      })(),
      brandSizeMult: (() => {
        try {
          const v = Number(localStorage.getItem(BRAND_SIZE_MULT_KEY) || 1) || 1;
          return Math.max(0.8, Math.min(1.35, v));
        } catch {
          return 1;
        }
      })(),
      sidebarHidden: (() => {
        try { return String(localStorage.getItem(SIDEBAR_HIDDEN_KEY) || '0') === '1'; } catch { return false; }
      })(),
      settingsSubTab: (() => {
        try {
          const v = String(localStorage.getItem(SETTINGS_SUBTAB_KEY) || 'general').trim().toLowerCase();
          return ['general', 'control', 'agents', 'rules', 'advanced'].includes(v) ? v : 'general';
        } catch {
          return 'general';
        }
      })(),
      settingsAgentsCategory: (() => {
        try {
          const v = String(localStorage.getItem(SETTINGS_AGENTS_CAT_KEY) || 'all').trim().toLowerCase();
          return ['all', 'connected', 'stale', 'offline'].includes(v) ? v : 'all';
        } catch {
          return 'all';
        }
      })(),
      settingsControlDomain: (() => {
        try { return normalizeSettingsControlDomain(localStorage.getItem(SETTINGS_CONTROL_DOMAIN_KEY) || 'global'); } catch { return 'global'; }
      })(),
      settingsControlScope: (() => {
        try { return normalizeSettingsControlScope(localStorage.getItem(SETTINGS_CONTROL_SCOPE_KEY) || 'global'); } catch { return 'global'; }
      })(),
      settingsControlModel: (() => {
        try {
          return mergeSettingsControlModel(storageGetJson(SETTINGS_CONTROL_MODEL_KEY, getDefaultSettingsControlModel()));
        } catch {
          return getDefaultSettingsControlModel();
        }
      })(),
      idsRulesUi: {
        tab: 'editor',
        selectedLineNo: -1,
        filter: '',
        sourceLines: [],
        parsedRules: [],
      },
      rulesWorkspace: {
        tab: 'editor',
        configFiles: [],
        activeConfigFile: null,
        configOriginal: '',
        versions: [],
      },
      nocTimer: null,
      dirty: { counters: false, agents: false, tables: false, details: false, health: false, ws: false, escalations: false, auth: false },
      lastCounterPaint: 0,
      lastOverviewPaint: 0,
      lastOverviewSnapshot: null,
      viewInit: { settings: false, ids: false, escalations: false, playbooks: false, response: false, audit: false },
      tableDomCache: new Map(), // tableId -> Map(rowKey -> { sig, tr })
      virtualScrollBound: false,

      apiOk: true,
      lastApiError: '',

      eventKnowledge: null,

      intel: { status: null, ipCache: new Map(), hashCache: new Map(), kevCache: new Map(), lastForKey: '' },

      geoip: { available: null, cache: new Map(), inflight: false, lastFetchMs: 0 },

      deviceNames: { cache: new Map(), inflight: new Set(), timer: null },

      relatedSignals: {
        // cacheKey -> { atMs, payload }
        cache: new Map(),
        // cacheKey -> Promise
        inflight: new Map(),
      },

      auth: { status: null },

      escalationsUi: {
        selectedId: null,
        linkedEventByEscId: new Map(),
      },

      sort: {
        events: { key: 'time', dir: 'desc' },
        alerts: { key: 'risk', dir: 'desc' },
      },

      pagination: {
        alerts: { page: 1, pageSize: 100, total: 0 },
        events: { page: 1, pageSize: 100, total: 0 },
      },

      rate: { lastIngestTotal: null, lastMs: 0, emaEps: 0 },
      mapMode: 'geoip', // 'geoip' | 'lan'
      mapAutoSwitched: false,

      lan: { snapshot: null, inflight: false, lastFetchMs: 0 },
      lanRates: new Map(), // agent_id -> { ema, lastMs }
      lanAnim: { running: false, rafId: 0, w: 0, h: 0, dpr: 1, particlesByAgent: new Map(), lastFrameMs: 0 },
    };

