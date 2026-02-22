    function buildWsUrl(path) {
      const proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
      return `${proto}//${location.host}${path}`;
    }

    function fnv1a32(text) {
      let hash = 0x811c9dc5;
      for (let i = 0; i < text.length; i++) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193);
      }
      return (hash >>> 0).toString(16).padStart(8, '0');
    }

    function alertKey(a) {
      if (!a || typeof a !== 'object') {
        return `fallback:${fnv1a32(JSON.stringify(a || {}).slice(0, 128))}`;
      }
      const id = a?.id || a?.hash;
      if (id && (typeof id === 'string' || typeof id === 'number')) {
        return `id:${String(id).slice(0, 256)}`;
      }
      const rule = String(a?.rule_id || '').trim().slice(0, 256);
      const last = String(a?.last_seen || a?.first_seen || '').trim().slice(0, 128);
      const agent = String(a?.agent_id || a?.agent_hostname || '').trim().slice(0, 256);
      const msg = String(a?.message || '').trim().slice(0, 512);
      const composite = `${rule}|${agent}|${last}|${msg}`;
      if (!composite.trim()) {
        const ts = String(a?.timestamp || a?.created_at || Date.now()).slice(0, 32);
        return `fallback:${fnv1a32(ts)}`;
      }
      return `h:${fnv1a32(composite)}`;
    }

    function eventKey(e) {
      // Prefer stable instance keys when available (especially Windows Event Log).
      // This prevents “same minute, same summary” rows from repeating on retries/replays.
      const agent = e?.agent?.id || e?.agent?.hostname || e?.agent_id || '';
      const rid = Number(
        e?.event?.record_id ||
        e?.metadata?.['winlog.record_id'] ||
        0
      ) || 0;
      const channel = String(
        e?.metadata?.['winlog.channel'] ||
        e?.event?.provider ||
        ''
      ).trim();
      if (agent && rid > 0) return `rid:${agent}|${channel}|${rid}`;

      const h = e?.hash || e?.event?.hash || e?.event_id;
      if (h) return `hash:${h}`;

      // Next best: stable fingerprint if present.
      const fp = e?.metadata?.['event.fingerprint'] || '';
      if (agent && fp) return `fp:${agent}|${fp}`;

      // Last resort: time bucket + summary.
      const ts = e?.event_time?.seconds ?? e?.ingest_time?.seconds ?? e?.timestamp ?? '';
      const sum = e?.event?.summary || e?.event?.original_message || e?.message || '';
      return `h:${fnv1a32(`${agent}|${ts}|${sum}`)}`;
    }

    function eventIngestMs(e) {
      // Prefer ingest_time so delayed / replayed events don't "time travel".
      const sec = tsToSec(e?.ingest_time || e?.event_time || e?.timestamp || '');
      return sec ? (sec * 1000) : 0;
    }

    function alertLastSeenMs(a) {
      const sec = tsToSec(a?.last_seen || a?.first_seen || '');
      return sec ? (sec * 1000) : 0;
    }

    function rememberKeyLRU(map, key, maxKeys) {
      if (!key) return;
      // Refresh key insertion order.
      if (map.has(key)) map.delete(key);
      map.set(key, Date.now());
      while (map.size > maxKeys) {
        const oldest = map.keys().next().value;
        if (!oldest) break;
        map.delete(oldest);
      }
    }

    function resetEventIndexesFromLists() {
      state.eventIndex.clear();
      state.alertIndex.clear();
      for (const a of state.alerts || []) rememberKeyLRU(state.alertIndex, alertKey(a), DEDUPE.maxAlertKeys);
      for (const e of state.events || []) rememberKeyLRU(state.eventIndex, eventKey(e), DEDUPE.maxEventKeys);
    }

    function acceptEventUnderWatermark(e) {
      if (!state.minIngestMs) return true;
      const ms = eventIngestMs(e);
      // If missing timestamps, don't drop (best-effort).
      if (!ms) return true;
      return ms >= state.minIngestMs;
    }

    function shortId(id) {
      const s = String(id ?? '');
      if (s.length <= 18) return s;
      return `${s.slice(0, 10)}…${s.slice(-6)}`;
    }

    function agentLabel(id) {
      const ord = agentOrdinalForAgentId(id);
      const deviceName = String(deviceNameForAgentId(id) || '').trim();
      const name = String(state.agentNameById.get(id) || '').trim();
      const user = String(state.agentUserById.get(id) || '').trim();
      const label = deviceName || name || user || 'unknown';
      if (ord > 0) return `Agent ${ord} (${label})`;
      return `Agent (${label})`;
    }

    function severityLabel(e) {
      const rank = (lab) => {
        switch (lab) {
          case 'critical': return 4;
          case 'high': return 3;
          case 'medium': return 2;
          case 'low': return 1;
          default: return 0;
        }
      };
      const fromRank = (n) => {
        if (n >= 4) return 'critical';
        if (n === 3) return 'high';
        if (n === 2) return 'medium';
        if (n === 1) return 'low';
        return 'info';
      };

      const tryNum = (v) => {
        if (typeof v === 'number' && Number.isFinite(v)) return v;
        if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
        return null;
      };

      // Severity floor based on outcome/signals so failures aren't shown as 'info'.
      const outcomeNum = tryNum(e?.event?.outcome ?? e?.outcome);
      const eventIdNum = tryNum(e?.event?.event_id ?? e?.event_id);
      const tags = Array.isArray(e?.tags) ? e.tags.map((x) => String(x || '').toLowerCase()) : [];
      const text = `${e?.event?.summary || ''} ${e?.event?.original_message || ''} ${e?.message || ''}`.toLowerCase();
      let floor = 0;
      if (outcomeNum === 2) floor = Math.max(floor, 2); // failure => medium
      if (outcomeNum === 3) floor = Math.max(floor, 3); // blocked => high
      if (eventIdNum === 4625) floor = Math.max(floor, 2); // Windows failed logon
      if (tags.includes('failed') || tags.includes('failure')) floor = Math.max(floor, 2);
      if (tags.includes('blocked')) floor = Math.max(floor, 3);
      if (text.includes('failed logon') || text.includes('failed login') || text.includes('logon failure')) floor = Math.max(floor, 2);

      // 1) Numeric severity
      // Percepta proto comment: 0=debug, 1=info, 2=warn, 3=error, 4=critical
      // Some sources may emit syslog-style severities (0..7); we only treat 5..7 as syslog
      // because 0..4 overlaps with Percepta and would otherwise invert meaning (0=debug vs 0=emerg).
      const sevNum = tryNum(e?.event?.severity ?? e?.severity);
      if (typeof sevNum === 'number') {
        // Syslog tail: 5=notice, 6=info, 7=debug
        if (sevNum === 5) return fromRank(Math.max(1, floor));
        if (sevNum === 6 || sevNum === 7) return fromRank(Math.max(0, floor));

        // Percepta scale.
        if (sevNum >= 4) return fromRank(Math.max(4, floor));
        if (sevNum === 3) return fromRank(Math.max(3, floor));
        if (sevNum === 2) return fromRank(Math.max(2, floor));
        // 1=info, 0=debug
        return fromRank(Math.max(0, floor));
      }

      // 2) Windows EventLog numeric level mapping:
      // 1=Critical, 2=Error, 3=Warning, 4=Information, 5=Verbose
      const lvlNum = tryNum(e?.event?.level ?? e?.level);
      if (typeof lvlNum === 'number') {
        if (lvlNum === 1) return fromRank(Math.max(4, floor));
        if (lvlNum === 2) return fromRank(Math.max(3, floor));
        if (lvlNum === 3) return fromRank(Math.max(2, floor));
        return fromRank(Math.max(0, floor));
      }

      // 3) Text severity/level
      const s = String(e?.severity ?? e?.event?.severity ?? e?.event?.level ?? e?.event?.level_text ?? '').toLowerCase();
      if (!s) return fromRank(Math.max(0, floor));
      if (s.includes('crit')) return fromRank(Math.max(4, floor));
      if (s.includes('emerg') || s.includes('alert') || s.includes('fatal')) return fromRank(Math.max(4, floor));
      if (s.includes('error') || s.includes('err') || s.includes('high')) return fromRank(Math.max(3, floor));
      if (s.includes('warn') || s.includes('warning') || s.includes('medium')) return fromRank(Math.max(2, floor));
      if (s.includes('low')) return fromRank(Math.max(1, floor));
      if (s.includes('info') || s.includes('information') || s.includes('verbose') || s.includes('debug') || s.includes('trace')) return fromRank(Math.max(0, floor));

      // Unknown text -> keep floor.
      return fromRank(Math.max(0, floor));
    }

    function eventFilterText(e) {
      const summary = e?.event?.summary || '';
      const orig = e?.event?.original_message || '';
      const msg = e?.message || '';
      const agent = e?.agent?.hostname || e?.agent?.id || e?.agent_id || '';
      const user = getBestUser(e) || '';
      const src = e?.network?.src_ip || '';
      const dst = e?.network?.dst_ip || '';
      const meta = e?.metadata ? JSON.stringify(e.metadata) : '';
      return `${summary} ${orig} ${msg} ${agent} ${user} ${src} ${dst} ${meta}`.toLowerCase();
    }

    function isHoneypotEvent(e) {
      const t = eventFilterText(e);
      return t.includes('honeypot') || t.includes('cowrie') || t.includes('kippo') || t.includes('dionaea') || t.includes('conpot') || t.includes('opencanary');
    }

    function isIdsEvent(e) {
      const sensorKind = String(
        e?.metadata?.['sensor.kind'] ||
        e?.metadata?.sensor_kind ||
        e?.event?.provider ||
        ''
      ).toLowerCase();
      if (sensorKind === 'ids' || sensorKind === 'ips') return true;

      const idsMetaHints = [
        e?.metadata?.['ids.signature'],
        e?.metadata?.['ids.sid'],
        e?.metadata?.['ids.action'],
        e?.metadata?.['suricata.signature'],
        e?.metadata?.['suricata.sid'],
      ];
      if (idsMetaHints.some((v) => String(v || '').trim().length > 0)) return true;

      const t = eventFilterText(e);
      return t.includes('ids') || t.includes('ips') || t.includes('suricata') || t.includes('snort') || t.includes('zeek') || t.includes('bro');
    }

    function isFimEvent(e) {
      const t = eventFilterText(e);
      // Pragmatic FIM indicators across common sources.
      return (
        t.includes('file integrity') ||
        t.includes('integrity') ||
        t.includes('fim') ||
        t.includes('tripwire') ||
        t.includes('aide') ||
        t.includes('syscheck') ||
        t.includes('inotify') ||
        t.includes('auditd') ||
        t.includes('file modified') ||
        t.includes('file created') ||
        t.includes('file deleted') ||
        t.includes('chmod ') ||
        t.includes('chown ')
      );
    }

    /** True if the event is an internal agent telemetry event (heartbeat, capability snapshot, etc.) */
    function isAgentInternalEvent(e) {
      const provider = String(e?.event?.provider || '').toLowerCase();
      if (provider === 'percepta-agent') {
        const action = String(e?.event?.action || '').toLowerCase();
        const summary = String(e?.event?.summary || '').toLowerCase();
        if (action === 'capabilities' || action === 'heartbeat'
          || summary.includes('agent capability') || summary.includes('agent heartbeat')
          || summary.includes('software inventory')) {
          return true;
        }
      }
      const tags = Array.isArray(e?.tags) ? e.tags : [];
      if (tags.includes('agent') && (tags.includes('capabilities') || tags.includes('heartbeat') || tags.includes('inventory'))) {
        return true;
      }
      return false;
    }

    function applyTheme(theme) {
      const t = (theme === 'light') ? 'light' : 'dark';
      const root = document.documentElement;
      const prev = root.getAttribute('data-theme');
      if (prev === t) return;
      root.setAttribute('data-theme', t);
      root.style.colorScheme = (t === 'light') ? 'light' : 'dark';
      try { document.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: t, previousTheme: prev } })); } catch {}
      try {
        localStorage.setItem('percepta_theme', t);
        localStorage.setItem('theme', t);
      } catch {}
      try {
        // Keep theme switch snappy: avoid forcing a full-table/details repaint.
        state.dirty.counters = true;
        state.dirty.health = true;
        state.dirty.ws = true;
        if (state.view === 'overview') {
          state.lastOverviewPaint = 0;
          try { if (typeof initEliteOverview === 'function') initEliteOverview(); } catch {}
          try { if (typeof paintOverviewDashThrottled === 'function') paintOverviewDashThrottled(); } catch {}
        } else {
          scheduleRender();
        }
      } catch {}
    }

    function initTheme() {
      let t = 'dark';
      try { t = localStorage.getItem('percepta_theme') || localStorage.getItem('theme') || t; } catch {}
      applyTheme(t);
    }

    function initOverviewModuleButtons() {
      const bind = (id, fn) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('click', fn);
      };

      bind('ovHpOpen', () => setView('honeypot'));
      bind('ovIdsOpen', () => setView('ids'));
      bind('ovFimOpen', () => pivotSearch('integrity fim file modified tripwire aide', 'events'));

      bind('ovHpPivot', () => {
        const best = document.querySelector('#ovHpBoards .boardRow span');
        const q = best?.textContent || '';
        if (q && q !== '–') pivotSearch(q, 'events');
      });

      bind('ovIdsPivot', () => {
        const best = document.querySelector('#ovIdsBoards .boardRow span');
        const q = best?.textContent || '';
        if (q && q !== '–') pivotSearch(q, 'events');
      });

      bind('ovFimPivot', () => {
        const best = document.querySelector('#ovFimBoards .boardRow span');
        const q = best?.textContent || '';
        if (q && q !== '–') pivotSearch(q, 'events');
      });

      // Draggable Drill-down for Overview Cards
      const cards = document.querySelectorAll('[draggable="true"][data-ov-id]');
      cards.forEach(card => {
        card.addEventListener('dragstart', (e) => {
          const id = card.dataset.ovId;
          e.dataTransfer.setData('percepta/ov-card', id);
          e.dataTransfer.effectAllowed = 'copyMove';
          card.style.opacity = '0.5';
          
          // Show a "Drop for Details" hint on the main map
          const hint = document.getElementById('ovMapHint');
          if (hint) {
            hint.textContent = 'Drop to Expand Tactical View';
            hint.style.display = 'flex';
          }
        });

        card.addEventListener('dragend', () => {
          card.style.opacity = '1';
          const hint = document.getElementById('ovMapHint');
          if (hint) hint.style.display = 'none';
        });
      });

      const mapWrap = document.querySelector('.threatMapWrap, .map-container');
      if (mapWrap) {
        mapWrap.addEventListener('dragover', (e) => {
          if (e.dataTransfer.types.includes('percepta/ov-card')) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
            mapWrap.classList.add('drag-target');
          }
        });
        mapWrap.addEventListener('dragleave', () => {
          mapWrap.classList.remove('drag-target');
        });
        mapWrap.addEventListener('drop', (e) => {
          const id = e.dataTransfer.getData('percepta/ov-card');
          if (id) {
            e.preventDefault();
            mapWrap.classList.remove('drag-target');
            showTacticalDrilldown(id);
          }
        });
      }
    }

    function showTacticalDrilldown(id) {
        const summary = state?.dashboardSummary || {};
        const topKey = (obj) => {
          if (!obj || typeof obj !== 'object') return '';
          const entries = Object.entries(obj)
            .map(([k, v]) => [String(k), Number(v || 0)])
            .filter(([, v]) => Number.isFinite(v))
            .sort((a, b) => b[1] - a[1]);
          return entries[0]?.[0] || '';
        };

        const topSource = topKey(summary.src_ip_counts);
        const topHost = topKey(summary.impacted_ips);

        const pivotByCard = {
          class: {
            view: 'events',
            query: 'ids OR honeypot OR fim OR auth OR process',
            toast: 'Tactical drilldown: classification pivot'
          },
          sources: {
            view: 'events',
            query: topSource || 'src_ip:',
            toast: topSource ? `Tactical drilldown: source ${topSource}` : 'Tactical drilldown: top sources'
          },
          hosts: {
            view: 'events',
            query: topHost || 'agent:',
            toast: topHost ? `Tactical drilldown: host ${topHost}` : 'Tactical drilldown: impacted hosts'
          },
          recent: {
            view: 'events',
            query: '',
            toast: 'Tactical drilldown: recent live stream'
          }
        };

        const pivot = pivotByCard[String(id || '')] || pivotByCard.recent;
        if (typeof pivotSearch === 'function') {
          pivotSearch(pivot.query, pivot.view);
        } else if (typeof setView === 'function') {
          setView(pivot.view);
          state.searchText = String(pivot.query || '');
          if (typeof scheduleRender === 'function') scheduleRender();
        }
        if (typeof showToast === 'function') showToast(pivot.toast);
    }

    function getOverviewLayout() {
      const fallback = { hidden: {}, heights: {} };
      const v = storageGetJson('percepta.overview.layout.v1', fallback);
      if (!v || typeof v !== 'object') return fallback;
      v.hidden = (v.hidden && typeof v.hidden === 'object') ? v.hidden : {};
      v.heights = (v.heights && typeof v.heights === 'object') ? v.heights : {};
      return v;
    }

    function setOverviewLayout(next) {
      storageSetJson('percepta.overview.layout.v1', next);
    }

    function overviewCardHeightBounds(id) {
      const key = String(id || '').trim().toLowerCase();
      const vh = Math.max(window.innerHeight || 0, document.documentElement?.clientHeight || 0);
      const compactViewport = vh > 0 && vh <= 930;
      if (key === 'class') return compactViewport ? { min: 132, max: 220 } : { min: 140, max: 270 };
      if (key === 'pipeline' || key === 'rate') return compactViewport ? { min: 136, max: 280 } : { min: 145, max: 350 };
      if (key === 'trend') return compactViewport ? { min: 150, max: 310 } : { min: 165, max: 420 };
      if (key === 'map') return compactViewport ? { min: 185, max: 360 } : { min: 205, max: 520 };
      return compactViewport ? { min: 132, max: 560 } : { min: 138, max: 820 };
    }

    function applyOverviewLayout() {
      const layout = getOverviewLayout();
      const cards = document.querySelectorAll('#paneOverview [data-ov-id]');
      const vNext = Boolean(document.querySelector('#paneOverview .overviewStack.ovx'));
      cards.forEach((card) => {
        const id = String(card.dataset.ovId || '').trim();
        if (!id) return;

        const hidden = Boolean(layout.hidden && layout.hidden[id]);
        card.style.display = hidden ? 'none' : '';

        // Height is the only practical resize dimension inside grid/flex layouts.
        const rawH = layout.heights ? Number(layout.heights[id] || 0) : 0;
        const h = Number.isFinite(rawH) ? Math.round(rawH) : 0;
        const bounds = overviewCardHeightBounds(id);
        if (!hidden && !vNext && h >= bounds.min && h <= bounds.max) card.style.height = `${h}px`;
        else card.style.height = '';
      });

      // Sync checkbox UI.
      document.querySelectorAll('#ovCustomize input[type="checkbox"][data-ov-id]').forEach((cb) => {
        const id = String(cb.dataset.ovId || '').trim();
        if (!id) return;
        cb.checked = !Boolean(layout.hidden && layout.hidden[id]);
      });

      // Re-render overview since some canvases may have resized/hidden.
      state.dirty.counters = true;
      scheduleRender();
    }

    function initOverviewCustomization() {
      const details = document.getElementById('ovCustomize');
      if (!details) return;

      const onChange = (ev) => {
        const el = ev.target;
        if (!el || el.tagName !== 'INPUT') return;
        const id = String(el.dataset.ovId || '').trim();
        if (!id) return;

        const layout = getOverviewLayout();
        layout.hidden[id] = !Boolean(el.checked);
        setOverviewLayout(layout);
        applyOverviewLayout();
      };

      details.addEventListener('change', onChange);

      // Persist card heights when user resizes (we only save while Customize is open).
      const saveHeights = () => {
        if (!details.open) return;
        const layout = getOverviewLayout();
        document.querySelectorAll('#paneOverview [data-ov-id]').forEach((card) => {
          if (!card || card.offsetParent === null) return;
          const id = String(card.dataset.ovId || '').trim();
          if (!id) return;
          const bounds = overviewCardHeightBounds(id);
          const h = Math.round(card.getBoundingClientRect().height);
          if (h >= bounds.min && h <= bounds.max) layout.heights[id] = h;
        });
        setOverviewLayout(layout);
      };

      let saveTimer = null;
      const saveDebounced = () => {
        if (!details.open) return;
        if (saveTimer) clearTimeout(saveTimer);
        saveTimer = setTimeout(saveHeights, 250);
      };

      if (window.ResizeObserver) {
        const ro = new ResizeObserver(() => saveDebounced());
        document.querySelectorAll('#paneOverview [data-ov-id]').forEach((card) => ro.observe(card));
      }

      // Apply saved layout on boot.
      applyOverviewLayout();
    }

    /* ── Session-expiry handler (401/403) ────────────────────── */
    let _authFailureHandled = false;
    function _handleAuthFailure(status) {
      if (_authFailureHandled) return;        // avoid redirect storms
      _authFailureHandled = true;
      const msg = status === 403 ? 'Access forbidden' : 'Session expired';
      try { if (typeof showToast === 'function') showToast(`${msg} — redirecting to login…`, 'warn'); } catch {}
      setTimeout(() => {
        const loginPath = window.location.pathname.startsWith('/admin') ? '/adminlogin' : '/login';
        window.location.href = loginPath;
      }, 1200);
    }

    async function apiFetchJson(url, { timeoutMs = 4000, headers = {} } = {}) {
      const normalizedUrl = String(url || '').trim();
      if (!normalizedUrl || normalizedUrl === 'undefined' || normalizedUrl.endsWith('/undefined')) {
        const err = new Error('Invalid API URL');
        err.status = 0;
        err.body = String(url || '');
        throw err;
      }
      const isApiKeyPath = (u) => {
        const s = String(u || '');
        return (
          s.startsWith('/api/assets') ||
          s.startsWith('/api/rbac') ||
          s.startsWith('/api/ioc') ||
          s.startsWith('/api/dlp') ||
          s.startsWith('/api/keys') ||
          s.startsWith('/api/webhooks')
        );
      };
      const withAuthHeaders = (u, h) => {
        const merged = { ...(h || {}) };
        if (!isApiKeyPath(u)) return merged;
        if (merged['X-Api-Key']) return merged;
        let k = '';
        try {
          k = String(
            localStorage.getItem('percepta.api.key') ||
            localStorage.getItem('percepta_api_key') ||
            localStorage.getItem('api_key') ||
            'demo'
          ).trim();
        } catch {
          k = 'demo';
        }
        if (k) merged['X-Api-Key'] = k;
        return merged;
      };
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const reqHeaders = withAuthHeaders(normalizedUrl, headers);
        const res = await fetch(normalizedUrl, { signal: ctrl.signal, credentials: 'same-origin', headers: reqHeaders });
        if (res.status === 401 || res.status === 403) {
          _handleAuthFailure(res.status);
        }
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

    async function apiPostJson(url, bodyObj, { timeoutMs = 4000, headers = {} } = {}) {
      const normalizedUrl = String(url || '').trim();
      if (!normalizedUrl || normalizedUrl === 'undefined' || normalizedUrl.endsWith('/undefined')) {
        const err = new Error('Invalid API URL');
        err.status = 0;
        err.body = String(url || '');
        throw err;
      }
      const isApiKeyPath = (u) => {
        const s = String(u || '');
        return (
          s.startsWith('/api/assets') ||
          s.startsWith('/api/rbac') ||
          s.startsWith('/api/ioc') ||
          s.startsWith('/api/dlp') ||
          s.startsWith('/api/keys') ||
          s.startsWith('/api/webhooks')
        );
      };
      const withAuthHeaders = (u, h) => {
        const merged = { ...(h || {}) };
        if (!isApiKeyPath(u)) return merged;
        if (merged['X-Api-Key']) return merged;
        let k = '';
        try {
          k = String(
            localStorage.getItem('percepta.api.key') ||
            localStorage.getItem('percepta_api_key') ||
            localStorage.getItem('api_key') ||
            'demo'
          ).trim();
        } catch {
          k = 'demo';
        }
        if (k) merged['X-Api-Key'] = k;
        return merged;
      };
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const reqHeaders = withAuthHeaders(normalizedUrl, headers);
        const res = await fetch(normalizedUrl, {
          method: 'POST',
          signal: ctrl.signal,
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', ...reqHeaders },
          body: JSON.stringify(bodyObj ?? {}),
        });
        if (res.status === 401 || res.status === 403) {
          _handleAuthFailure(res.status);
        }
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

    function isPersistableUiKey(key) {
      const k = String(key || '');
      return k === 'theme' || k === 'percepta_theme' || k.startsWith('percepta.');
    }

    function collectUiSnapshotItems() {
      const items = {};
      try {
        const maxKeys = 512;
        for (let i = 0; i < localStorage.length && Object.keys(items).length < maxKeys; i += 1) {
          const key = String(localStorage.key(i) || '');
          if (!isPersistableUiKey(key)) continue;
          const val = localStorage.getItem(key);
          if (typeof val !== 'string') continue;
          if (val.length > 8192) continue;
          items[key] = val;
        }
      } catch {}
      return items;
    }

    function getLocalUiSnapshotUpdatedAt() {
      try {
        return Number(localStorage.getItem(UI_SNAPSHOT_UPDATED_KEY) || 0) || 0;
      } catch {
        return 0;
      }
    }

    function setLocalUiSnapshotUpdatedAt(ms) {
      try { localStorage.setItem(UI_SNAPSHOT_UPDATED_KEY, String(Math.max(0, Number(ms) || 0))); } catch {}
    }

    function uiSnapshotDigest(items) {
      try {
        const keys = Object.keys(items || {}).sort();
        const packed = keys.map((k) => `${k}=${String(items[k] || '')}`).join('\n');
        return packed;
      } catch {
        return '';
      }
    }

    function hydrateStateFromLocalStorage() {
      try {
        const p = String(localStorage.getItem(PERF_MODE_KEY) || state.perfMode || 'auto').trim().toLowerCase();
        state.perfMode = (p === 'on' || p === 'off' || p === 'auto') ? p : 'auto';
      } catch {}
      try {
        const d = String(localStorage.getItem(DENSITY_MODE_KEY) || state.densityMode || 'auto').trim().toLowerCase();
        state.densityMode = (d === 'auto' || d === 'normal' || d === 'compact' || d === 'ultra') ? d : 'auto';
      } catch {}
      try { state.nocMode = String(localStorage.getItem(NOC_MODE_KEY) || '0') === '1'; } catch {}
      try { state.sidebarHidden = String(localStorage.getItem(SIDEBAR_HIDDEN_KEY) || '0') === '1'; } catch {}
      try {
        const s = String(localStorage.getItem(SETTINGS_SUBTAB_KEY) || 'general').trim().toLowerCase();
        state.settingsSubTab = ['general', 'control', 'agents', 'rules', 'advanced'].includes(s) ? s : 'general';
      } catch {}
      try {
        const a = String(localStorage.getItem(SETTINGS_AGENTS_CAT_KEY) || 'all').trim().toLowerCase();
        state.settingsAgentsCategory = ['all', 'connected', 'stale', 'offline'].includes(a) ? a : 'all';
      } catch {}
      try { state.settingsControlDomain = normalizeSettingsControlDomain(localStorage.getItem(SETTINGS_CONTROL_DOMAIN_KEY) || 'global'); } catch {}
      try { state.settingsControlScope = normalizeSettingsControlScope(localStorage.getItem(SETTINGS_CONTROL_SCOPE_KEY) || 'global'); } catch {}
      try { state.settingsControlModel = mergeSettingsControlModel(storageGetJson(SETTINGS_CONTROL_MODEL_KEY, getDefaultSettingsControlModel())); } catch {}
      try {
        const tabs = storageGetJson(SUBTABS_KEY, state.subTabs || {});
        if (tabs && typeof tabs === 'object') state.subTabs = { ...(state.subTabs || {}), ...tabs };
      } catch {}
      try {
        const filters = storageGetJson(SCOPE_FILTERS_KEY, state.scopeFilters || {});
        if (filters && typeof filters === 'object') state.scopeFilters = filters;
      } catch {}
    }

    function applyUiSnapshotItems(items) {
      if (!items || typeof items !== 'object') return false;
      let changed = false;
      try {
        for (const [key, value] of Object.entries(items)) {
          if (!isPersistableUiKey(key)) continue;
          if (typeof value !== 'string') continue;
          const cur = localStorage.getItem(key);
          if (cur === value) continue;
          localStorage.setItem(key, value);
          changed = true;
        }
      } catch {}
      return changed;
    }

    async function restoreUiSnapshotFromServer() {
      try {
        const remote = await apiFetchJson(API.settingsUiSnapshot, { timeoutMs: 2000, headers: { 'Accept': 'application/json' } });
        if (!remote || typeof remote !== 'object') return false;
        const remoteUpdated = Math.max(0, Number(remote.updated_at_ms || 0) || 0);
        const localUpdated = getLocalUiSnapshotUpdatedAt();
        const items = (remote.items && typeof remote.items === 'object') ? remote.items : null;
        if (!items || !Object.keys(items).length) return false;
        if (localUpdated > 0 && remoteUpdated > 0 && localUpdated > remoteUpdated) return false;

        const changed = applyUiSnapshotItems(items);
        if (!changed) return false;

        setLocalUiSnapshotUpdatedAt(remoteUpdated || Date.now());
        hydrateStateFromLocalStorage();
        initTheme();
        initI18n();
        updatePerformanceMode();
        updateDensityMode();
        updateNocMode();
        applyBrandStyleMode();
        applyBrandLayout();
        applySidebarMenuState();
        applyPaneScopeUi();
        applySettingsSubTabsUi();
        applySettingsAgentsCategoryUi();
        applySettingsControlDomainScopeUi();
        applySettingsControlModel({ silent: true });
        applyOverviewLayout();
        state.dirty.tables = true;
        state.dirty.details = true;
        state.dirty.counters = true;
        scheduleRender();
        return true;
      } catch {
        return false;
      }
    }

    const uiSnapshotSync = {
      timer: null,
      lastDigest: '',
      inflight: false,
    };

    async function pushUiSnapshotToServer({ force = false } = {}) {
      if (uiSnapshotSync.inflight) return false;
      const items = collectUiSnapshotItems();
      const digest = uiSnapshotDigest(items);
      if (!force && digest && digest === uiSnapshotSync.lastDigest) return false;

      uiSnapshotSync.inflight = true;
      try {
        const payload = {
          updated_at_ms: Date.now(),
          items,
        };
        const saved = await apiPostJson(API.settingsUiSnapshot, payload, { timeoutMs: 2200, headers: { 'Accept': 'application/json' } });
        uiSnapshotSync.lastDigest = digest;
        const ackMs = Math.max(0, Number(saved?.updated_at_ms || payload.updated_at_ms) || payload.updated_at_ms);
        setLocalUiSnapshotUpdatedAt(ackMs);
        return true;
      } catch {
        return false;
      } finally {
        uiSnapshotSync.inflight = false;
      }
    }

    function startUiSnapshotSync() {
      if (uiSnapshotSync.timer) return;
      uiSnapshotSync.timer = setInterval(() => {
        pushUiSnapshotToServer({ force: false });
      }, 15000);

      document.addEventListener('visibilitychange', () => {
        if (document.hidden) pushUiSnapshotToServer({ force: true });
      });

      window.addEventListener('beforeunload', () => {
        pushUiSnapshotToServer({ force: true });
      });
    }

    async function fetchRuntimeSettingsFromServer() {
      try {
        return await apiFetchJson(API.settingsRuntime, { timeoutMs: 4000, headers: { 'Accept': 'application/json' } });
      } catch {
        return null;
      }
    }

    async function pushRuntimeSettingsPatch(patch) {
      try {
        return await apiPostJson(API.settingsRuntime, patch || {}, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
      } catch {
        return null;
      }
    }

