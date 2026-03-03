    function initUi() {
      try {
        document.addEventListener('visibilitychange', () => updatePerformanceMode());
      } catch {}
      try {
        window.addEventListener('resize', () => updateDensityMode(), { passive: true });
      } catch {}
      try {
        window.addEventListener('keydown', (ev) => {
          if (!ev.altKey) return;
          const k = String(ev.key || '').trim();
          const map = {
            '1': 'overview',
            '2': 'alerts',
            '3': 'events',
            '4': 'honeypot',
            '5': 'ids',
            '6': 'escalations',
            '7': 'playbooks',
            '8': 'response',
            '9': 'audit',
          };
          const next = map[k];
          if (!next) return;
          ev.preventDefault();
          setView(next);
        });
      } catch {}

      // Keyboard shortcuts help overlay (? key)
      try {
        const kbOverlay = document.getElementById('kbShortcutsOverlay');
        if (kbOverlay) {
          const showKb = () => { kbOverlay.style.display = ''; };
          const hideKb = () => { kbOverlay.style.display = 'none'; };
          window.toggleKbHelp = () => { kbOverlay.style.display === 'none' ? showKb() : hideKb(); };
          kbOverlay.querySelector('.kb-overlay-backdrop')?.addEventListener('click', hideKb);
          kbOverlay.querySelector('.kb-overlay-close')?.addEventListener('click', hideKb);
          window.addEventListener('keydown', (ev) => {
            if (ev.key === '?' && !ev.altKey && !ev.ctrlKey && !ev.metaKey) {
              const tag = (document.activeElement?.tagName || '').toLowerCase();
              if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
              ev.preventDefault();
              toggleKbHelp();
            }
            if (ev.key === 'Escape' && kbOverlay.style.display !== 'none') {
              hideKb();
            }
          });
        }
      } catch {}

      // Command Palette (Ctrl+K / Cmd+K)
      try { initCommandPalette(); } catch {}

      // ── Modal close on browser back button (popstate) ──────────────────
      // When a modal-overlay is added to the DOM, push a history entry.
      // Pressing the browser back button pops that entry and closes the topmost modal.
      try {
        let _modalCount = 0;
        const _modalObserver = new MutationObserver((mutations) => {
          const overlays = document.querySelectorAll('.modal-overlay');
          const count = overlays.length;
          if (count > _modalCount) {
            // Modal opened — push state so back button can close it.
            for (let i = _modalCount; i < count; i++) {
              history.pushState({ _percModal: true }, '');
            }
          }
          _modalCount = count;
        });
        _modalObserver.observe(document.body, { childList: true });

        window.addEventListener('popstate', (ev) => {
          const overlays = document.querySelectorAll('.modal-overlay');
          if (overlays.length > 0) {
            const top = overlays[overlays.length - 1];
            try { top.remove(); } catch {}
            _modalCount = Math.max(0, _modalCount - 1);
          }
        });
      } catch {}

      initShowcaseInteractions();
      initPaneScopeTabs();

      // Monitor network connectivity
      let lastOnlineTime = Date.now();
      let isEffectivelyOffline = false;

      window.addEventListener('online', () => {
        console.log('[network] Online detected');
        lastOnlineTime = Date.now();
        isEffectivelyOffline = false;
        showToast('Network connection restored', 'ok');
        
        if (state.ws && state.ws.readyState !== WebSocket.OPEN) {
          startStream();
        }
        
        state.dirty.alerts = true;
        state.dirty.events = true;
        scheduleRender();
      });

      window.addEventListener('offline', () => {
        console.log('[network] Offline detected');
        isEffectivelyOffline = true;
        showToast('Network connection lost - using cached data', 'warn');
        
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
          try { state.ws.close(); } catch {}
        }
      });

      if (!navigator.onLine) {
        isEffectivelyOffline = true;
        showToast('Offline - some features may be limited', 'warn');
      }
      
      window.isEffectivelyOffline = () => isEffectivelyOffline || !navigator.onLine;

      document.getElementById('sidebarMenuToggle')?.addEventListener('click', () => {
        toggleSidebarMenu();
      });

      // Mobile: close sidebar when tapping the backdrop (::after pseudo on .app)
      document.querySelector('.app')?.addEventListener('click', (ev) => {
        if (window.innerWidth > 980) return;
        if (state.sidebarHidden) return;
        const sidebar = document.querySelector('.sidebar');
        if (sidebar && sidebar.contains(ev.target)) return;
        const topbar = document.querySelector('.topbar');
        if (topbar && topbar.contains(ev.target)) return;
        state.sidebarHidden = true;
        try { localStorage.setItem(SIDEBAR_HIDDEN_KEY, '1'); } catch {}
        applySidebarMenuState();
      });

      // Auto-hide sidebar on mobile first load
      if (window.innerWidth <= 980) {
        state.sidebarHidden = true;
        try { localStorage.setItem(SIDEBAR_HIDDEN_KEY, '1'); } catch {}
      }

      applyBrandStyleMode();
      applyBrandLayout();
      applySidebarMenuState();

      document.getElementById('themeBtn')?.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        applyTheme(current === 'light' ? 'dark' : 'light');
      });
      document.getElementById('refreshBtn')?.addEventListener('click', () => refreshAll());
      document.getElementById('toastClose')?.addEventListener('click', () => document.getElementById('toast')?.classList.remove('show'));

      // Micro-feedback: ripple-ish flash on press for primary clickables.
      const attachRipple = (el) => {
        if (!el) return;
        el.addEventListener('pointerdown', (ev) => {
          try {
            const r = el.getBoundingClientRect();
            const x = ((ev.clientX - r.left) / Math.max(1, r.width)) * 100;
            const y = ((ev.clientY - r.top) / Math.max(1, r.height)) * 100;
            el.style.setProperty('--rx', `${x}%`);
            el.style.setProperty('--ry', `${y}%`);
          } catch {}
          el.classList.remove('rippling');
          // Force reflow so animation restarts reliably.
          void el.offsetWidth;
          el.classList.add('rippling');
          clearTimeout(attachRipple._t);
          attachRipple._t = setTimeout(() => el.classList.remove('rippling'), 520);
        }, { passive: true });
      };
      attachRipple._t = null;
      document.querySelectorAll('button.btn').forEach(attachRipple);

      document.querySelectorAll('.nav .item').forEach((el) => {
        // Keyboard accessibility for nav (div-based items)
        try { el.tabIndex = 0; } catch {}
        el.addEventListener('click', () => setView(el.dataset.view));
        attachRipple(el);
        el.addEventListener('keydown', (ev) => {
          const k = ev?.key;
          if (k === 'Enter' || k === ' ') {
            ev.preventDefault();
            setView(el.dataset.view);
          }
        });
      });

      // ═══════════════════════════════════════════════════════════════════════════
      // KEYBOARD SHORTCUTS: Alt+1-6 for Primary Workflow Navigation (Professional SIEMs)
      // Tier 1 workflow access:
      //   Alt+1 = Dashboard (Overview)
      //   Alt+2 = Alerts
      //   Alt+3 = Investigation (Events)
      //   Alt+4 = Response
      //   Alt+5 = Playbooks
      //   Alt+6 = Create Case (Escalations)
      // ═══════════════════════════════════════════════════════════════════════════
      document.addEventListener('keydown', (ev) => {
        // Only activate if no text input is focused (avoid interfering with searches, modals)
        const focused = document.activeElement;
        if (focused && (
          focused.tagName === 'INPUT' ||
          focused.tagName === 'TEXTAREA' ||
          focused.contentEditable === 'true'
        )) {
          return;
        }

        // Check for Alt+number keys (Ctrl NOT pressed, to avoid conflict with browser shortcuts)
        if (ev.altKey && !ev.ctrlKey && !ev.metaKey && !ev.shiftKey) {
          const shortcutMap = {
            '1': 'overview',   // Dashboard
            '2': 'alerts',     // Alerts
            '3': 'events',     // Investigation
            '4': 'response',   // Response
            '5': 'playbooks',  // Playbooks
            '6': 'escalations' // Create Case
          };

          const view = shortcutMap[ev.key];
          if (view) {
            ev.preventDefault();
            setView(view);
          }
        }
      });

      // Persist nav group open/closed state in localStorage
      try {
        document.querySelectorAll('details.nav-group').forEach((g) => {
          const key = 'percepta.nav.' + g.id;
          const saved = localStorage.getItem(key);
          if (saved === 'closed') g.removeAttribute('open');
          else if (saved === 'open') g.setAttribute('open', '');
          g.addEventListener('toggle', () => {
            try { localStorage.setItem(key, g.open ? 'open' : 'closed'); } catch {}
          });
        });
      } catch {}

      // Resizable Events split (table vs details)
      (function initEventsSplitter() {
        const split = document.getElementById('eventsSplit');
        const handle = document.getElementById('eventsSplitter');
        if (!split || !handle) return;

        const KEY = 'percepta.ui.eventsSplitPct';
        const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
        const setPct = (pct) => {
          const p = clamp(Number(pct), 35, 82);
          split.style.setProperty('--eventsSplit', `${p}%`);
          try { localStorage.setItem(KEY, String(p)); } catch {}
        };

        // Load persisted value.
        try {
          const saved = localStorage.getItem(KEY);
          if (saved != null && saved !== '') {
            const n = Number(saved);
            if (Number.isFinite(n)) split.style.setProperty('--eventsSplit', `${clamp(n, 35, 82)}%`);
          }
        } catch {}

        const onMove = (clientX) => {
          const r = split.getBoundingClientRect();
          const x = clamp(clientX - r.left, 0, r.width);
          const pct = (x / Math.max(1, r.width)) * 100;
          setPct(pct);
        };

        const onPointerDown = (ev) => {
          // Ignore on small screens where splitter is hidden.
          if (window.matchMedia && window.matchMedia('(max-width: 1100px)').matches) return;
          try { handle.setPointerCapture(ev.pointerId); } catch {}
          split.classList.add('resizing');
          onMove(ev.clientX);
        };
        const onPointerMove = (ev) => {
          if (!split.classList.contains('resizing')) return;
          onMove(ev.clientX);
        };
        const onPointerUp = () => {
          split.classList.remove('resizing');
        };

        handle.addEventListener('pointerdown', onPointerDown);
        handle.addEventListener('pointermove', onPointerMove);
        handle.addEventListener('pointerup', onPointerUp);
        handle.addEventListener('pointercancel', onPointerUp);
        handle.addEventListener('dblclick', () => setPct(62));

        handle.addEventListener('keydown', (ev) => {
          const k = ev?.key;
          if (k !== 'ArrowLeft' && k !== 'ArrowRight' && k !== 'Home' && k !== 'End') return;
          ev.preventDefault();
          const current = split.style.getPropertyValue('--eventsSplit') || '';
          const cur = Number(String(current).replace('%', '').trim());
          const base = Number.isFinite(cur) ? cur : 62;
          if (k === 'ArrowLeft') setPct(base - 2);
          else if (k === 'ArrowRight') setPct(base + 2);
          else if (k === 'Home') setPct(35);
          else if (k === 'End') setPct(82);
        });
      })();

      // Event Detail Drawer — open/close logic
      (function initEventDetailDrawer() {
        const drawer = document.getElementById('evDetailDrawer');
        const backdrop = document.getElementById('evDetailBackdrop');
        const closeBtn = document.getElementById('evDetailClose');
        if (!drawer) return;

        window.openEventDetailDrawer = function() {
          drawer.classList.add('open');
        };
        window.closeEventDetailDrawer = function() {
          drawer.classList.remove('open');
          // Clean up drawer state to prevent stale data/references on next open.
          try {
            if (state.ui) {
              state.ui.selectedEvent = null;
              state.ui.selectedEventHash = null;
            }
            const body = document.getElementById('evDetailBody');
            if (body) body.innerHTML = '';
          } catch {}
        };

        if (backdrop) backdrop.addEventListener('click', () => window.closeEventDetailDrawer());
        if (closeBtn) closeBtn.addEventListener('click', () => window.closeEventDetailDrawer());

        document.addEventListener('keydown', (e) => {
          if (e.key === 'Escape' && drawer.classList.contains('open')) {
            window.closeEventDetailDrawer();
          }
        });

        // ═══════════════════════════════════════════════════════════════════
        // DEMO POLISH: Contextual Navigation Buttons in Event Detail Drawer
        // Added 2026-03-16 for enterprise-grade workflow experience
        // ═══════════════════════════════════════════════════════════════════

        // Back button (breadcrumb)
        const backBtn = document.getElementById('evDetailBack');
        if (backBtn) {
          backBtn.addEventListener('click', () => {
            window.closeEventDetailDrawer();
          });
        }

        // "View Events" button — Switch to Investigation pane
        const viewEventsBtn = document.getElementById('evDetailViewEvents');
        if (viewEventsBtn) {
          viewEventsBtn.addEventListener('click', () => {
            window.closeEventDetailDrawer();
            setView('events');
            // Optionally: could pre-populate search box with current event's source IP
            // const body = document.getElementById('evDetailBody');
            // const srcIp = body?.querySelector?.('[data-field="src_ip"]')?.textContent;
            // if (srcIp) { document.getElementById('eventsSearchInput')?.value = srcIp; }
          });
        }

        // "Respond" button — Switch to Response pane
        const executeResponseBtn = document.getElementById('evDetailExecuteResponse');
        if (executeResponseBtn) {
          executeResponseBtn.addEventListener('click', () => {
            window.closeEventDetailDrawer();
            setView('response');
          });
        }

        // "Create Case" button — Switch to Cases/Escalations pane
        const createCaseBtn = document.getElementById('evDetailCreateCase');
        if (createCaseBtn) {
          createCaseBtn.addEventListener('click', () => {
            window.closeEventDetailDrawer();
            setView('escalations');
          });
        }

        // "Compliance" button — Switch to Compliance pane
        const checkComplianceBtn = document.getElementById('evDetailCheckCompliance');
        if (checkComplianceBtn) {
          checkComplianceBtn.addEventListener('click', () => {
            window.closeEventDetailDrawer();
            setView('compliance');
          });
        }

        // ═══════════════════════════════════════════════════════════════════
        // END DEMO POLISH
        // ═══════════════════════════════════════════════════════════════════
      })();

      // Resizable Events table columns (drag header separators; persisted locally)
      (function initEventsColumns() {
        const table = document.getElementById('eventsTable');
        if (!table) return;
        const presetBar = document.getElementById('eventsPresetBar');
        const manageBtn = document.getElementById('eventsColumnsManageBtn');
        const KEY = 'percepta.ui.eventsColumnsPx.v1';
        const PRESET_KEY = 'percepta.ui.eventsColumnsPreset.v1';
        const MODEL_KEY = 'percepta.ui.eventsColumnsModel.v2';
        const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
        const minColumnPx = 90;

        const flattenPaths = (input, prefix = '', out = new Set(), depth = 0) => {
          if (depth > 3 || !input || typeof input !== 'object') return out;
          for (const [k, v] of Object.entries(input)) {
            if (!k || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
            const key = String(k).trim();
            if (!key) continue;
            const path = prefix ? `${prefix}.${key}` : key;
            if (path.split('.').length <= 4) out.add(path);
            if (v && typeof v === 'object' && !Array.isArray(v)) flattenPaths(v, path, out, depth + 1);
          }
          return out;
        };

        const discoverPathsFromEvents = () => {
          const sample = Array.isArray(state.events) ? state.events.slice(0, 250) : [];
          const out = new Set();
          for (const ev of sample) flattenPaths(ev, '', out, 0);
          return Array.from(out)
            .filter((p) => !/^normalized\./i.test(p) && !/^raw\./i.test(p) && !/^ingest\./i.test(p))
            .slice(0, 260);
        };

        const seedMap = getEventsColumnDefinitionMap([]);
        const defaultOrder = Array.from(eventsColumnsRuntime.defaultOrder || []);
        const hasDef = (id, map) => map.has(id);
        const PRESETS = {
          default: defaultOrder.slice(),
          process: ['timestamp', 'severity', 'user', 'host', 'process', 'object', 'summary'],
          network: ['timestamp', 'severity', 'agent', 'src_ip', 'dst_ip', 'object', 'summary'],
          auth: ['timestamp', 'severity', 'user', 'agent', 'host', 'src_ip', 'summary'],
          file: ['timestamp', 'severity', 'user', 'agent', 'host', 'process', 'object', 'summary'],
        };

        const savedModel = storageGetJson(MODEL_KEY, null);
        const model = {
          order: Array.isArray(savedModel?.order) ? savedModel.order.map((s) => String(s || '').trim()).filter(Boolean) : defaultOrder.slice(),
          visible: Array.isArray(savedModel?.visible) ? savedModel.visible.map((s) => String(s || '').trim()).filter(Boolean) : defaultOrder.slice(),
          customPaths: Array.isArray(savedModel?.customPaths) ? savedModel.customPaths.map((s) => String(s || '').trim()).filter(Boolean) : [],
          widths: (savedModel && typeof savedModel.widths === 'object' && savedModel.widths) ? { ...savedModel.widths } : {},
        };

        const migrateOldWidths = storageGetJson(KEY, null);
        if (Array.isArray(migrateOldWidths) && migrateOldWidths.length === defaultOrder.length) {
          for (let i = 0; i < defaultOrder.length; i++) {
            const id = defaultOrder[i];
            const n = Number(migrateOldWidths[i]);
            if (!Number.isFinite(n) || n <= 0) continue;
            model.widths[id] = Math.round(clamp(n, minColumnPx, 1400));
          }
        }

        const persistModel = () => {
          storageSetJson(MODEL_KEY, {
            order: model.order,
            visible: model.visible,
            customPaths: model.customPaths,
            widths: model.widths,
          });
          const active = getActiveDefs();
          storageSetJson(KEY, active.map((d) => Math.round(Number(model.widths[d.id] || d.width || 140) || 140)));
        };

        const markPresetActive = (name) => {
          if (!presetBar) return;
          presetBar.querySelectorAll('[data-col-preset]').forEach((btn) => {
            const k = String(btn.getAttribute('data-col-preset') || '').trim();
            btn.classList.toggle('active', Boolean(name) && k === name);
          });
        };

        let cachedDiscoveredPaths = [];
        const getDefMap = () => {
          cachedDiscoveredPaths = discoverPathsFromEvents();
          const allCustom = Array.from(new Set([...(model.customPaths || []), ...cachedDiscoveredPaths]));
          return getEventsColumnDefinitionMap(allCustom);
        };

        const normalizeModel = () => {
          const map = getDefMap();
          const ids = Array.from(map.keys());
          const orderSeed = [...model.order, ...defaultOrder, ...ids];
          model.order = Array.from(new Set(orderSeed.filter((id) => hasDef(id, map))));
          model.visible = Array.from(new Set((model.visible || []).filter((id) => hasDef(id, map))));
          if (!model.visible.length) model.visible = PRESETS.default.filter((id) => hasDef(id, map));
          model.customPaths = Array.from(new Set((model.customPaths || []).filter(Boolean)));
          if (!model.order.length) model.order = PRESETS.default.filter((id) => hasDef(id, map));
        };

        const getActiveDefs = () => {
          const map = getDefMap();
          normalizeModel();
          const visibleSet = new Set(model.visible);
          const defs = [];
          for (const id of model.order) {
            if (!visibleSet.has(id)) continue;
            const def = map.get(id);
            if (def) defs.push(def);
          }
          return defs.length ? defs : PRESETS.default.map((id) => map.get(id)).filter(Boolean);
        };

        const updateEventsColumnsRuntime = () => {
          const defs = getActiveDefs();
          eventsColumnsRuntime.activeDefs = defs;
          eventsColumnsRuntime.activeIds = defs.map((d) => d.id);
        };

        const bindEventsSortHandlers = () => {
          const defs = eventsColumnsRuntime.activeDefs || [];
          const ths = Array.from(table.querySelectorAll('thead th'));
          for (let i = 0; i < ths.length; i++) {
            const th = ths[i];
            const key = defs[i]?.key;
            if (!key) continue;
            th.style.cursor = 'pointer';
            th.title = 'Click to sort';
            th.onclick = () => toggleSort('events', key);
          }
        };

        const renderTableStructure = () => {
          updateEventsColumnsRuntime();
          const defs = eventsColumnsRuntime.activeDefs || [];
          let colgroup = table.querySelector('colgroup');
          if (!colgroup) {
            colgroup = document.createElement('colgroup');
            table.insertBefore(colgroup, table.firstChild || null);
          }
          colgroup.innerHTML = '';
          for (const def of defs) {
            const col = document.createElement('col');
            const w = Number(model.widths[def.id]);
            const px = Number.isFinite(w) && w > 0 ? clamp(w, minColumnPx, 1400) : Number(def.width || 140);
            col.style.width = `${Math.round(px)}px`;
            col.dataset.colId = def.id;
            model.widths[def.id] = Math.round(px);
            colgroup.appendChild(col);
          }

          let tr = table.querySelector('thead tr');
          if (!tr) {
            const thead = table.querySelector('thead') || table.createTHead();
            tr = document.createElement('tr');
            thead.appendChild(tr);
          }
          tr.innerHTML = '';
          for (const def of defs) {
            const th = document.createElement('th');
            th.textContent = def.label || def.id;
            th.dataset.colId = def.id;
            tr.appendChild(th);
          }

          const cols = Array.from(colgroup.querySelectorAll('col'));
          const ths = Array.from(tr.querySelectorAll('th'));
          const beginDrag = (idx, startX) => {
            const id = defs[idx]?.id;
            if (!id) return;
            const startW = parseInt(cols[idx]?.style.width || '0', 10) || Number(defs[idx]?.width || 140);
            document.body.classList.add('colResizing');

            const onMove = (ev) => {
              const dx = (ev.clientX - startX);
              const nextW = clamp(startW + dx, minColumnPx, 1400);
              model.widths[id] = Math.round(nextW);
              if (cols[idx]) cols[idx].style.width = `${Math.round(nextW)}px`;
            };

            const onUp = () => {
              window.removeEventListener('pointermove', onMove);
              window.removeEventListener('pointerup', onUp);
              window.removeEventListener('pointercancel', onUp);
              document.body.classList.remove('colResizing');
              persistModel();
              try { localStorage.removeItem(PRESET_KEY); } catch {}
              markPresetActive('');
            };

            window.addEventListener('pointermove', onMove);
            window.addEventListener('pointerup', onUp, { once: true });
            window.addEventListener('pointercancel', onUp, { once: true });
          };

          for (let i = 0; i < ths.length; i++) {
            if (i >= ths.length - 1) continue;
            const th = ths[i];
            const h = document.createElement('div');
            h.className = 'thResizeHandle';
            h.setAttribute('role', 'separator');
            h.setAttribute('aria-orientation', 'vertical');
            h.setAttribute('aria-label', `Resize column ${i + 1}`);
            try { h.tabIndex = 0; } catch {}
            h.addEventListener('click', (ev) => ev.stopPropagation());
            h.addEventListener('pointerdown', (ev) => {
              ev.preventDefault();
              ev.stopPropagation();
              try { h.setPointerCapture(ev.pointerId); } catch {}
              beginDrag(i, ev.clientX);
            });
            h.addEventListener('keydown', (ev) => {
              const k = ev?.key;
              if (k !== 'ArrowLeft' && k !== 'ArrowRight') return;
              ev.preventDefault();
              const id = defs[i]?.id;
              if (!id) return;
              const step = ev.shiftKey ? 24 : 10;
              const cur = Number(model.widths[id] || defs[i]?.width || 140);
              const next = clamp(cur + (k === 'ArrowRight' ? step : -step), minColumnPx, 1400);
              model.widths[id] = Math.round(next);
              if (cols[i]) cols[i].style.width = `${Math.round(next)}px`;
              persistModel();
              try { localStorage.removeItem(PRESET_KEY); } catch {}
              markPresetActive('');
            });
            th.appendChild(h);
          }

          bindEventsSortHandlers();
          persistModel();
        };

        window.__PERCEPTA_EVENTS_COLUMNS_RERENDER = () => {
          try {
            renderTableStructure();
          } catch {}
        };

        const applyPreset = (name, { persistPreset = true } = {}) => {
          const key = String(name || '').trim();
          const map = getDefMap();
          const preset = (PRESETS[key] || PRESETS.default).filter((id) => hasDef(id, map));
          if (!preset.length) return;
          model.visible = preset.slice();
          model.order = Array.from(new Set([...model.order.filter((id) => !preset.includes(id)), ...preset]));
          renderTableStructure();
          markPresetActive(key);
          if (persistPreset) {
            try { localStorage.setItem(PRESET_KEY, key); } catch {}
          }
        };

        try {
          const savedPreset = String(localStorage.getItem(PRESET_KEY) || '').trim().toLowerCase();
          if (savedPreset && PRESETS[savedPreset]) applyPreset(savedPreset, { persistPreset: false });
          else {
            renderTableStructure();
            markPresetActive('');
          }
        } catch {
          renderTableStructure();
          markPresetActive('');
        }

        const createMenu = () => {
          let menu = document.getElementById('eventsColsMenuOverlay');
          if (menu) return menu;
          menu = document.createElement('div');
          menu.id = 'eventsColsMenuOverlay';
          menu.className = 'eventsColsMenu';
          menu.innerHTML = `
            <div class="eventsColsHead">
              <input class="eventsColsSearch field sm" id="eventsColsSearch" placeholder="Search fields…" />
              <button class="btn sm" id="eventsColsResetBtn">Reset</button>
            </div>
            <div class="eventsColsMeta" id="eventsColsMeta">Drag to reorder · Toggle to show/hide</div>
            <div class="eventsColsList" id="eventsColsList"></div>
            <div class="eventsColsAdd">
              <input class="eventsColsSearch field sm" id="eventsColsAddPath" placeholder="Add path (e.g. metadata.user)" />
              <button class="btn sm" id="eventsColsAddBtn">Add</button>
            </div>`;
          document.body.appendChild(menu);
          return menu;
        };

        const renderMenuList = () => {
          const menu = createMenu();
          const list = menu.querySelector('#eventsColsList');
          const searchEl = menu.querySelector('#eventsColsSearch');
          const meta = menu.querySelector('#eventsColsMeta');
          if (!list) return;
          const query = String(searchEl?.value || '').trim().toLowerCase();

          const map = getDefMap();
          normalizeModel();
          const visibleSet = new Set(model.visible);
          const defs = model.order.map((id) => map.get(id)).filter(Boolean);
          const filtered = query
            ? defs.filter((d) => String(d.label || '').toLowerCase().includes(query) || String(d.id || '').toLowerCase().includes(query))
            : defs;

          list.innerHTML = '';
          let draggingId = null;
          const onDropBefore = (targetId) => {
            if (!draggingId || draggingId === targetId) return;
            const next = model.order.filter((id) => id !== draggingId);
            const idx = next.indexOf(targetId);
            if (idx < 0) next.push(draggingId);
            else next.splice(idx, 0, draggingId);
            model.order = next;
            persistModel();
            renderTableStructure();
            renderMenuList();
          };

          for (const def of filtered) {
            const row = document.createElement('div');
            row.className = 'eventsColsItem';
            row.draggable = true;
            row.dataset.colId = def.id;
            row.innerHTML = `<span class="eventsColsDragHandle">⋮⋮</span><div><div>${escapeHtml(def.label || def.id)}</div><div class="mono">${escapeHtml(def.id)}</div></div>`;
            const chk = document.createElement('input');
            chk.type = 'checkbox';
            chk.checked = visibleSet.has(def.id);
            chk.addEventListener('change', () => {
              if (chk.checked) model.visible = Array.from(new Set([...model.visible, def.id]));
              else model.visible = model.visible.filter((id) => id !== def.id);
              if (!model.visible.length) model.visible = PRESETS.default.slice();
              persistModel();
              renderTableStructure();
            });
            row.appendChild(chk);

            row.addEventListener('dragstart', () => {
              draggingId = def.id;
              row.classList.add('dragging');
            });
            row.addEventListener('dragend', () => {
              draggingId = null;
              row.classList.remove('dragging');
            });
            row.addEventListener('dragover', (ev) => ev.preventDefault());
            row.addEventListener('drop', (ev) => {
              ev.preventDefault();
              onDropBefore(def.id);
            });

            list.appendChild(row);
          }

          if (meta) {
            meta.textContent = `${model.visible.length} visible · ${defs.length} available`;
          }
        };

        const toggleMenu = () => {
          const menu = createMenu();
          const show = !menu.classList.contains('show');
          menu.classList.toggle('show', show);
          if (!show) return;
          const r = manageBtn?.getBoundingClientRect();
          const top = Math.round((r?.bottom || 54) + 6);
          const left = Math.max(8, Math.round((r?.right || window.innerWidth) - 360));
          menu.style.top = `${Math.min(top, window.innerHeight - 220)}px`;
          menu.style.left = `${left}px`;
          renderMenuList();
        };

        const wireMenu = () => {
          if (!manageBtn) return;
          const menu = createMenu();
          manageBtn.addEventListener('click', (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            toggleMenu();
          });
          document.addEventListener('click', (ev) => {
            const t = ev.target;
            if (!menu.classList.contains('show')) return;
            if (menu.contains(t) || manageBtn.contains(t)) return;
            menu.classList.remove('show');
          });
          menu.querySelector('#eventsColsSearch')?.addEventListener('input', renderMenuList);
          menu.querySelector('#eventsColsResetBtn')?.addEventListener('click', () => {
            const map = getDefMap();
            model.order = PRESETS.default.filter((id) => hasDef(id, map));
            model.visible = model.order.slice();
            try { localStorage.removeItem(PRESET_KEY); } catch {}
            markPresetActive('default');
            persistModel();
            renderTableStructure();
            renderMenuList();
          });
          menu.querySelector('#eventsColsAddBtn')?.addEventListener('click', () => {
            const inp = menu.querySelector('#eventsColsAddPath');
            const raw = String(inp?.value || '').trim();
            if (!raw) return;
            const path = raw.replace(/^custom:/i, '').replace(/^field:/i, '').trim();
            if (!path) return;
            if (!model.customPaths.includes(path)) model.customPaths.push(path);
            const id = `custom:${path}`;
            if (!model.order.includes(id)) model.order.push(id);
            if (!model.visible.includes(id)) model.visible.push(id);
            if (inp) inp.value = '';
            persistModel();
            renderTableStructure();
            renderMenuList();
          });
        };

        if (presetBar) {
          presetBar.querySelectorAll('[data-col-preset]').forEach((btn) => {
            btn.addEventListener('click', () => {
              const key = String(btn.getAttribute('data-col-preset') || '').trim().toLowerCase();
              if (!key) return;
              applyPreset(key);
              showToast(`${t('events.presets.title')}: ${btn.textContent || key}`);
            });
          });
        }

        wireMenu();
      })();

      const search = document.getElementById('globalSearch');
      let st = null;
      search?.addEventListener('input', () => {
        state.searchText = String(search.value || '');
        state.pagination.events.page = 1;
        state.pagination.alerts.page = 1;
        persistScopeFilterForCurrentView();
        // Debounce: refresh the currently relevant dataset.
        clearTimeout(st);
        st = setTimeout(() => {
          const v = state.view;
          const p = (v === 'alerts') ? fetchAlerts() : fetchEvents();
          Promise.resolve(p).finally(() => {
            state.dirty.tables = true;
            scheduleRender();
          });
        }, 300);
        state.dirty.tables = true;
        scheduleRender();
      });

      // Table click selection.
      const clickSelect = (tbodyId, type) => {
        document.getElementById(tbodyId)?.addEventListener('click', (ev) => {
          if (type === 'alert' && ev.target?.classList?.contains('alert-row-check')) return;
          const tr = ev.target && ev.target.closest ? ev.target.closest('tr') : null;
          if (!tr) return;
          const key = tr.dataset.key;
          if (type === 'event') {
            state.selected.key = key;
            state._detailOpenRequested = true;
            state.dirty.tables = true;
            state.dirty.details = true;
            // With Stream v2, tables may show sampled headers; fetch full event on demand.
            Promise.resolve(ensureFullEventByHash(key)).catch(() => {});
          } else {
            state.selectedAlertKey = key;
            state.dirty.tables = true;
            state.dirty.details = true;
          }
          scheduleRender();
        });
      };

      clickSelect('tblOverviewEvents', 'event');
      clickSelect('tblEvents', 'event');
      clickSelect('tblHoneypot', 'event');
      clickSelect('tblIds', 'event');
      clickSelect('tblAlerts', 'alert');

      const updateBulkAlertActionsUi = () => {
        const selected = (state.selectedAlertKeys instanceof Set) ? state.selectedAlertKeys.size : 0;
        const countEl = document.getElementById('alertsBulkCount');
        if (countEl) countEl.textContent = `Selected: ${selected}`;
        const ackBtn = document.getElementById('alertsBulkAck');
        const resBtn = document.getElementById('alertsBulkResolve');
        if (ackBtn) ackBtn.disabled = selected === 0;
        if (resBtn) resBtn.disabled = selected === 0;
      };

      const bulkUpdateAlertsStatus = async (status) => {
        const keys = (state.selectedAlertKeys instanceof Set) ? Array.from(state.selectedAlertKeys) : [];
        if (!keys.length) return;

        const updates = keys
          .map((key) => getAlertByKey(key))
          .filter((a) => a && a.id)
          .map((a) => apiRequestJson(`/api/alerts/${encodeURIComponent(a.id)}/status`, {
            method: 'POST',
            bodyObj: { status },
            timeoutMs: 3000,
          }));

        if (!updates.length) {
          state.selectedAlertKeys.clear();
          updateBulkAlertActionsUi();
          return;
        }

        await Promise.allSettled(updates);
        state.selectedAlertKeys.clear();
        state.selectedAlertKey = null;
        updateBulkAlertActionsUi();
        await fetchAlerts();
        state.dirty.tables = true;
        state.dirty.details = true;
        scheduleRender();
      };

      document.getElementById('tblAlerts')?.addEventListener('change', (ev) => {
        const chk = ev.target && ev.target.closest ? ev.target.closest('.alert-row-check') : null;
        if (!chk) return;
        const key = String(chk.dataset.key || '').trim();
        if (!key) return;
        if (!(state.selectedAlertKeys instanceof Set)) state.selectedAlertKeys = new Set();
        if (chk.checked) state.selectedAlertKeys.add(key);
        else state.selectedAlertKeys.delete(key);
        updateBulkAlertActionsUi();
      });

      document.getElementById('alertsBulkAck')?.addEventListener('click', async () => {
        await bulkUpdateAlertsStatus('acknowledged');
      });
      document.getElementById('alertsBulkResolve')?.addEventListener('click', async () => {
        await bulkUpdateAlertsStatus('resolved');
      });
      updateBulkAlertActionsUi();

      // Click-to-sort table headers.
      const attachSort = (tbodyId, tableKind, keys) => {
        const tbody = document.getElementById(tbodyId);
        const table = tbody?.closest ? tbody.closest('table') : null;
        const ths = table ? Array.from(table.querySelectorAll('thead th')) : [];
        for (let i = 0; i < ths.length; i++) {
          const key = keys[i];
          if (!key) continue;
          const th = ths[i];
          th.style.cursor = 'pointer';
          th.title = 'Click to sort';
          th.addEventListener('click', () => toggleSort(tableKind, key));
        }
      };

      const eventsKeys = ['time', 'sev', 'user', 'agent', 'host', 'agent_ip', 'src', 'dst', 'process', 'object', 'summary'];
      const honeypotKeys = ['time', 'sev', 'attacker', 'target', 'activity', 'outcome', 'agent'];
      const idsKeys = ['time', 'sev', 'signature', 'action', 'flow', 'proto', 'agent'];
      attachSort('tblOverviewEvents', 'events', eventsKeys);
      attachSort('tblHoneypot', 'events', honeypotKeys);
      attachSort('tblIds', 'events', idsKeys);
      attachSort('tblAlerts', 'alerts', ['time', 'sev', 'message', 'agent', 'status']);

      // Escalation tab switching.
      document.getElementById('escTabs')?.addEventListener('click', (ev) => {
        const btn = ev.target.closest?.('.tabBtn');
        if (!btn) return;
        const key = btn.dataset.escTab;
        if (!key) return;
        document.querySelectorAll('#escTabs .tabBtn').forEach(b => b.classList.toggle('active', b === btn));
        document.querySelectorAll('.escTabPane').forEach(p => p.classList.toggle('active', p.dataset.escPane === key));
        // Trigger re-paint so scope meta updates with live counts.
        state.dirty.escalations = true;
        scheduleRender();
      });

      // Escalation decisions (delegated on review wrap).
      document.getElementById('escReviewWrap')?.addEventListener('click', (ev) => {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button') : null;
        if (!btn) return;

        const act = btn.dataset.act;
        const id = btn.dataset.id;
        if (!act || !id) return;
        decideEscalation(id, act);
      });

      // Escalation refresh.
      document.getElementById('escRefreshBtn')?.addEventListener('click', () => {
        state.dirty.escalations = true;
        scheduleRender();
      });

      // Escalation export.
      document.getElementById('escExportBtn')?.addEventListener('click', async () => {
        try {
          const data = await apiFetchJson(API.escalations, { headers: { 'Accept': 'application/json' }, timeoutMs: 4000 });
          const esc = Array.isArray(data.escalations) ? data.escalations : [];
          const blob = new Blob([JSON.stringify(esc, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `escalations_${new Date().toISOString().slice(0,10)}.json`;
          a.click();
          URL.revokeObjectURL(url);
        } catch (e) {
          showToast('Export failed');
        }
      });

      // Export buttons.
      document.getElementById('exportOverviewJson')?.addEventListener('click', () => exportEvents('events', 'json'));
      document.getElementById('exportOverviewCsv')?.addEventListener('click', () => exportEvents('events', 'csv'));
      document.getElementById('exportEventsJson')?.addEventListener('click', () => exportEvents('events', 'json'));
      document.getElementById('exportEventsCsv')?.addEventListener('click', () => exportEvents('events', 'csv'));
      document.getElementById('exportHoneypotJson')?.addEventListener('click', () => exportEvents('honeypot', 'json'));
      document.getElementById('exportHoneypotCsv')?.addEventListener('click', () => exportEvents('honeypot', 'csv'));
      document.getElementById('exportIdsJson')?.addEventListener('click', () => exportEvents('ids', 'json'));
      document.getElementById('exportIdsCsv')?.addEventListener('click', () => exportEvents('ids', 'csv'));

      document.getElementById('clearEventsBtn')?.addEventListener('click', async () => {
        if (!(await uiConfirm(t('confirm.clearEvents'), { danger: true }))) return;
        // Set a client-side watermark so polling/refresh doesn't repopulate older events.
        state.minIngestMs = Date.now();
        state.events = [];
        state.honeypot = [];
        state.ids = [];
        state.pagination.events.page = 1;
        state.pagination.events.total = 0;
        state.eventIndex.clear();
        state.selected.key = null;
        state.dirty.tables = true;
        state.dirty.details = true;
        syncPagerUi('events');
        scheduleRender();
      });

      document.getElementById('alertsPrevPage')?.addEventListener('click', () => {
        const p = state.pagination.alerts;
        if (p.page <= 1) return;
        p.page -= 1;
        fetchAlerts().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      });

      document.getElementById('alertsNextPage')?.addEventListener('click', () => {
        const p = state.pagination.alerts;
        const totalPages = pagerTotalPages('alerts');
        if (p.page >= totalPages) return;
        p.page += 1;
        fetchAlerts().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      });

      document.getElementById('eventsPrevPage')?.addEventListener('click', () => {
        const p = state.pagination.events;
        if (p.page <= 1) return;
        p.page -= 1;
        fetchEvents().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      });

      document.getElementById('eventsNextPage')?.addEventListener('click', () => {
        const p = state.pagination.events;
        const totalPages = pagerTotalPages('events');
        if (p.page >= totalPages) return;
        p.page += 1;
        fetchEvents().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      });

      syncPagerUi('alerts');
      syncPagerUi('events');

      // Alerts filter bar
      const _applyAlertFilters = () => {
        const p = state.pagination.alerts;
        p.page = 1;
        fetchAlerts().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      };

      document.getElementById('alertsFilterApply')?.addEventListener('click', _applyAlertFilters);

      document.getElementById('alertsFilterReset')?.addEventListener('click', () => {
        const ids = ['alertsSearchQ','alertsFilterSeverity','alertsFilterCategory','alertsFilterAgent','alertsFilterFrom','alertsFilterTo'];
        ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
        const sortEl = document.getElementById('alertsFilterSort');
        if (sortEl) sortEl.value = 'last_seen';
        const orderEl = document.getElementById('alertsFilterOrder');
        if (orderEl) orderEl.value = 'desc';
        _applyAlertFilters();
      });

      // Enable Enter key on search input
      document.getElementById('alertsSearchQ')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') _applyAlertFilters();
      });

      // Populate category/agent dropdowns after first alerts fetch
      window._populateAlertFilterDropdowns = function(alerts) {
        const cats = new Set(), agents = new Set();
        for (const a of alerts) {
          if (a.category) cats.add(a.category);
          if (a.agent_hostname) agents.add(a.agent_hostname);
          else if (a.agent_id) agents.add(a.agent_id);
        }
        const catSel = document.getElementById('alertsFilterCategory');
        if (catSel) {
          const prev = catSel.value;
          catSel.innerHTML = '<option value="">All Categories</option>' +
            Array.from(cats).sort().map(c => `<option value="${c}"${c === prev ? ' selected' : ''}>${c}</option>`).join('');
        }
        const agSel = document.getElementById('alertsFilterAgent');
        if (agSel) {
          const prev = agSel.value;
          agSel.innerHTML = '<option value="">All Agents</option>' +
            Array.from(agents).sort().map(a => `<option value="${a}"${a === prev ? ' selected' : ''}>${a}</option>`).join('');
        }
      };

      // Hunt query bar wiring
      const _applyHuntQuery = () => {
        const p = state.pagination.events;
        p.page = 1;
        fetchEvents().finally(() => {
          state.dirty.tables = true;
          state.dirty.counters = true;
          scheduleRender();
        });
      };

      document.getElementById('huntQueryApply')?.addEventListener('click', _applyHuntQuery);
      document.getElementById('huntQueryInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') _applyHuntQuery();
      });
      document.getElementById('huntFilterCategory')?.addEventListener('change', () => {
        // Tab bar follows filter
        const cat = document.getElementById('huntFilterCategory')?.value || '';
        const tabMap = { process: 'process', network: 'network', auth: 'auth', file: 'file' };
        const tabKey = tabMap[cat] || 'timeline';
        document.querySelector(`#eventsScopeTabs .tabBtn[data-key="${tabKey}"]`)?.click();
        _applyHuntQuery();
      });
      document.getElementById('huntFilterSeverity')?.addEventListener('change', _applyHuntQuery);
      document.getElementById('huntLookback')?.addEventListener('change', _applyHuntQuery);

      document.getElementById('huntQueryReset')?.addEventListener('click', () => {
        const ids = ['huntQueryInput', 'huntFilterCategory', 'huntFilterSeverity'];
        ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
        const lb = document.getElementById('huntLookback');
        if (lb) lb.value = '168';
        _applyHuntQuery();
      });

      document.getElementById('huntSaveSearch')?.addEventListener('click', async () => {
        const q = document.getElementById('huntQueryInput')?.value?.trim() || '';
        if (!q) { showToast('Enter a query before saving', 'warn'); return; }
        const cat = document.getElementById('huntFilterCategory')?.value || '';
        const sev = document.getElementById('huntFilterSeverity')?.value || '';
        const lb = document.getElementById('huntLookback')?.value || '';
        const queryStr = [q, cat ? `category:${cat}` : '', sev ? `severity:${sev}` : ''].filter(Boolean).join(' ');
        const name = prompt('Save search as:', q.substring(0, 40));
        if (!name) return;
        try {
          await apiPostJson('/api/saved_searches', { name, query: queryStr });
          showToast(`Saved: ${name}`, 'ok');
          if (typeof loadSavedSearches === 'function') loadSavedSearches();
        } catch (e) {
          showToast(`Save failed: ${e?.message || 'error'}`, 'danger');
        }
      });

      document.getElementById('toggleMapMode')?.addEventListener('click', () => {
        // Cycle: geoip <-> lan
        const m = state.mapMode || 'geoip';
        state.mapMode = (m === 'geoip') ? 'lan' : 'geoip';
        if (state.mapMode === 'lan') {
          fetchLanTopology();
          ensureLanAnimLoop();
        } else {
          ensureGeoipAvailability();
        }
        state.dirty.counters = true;
        scheduleRender();
      });

      ensureGeoipAvailability();
    }

    (function boot() {
      try {
        window.__PERCEPTA_DASH_BOOT_STARTED = Date.now();
        window.__PERCEPTA_DASH_BOOT_OK = false;
      } catch {}
      try { document.documentElement.classList.add('ui-loading'); } catch {}

      // Global error handler for uncaught errors
      window.onerror = (msg, url, line, col, err) => {
        try {
          const errMsg = String(err?.message || msg || 'Unknown error').slice(0, 150);
          const file = String(url || '').split('/').pop() || 'unknown';
          const fullMsg = `Error at ${file}:${line} - ${errMsg}`;
          console.error('[Global Error]', fullMsg, err);
          // Only show toast if showToast is available
          if (typeof showToast === 'function' && window.__PERCEPTA_DASH_BOOT_OK) {
            showToast(`${escapeHtml(fullMsg)}`, 'error');
          }
        } catch (e) {
          console.error('[Error Handler Error]', e);
        }
        return false; // Allow default error handling
      };

      // Global handler for unhandled promise rejections
      window.onunhandledrejection = (event) => {
        try {
          const reason = event.reason || event.error || {};
          const msg = String(reason?.message || reason || 'Unhandled promise rejection').slice(0, 150);
          console.error('[Unhandled Rejection]', msg, reason);
          // Only show toast if showToast is available
          if (typeof showToast === 'function' && window.__PERCEPTA_DASH_BOOT_OK) {
            showToast(`${escapeHtml(msg)}`, 'error');
          }
          event.preventDefault(); // Prevent application termination
        } catch (e) {
          console.error('[Rejection Handler Error]', e);
        }
      };

      const safe = (label, fn) => {
        try {
          const r = fn();
          // Avoid unhandled rejections killing the boot flow.
          if (r && typeof r.then === 'function') {
            r.catch((e) => {
              try { showToast(`${escapeHtml(label)} failed: ${escapeHtml(String(e?.message || e || '').slice(0, 180))}`); } catch {}
            });
          }
          return r;
        } catch (e) {
          try { showToast(`${escapeHtml(label)} failed: ${escapeHtml(String(e?.message || e || '').slice(0, 180))}`); } catch {}
          return null;
        }
      };

      safe('initTheme', () => initTheme());
      safe('restoreUiSnapshotFromServer', () => restoreUiSnapshotFromServer());
      safe('initI18n', () => initI18n());
      safe('initUi', () => initUi());
      safe('initOverviewButtons', () => initOverviewModuleButtons());
      safe('initOverviewCustomization', () => initOverviewCustomization());
      safe('updatePerformanceMode', () => updatePerformanceMode());
      safe('updateDensityMode', () => updateDensityMode());
      safe('updateNocMode', () => updateNocMode());
      safe('loadAgentOrdinals', () => loadAgentOrdinals());
      safe('restoreAgentOrdinalsFromServer', () => restoreAgentOrdinalsFromServer());
      safe('fetchEventKnowledge', () => fetchEventKnowledge());
      safe('fetchIntelStatus', () => fetchIntelStatus());
      safe('fetchWhoAmI', () => fetchWhoAmI());
      safe('setView', () => {
        const allowed = ['overview', 'alerts', 'events', 'honeypot', 'ids', 'escalations', 'settings',
          'playbooks', 'response', 'audit', 'cases', 'compliance', 'reports', 'detection',
          'assets', 'rbac', 'ioc', 'dlp', 'webhooks', 'mitre', 'soctools', 'savedsearches',
          'tenants', 'vulnerabilities'];
        const settingsDefault = String(state.settingsControlModel?.['ui.defaultView'] || '').toLowerCase();
        // Restore last-active tab across refreshes; fall back to settings default then overview.
        const lastView = (() => { try { return (localStorage.getItem('percepta.ui.lastView') || '').toLowerCase(); } catch { return ''; } })();
        const preferred = (lastView && allowed.includes(lastView)) ? lastView : (settingsDefault || 'overview');
        setView(allowed.includes(preferred) ? preferred : 'overview');
      });

      // Ensure state is hydrated before first render
      safe('ensureStateHydration', () => {
        if (!Array.isArray(state.events)) state.events = [];
        if (!Array.isArray(state.alerts)) state.alerts = [];
        if (!state.stats || typeof state.stats !== 'object') state.stats = {};
        if (!state.rate || typeof state.rate !== 'object') state.rate = { lastIngestTotal: 0, lastMs: 0 };
        return true;
      });

      // Even if refresh fails, always unlock the UI and start polling.
      Promise.resolve(safe('refreshAll', () => refreshAll()))
        .finally(() => {
          clearUiLoadingOnce();
          scheduleRender();
        });

      safe('startStream', () => startStream());
      safe('startPolling', () => startPollingFallback());
      safe('startUiSnapshotSync', () => startUiSnapshotSync());
      safe('pushUiSnapshotToServer', () => pushUiSnapshotToServer({ force: false }));

      try { window.__PERCEPTA_DASH_BOOT_OK = true; } catch {}
    })();
