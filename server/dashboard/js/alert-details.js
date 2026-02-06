    function buildAlertDetailsShell(rootEl, alertObj) {
      const shell = document.createElement('div');
      shell.className = 'alertDetailsShell';

      const summary = document.createElement('div');
      summary.className = 'alertSummaryRail';

      const titleWrap = document.createElement('div');
      titleWrap.className = 'alertSummaryTitle';
      const rule = String(alertObj?.rule_name || alertObj?.rule_id || 'Alert').trim();
      const msg = String(alertObj?.message || '').trim();
      const sev = alertSeverityLabel(alertObj);
      const status = String(alertObj?.status || 'new');

      const title = document.createElement('div');
      title.className = 'alertSummaryTitleMain';
      title.textContent = rule || 'Alert';
      const subtitle = document.createElement('div');
      subtitle.className = 'alertSummaryTitleSub';
      subtitle.textContent = msg || 'No message';
      titleWrap.appendChild(title);
      titleWrap.appendChild(subtitle);

      const chips = document.createElement('div');
      chips.className = 'alertSummaryChips';
      const sevChip = document.createElement('span');
      const sevClass = String(sev || '').toLowerCase().replace(/[^a-z]/g, '') || 'info';
      sevChip.className = `sev ${sevClass}`;
      sevChip.textContent = sev;
      chips.appendChild(sevChip);

      const statusChip = document.createElement('span');
      statusChip.className = 'kpiPill';
      statusChip.innerHTML = `Status <strong>${escapeHtml(status)}</strong>`;
      chips.appendChild(statusChip);

      const tChip = document.createElement('span');
      tChip.className = 'kpiPill';
      tChip.innerHTML = `Seen <strong>${escapeHtml(formatTime(alertObj?.last_seen || alertObj?.first_seen))}</strong>`;
      chips.appendChild(tChip);

      summary.appendChild(titleWrap);

      // ─── BREADCRUMB COMPONENT ───────────────────────────────────────────
      const breadcrumbContainer = document.createElement('div');
      breadcrumbContainer.className = 'alertBreadcrumb';
      breadcrumbContainer.id = 'alertBreadcrumbContainer';
      summary.appendChild(breadcrumbContainer);
      // ─────────────────────────────────────────────────────────────────────

      summary.appendChild(chips);

      const quickActions = document.createElement('div');
      quickActions.className = 'alertSummaryActions';
      summary.appendChild(quickActions);

      const tabs = document.createElement('div');
      tabs.className = 'tabBar alertDetailsTabs';

      const paneWrap = document.createElement('div');
      paneWrap.className = 'alertDetailsPaneWrap';

      const tabDefs = [
        ['overview', 'Overview'],
        ['evidence', 'Evidence'],
        ['related', 'Related'],
        ['response', 'Response'],
        ['traceback', 'Traceback'],
        ['audit', 'Audit'],
        ['raw', 'Raw'],
      ];

      const panes = {};
      const tabButtons = {};
      const quickActionMap = new Map();

      const setTab = (tabKey) => {
        const selected = tabDefs.some(([k]) => k === tabKey) ? tabKey : 'overview';
        for (const [k] of tabDefs) {
          const pane = panes[k];
          const btn = tabButtons[k];
          if (!pane || !btn) continue;
          const active = k === selected;
          pane.classList.toggle('active', active);
          btn.classList.toggle('active', active);
          btn.setAttribute('aria-selected', active ? 'true' : 'false');
        }
        if (!state.ui) state.ui = {};
        state.ui.alertDetailsTab = selected;
      };

      for (const [key, label] of tabDefs) {
        const btn = document.createElement('button');
        btn.className = 'tabBtn';
        btn.type = 'button';
        btn.textContent = label;
        btn.setAttribute('data-alert-tab', key);
        btn.setAttribute('role', 'tab');
        btn.addEventListener('click', () => setTab(key));
        tabButtons[key] = btn;
        tabs.appendChild(btn);

        const pane = document.createElement('div');
        pane.className = 'alertDetailsPane';
        pane.setAttribute('data-alert-pane', key);
        panes[key] = pane;
        paneWrap.appendChild(pane);
      }

      shell.appendChild(summary);
      shell.appendChild(tabs);
      shell.appendChild(paneWrap);
      rootEl.appendChild(shell);

      const wantedTab = String(state?.ui?.alertDetailsTab || 'overview');
      setTab(wantedTab);
      state.alertDetailsSetTab = setTab;

      if (!state._alertDetailsHotkeysAttached) {
        state._alertDetailsHotkeysAttached = true;
        window.addEventListener('keydown', (ev) => {
          if (state.view !== 'alerts') return;
          const tag = String(document.activeElement?.tagName || '').toLowerCase();
          if (tag === 'input' || tag === 'textarea' || tag === 'select') return;

          if (ev.altKey && !ev.ctrlKey && !ev.metaKey) {
            const idx = Number(ev.key);
            if (Number.isFinite(idx) && idx >= 1 && idx <= tabDefs.length) {
              ev.preventDefault();
              const pair = tabDefs[idx - 1];
              if (pair && typeof state.alertDetailsSetTab === 'function') {
                state.alertDetailsSetTab(pair[0]);
              }
              return;
            }
          }

          if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
          const k = String(ev.key || '').toLowerCase();
          if (k === 'a' || k === 'i' || k === 'r') {
            const statusKey = k === 'a' ? 'acknowledged' : (k === 'i' ? 'investigating' : 'resolved');
            const btn = state.alertDetailsQuickActions?.get(statusKey);
            if (btn) {
              ev.preventDefault();
              btn.click();
            }
          }
        });
      }

      return {
        panes,
        setTab,
        breadcrumbContainer,
        mountQuickActions(buttons) {
          quickActions.innerHTML = '';
          quickActionMap.clear();
          for (const b of buttons || []) {
            if (!(b instanceof Node)) continue;
            quickActions.appendChild(b);
            const status = String(b.dataset.actionStatus || '').trim();
            if (status) quickActionMap.set(status, b);
          }
          state.alertDetailsQuickActions = quickActionMap;
        },
      };
    }
