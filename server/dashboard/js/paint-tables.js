    // ── Table Loading Skeleton (ISS-049) ────────────────────────────────────
    function showTableSkeleton(tbodyId, cols, rows) {
      const tbody = document.getElementById(tbodyId);
      if (!tbody) return;
      const n = rows || 5;
      const c = cols || (tbody.closest('table')?.querySelectorAll('thead th')?.length || 6);
      const frag = document.createDocumentFragment();
      for (let i = 0; i < n; i++) {
        const tr = document.createElement('tr');
        tr.className = 'table-skeleton-row';
        for (let j = 0; j < c; j++) {
          tr.appendChild(document.createElement('td'));
        }
        frag.appendChild(tr);
      }
      tbody.innerHTML = '';
      tbody.appendChild(frag);
    }

    // ── Pagination Bar (ISS-055) ────────────────────────────────────────────
    function paintPaginationBar(containerId, opts) {
      const container = document.getElementById(containerId);
      if (!container) return;
      const { total, offset, limit, onPage } = opts;
      if (!total || total <= limit) {
        container.innerHTML = '';
        return;
      }
      const currentPage = Math.floor(offset / limit) + 1;
      const totalPages = Math.ceil(total / limit);
      const hasPrev = currentPage > 1;
      const hasNext = currentPage < totalPages;

      container.innerHTML = `
        <div class="pagination-bar">
          <button class="pagination-btn" ${hasPrev ? '' : 'disabled'} data-dir="prev">&laquo; Prev</button>
          <span class="pagination-info">Page ${currentPage} of ${totalPages} &middot; ${total.toLocaleString()} total</span>
          <button class="pagination-btn" ${hasNext ? '' : 'disabled'} data-dir="next">Next &raquo;</button>
        </div>`;

      container.querySelector('[data-dir="prev"]')?.addEventListener('click', () => {
        if (hasPrev) onPage(Math.max(0, offset - limit));
      });
      container.querySelector('[data-dir="next"]')?.addEventListener('click', () => {
        if (hasNext) onPage(offset + limit);
      });
    }

    // ── Event Burst Collapsing ───────────────────────────────────────────────
    // Groups high-frequency repeated process events (e.g. sc.exe called 8x/second)
    // into a single representative row with a burst count badge.
    // Collapses events with identical (summary + process + agent) within
    // BURST_WINDOW_SEC seconds. Only collapses obvious repetition (>=3 occurrences).
    const BURST_WINDOW_SEC = 15;    // window; events farther apart start new group
    const BURST_MIN_COUNT  = 3;     // need at least 3 to consider it a burst

    function collapseEventBursts(events) {
      if (!events || events.length === 0) return events;

      const burstKey = (e) => {
        const summary = String(e?.event?.summary || e?.message || '').trim().slice(0, 120);
        const proc    = String(e?.process?.name || e?.process?.commandline || '').toLowerCase().trim().slice(0, 120);
        const agentId = String(e?.agent?.id || e?.agent_id || '').trim();
        return `${agentId}|${summary}|${proc}`;
      };

      const eventTimeSec = (e) => {
        const ts = e?.event_time || e?.ingest_time;
        if (!ts) return 0;
        const s = Number(ts?.seconds || 0);
        return s > 0 ? s : Math.floor(Date.parse(String(ts)) / 1000);
      };

      // O(n) Map-based grouping: collect all events for each key, then emit.
      const grouped = new Map();
      const result = [];

      for (const e of events) {
        const summary = String(e?.event?.summary || e?.message || '').toLowerCase();
        const isProcessCreate = summary.includes('process created') || summary.includes('process_created');

        if (!isProcessCreate) {
          result.push(e);
          continue;
        }

        const key = burstKey(e);
        const t0 = eventTimeSec(e);

        if (!grouped.has(key)) {
          grouped.set(key, { events: [], startTime: t0 });
        }

        const group = grouped.get(key);
        // Only add if within window from start of this group.
        if (Math.abs(t0 - group.startTime) <= BURST_WINDOW_SEC) {
          group.events.push(e);
        } else {
          // Time window exceeded; flush current group and start new one.
          if (group.events.length >= BURST_MIN_COUNT) {
            const rep = Object.assign({}, group.events[0], { _burstCount: group.events.length });
            result.push(rep);
          } else {
            result.push(...group.events);
          }
          grouped.set(key, { events: [e], startTime: t0 });
        }
      }

      // Flush remaining groups.
      for (const [, group] of grouped) {
        if (group.events.length >= BURST_MIN_COUNT) {
          const rep = Object.assign({}, group.events[0], { _burstCount: group.events.length });
          result.push(rep);
        } else {
          result.push(...group.events);
        }
      }

      return result;
    }
    // ─────────────────────────────────────────────────────────────────────────

    function paintTables() {
      ensureVirtualScrollBindings();

      const activeEventKey = state.selected.key;
      const activeAlertKey = state.selectedAlertKey;
      const tabs = state.subTabs || {};

      const eventInScope = (e, scope) => {
        // Always exclude agent-internal telemetry from hunt/events views
        if (isAgentInternalEvent(e)) return false;
        const s = String(scope || 'timeline');
        if (s === 'timeline') return true;
        const md = (e?.metadata && typeof e.metadata === 'object') ? e.metadata : {};
        if (s === 'process') {
          if (isIdsEvent(e)) return false;
          const processHints = [
            e?.process?.name,
            e?.process?.commandline,
            e?.process?.executable,
            e?.process?.pid,
            md['process.name'],
            md['process.command_line'],
            md['process.executable'],
            md['winlog.event_data.Image'],
            md['winlog.event_data.NewProcessName'],
            md['winlog.event_data.ParentProcessName'],
          ];
          if (processHints.some(Boolean)) return true;
          return /4688|4689|592|process|cmd\.exe|powershell|wmic|rundll32|svchost/i.test(String(getEventIdValue(e) || '') + ' ' + eventFilterText(e));
        }
        if (s === 'network') {
          const networkHints = [
            e?.network?.src_ip,
            e?.network?.dst_ip,
            e?.network?.src_port,
            e?.network?.dst_port,
            md['src_ip'],
            md['dst_ip'],
            md['source_ip'],
            md['destination_ip'],
            md['client_ip'],
            md['remote_ip'],
            md['network.src_ip'],
            md['network.dst_ip'],
            md['network.transport'],
            md['src_port'],
            md['dst_port'],
          ];
          if (networkHints.some(Boolean)) return true;
          if (isIdsEvent(e) || isHoneypotEvent(e)) return true;
          return /network|socket|dns|http|https|tcp|udp|icmp|portscan|connection/i.test(eventFilterText(e));
        }
        if (s === 'auth') {
          const txt = eventFilterText(e);
          return Boolean(getBestUser(e) || txt.includes('logon') || txt.includes('auth') || txt.includes('security-auditing'));
        }
        if (s === 'file') {
          return Boolean(isFimEvent(e) || e?.file?.path || e?.registry?.path || /4663|4656|4658|4660/.test(String(getEventIdValue(e) || '')));
        }
        return true;
      };

      const honeypotInScope = (e, scope) => {
        const s = String(scope || 'all');
        if (s === 'all') return true;
        const txt = eventFilterText(e);
        if (s === 'auth') return /login|logon|password|brute|ssh|rdp|credential/.test(txt);
        if (s === 'web') return /http|https|web|uri|path|sql|xss|lfi|rfi|phpmyadmin|wp-|admin/.test(txt);
        if (s === 'lateral') return /smb|rdp|winrm|wmic|psexec|rpc|lateral|445\b|3389\b/.test(txt);
        if (s === 'trap') return (e?.tags || []).some(t => t === 'trap');
        if (s === 'tcp') return /tcp_port|tcp.*trap/.test(txt) || (e?.metadata?.['honeypot.trap'] === 'tcp_port');
        return true;
      };

      const idsInScope = (e, scope) => {
        const s = String(scope || 'detections');
        if (s === 'detections') return true;
        const action = String(e?.event?.action || '').toLowerCase();
        const sig = String(e?.event?.summary || e?.message || '').toLowerCase();
        if (s === 'block') return /drop|reject|block|deny/.test(action) || /blocked|dropped|rejected/.test(sig);
        if (s === 'malware') return /malware|trojan|ransom|c2|command\s*and\s*control|botnet|exploit\s*kit/.test(sig);
        if (s === 'scan') return /scan|nmap|recon|sweep|portscan|probe|fingerprint/.test(sig);
        return true;
      };

      const alertInScope = (a, scope) => {
        const s = String(scope || 'queue');
        if (s === 'queue') return true;
        const st = String(a?.status || 'new').toLowerCase();
        if (s === 'investigating') return /investigat|triage|in_progress|in-progress|working/.test(st);
        if (s === 'resolved') return /resolved|closed|done|mitigated/.test(st);
        if (s === 'false_positive') return /false|benign|allow|suppress/.test(st);
        return true;
      };

      const view = String(state.view || 'overview');

      if (view === 'overview') {
        const overviewBody = document.getElementById('tblOverviewEvents');
        const allEvents = filtered(state.events, 'event');
        const sorted = applyEventSort(allEvents);
        // Overview should stay concise: show only the most recent high-severity items.
        // This prevents the card from becoming an endless scrolling table.
        const evList = sorted
          .filter((e) => {
            const s = String(severityLabel(e) || '').toLowerCase();
            return s === 'high' || s === 'critical';
          })
          .slice(0, 5);
        renderRowsSmart(
          overviewBody,
          evList,
          5,
          (e, isActive) => buildEventRowTr(e, isActive),
          (e) => eventKey(e),
          (e) => eventKey(e),
          activeEventKey,
        );
        return;
      }

      if (view === 'events') {
        const eventsBody = document.getElementById('tblEvents');
        const allEvents = filtered(state.events, 'event');
        const scope = String(tabs.events || 'timeline');
        const scoped = allEvents.filter((e) => eventInScope(e, scope));
        const evList = collapseEventBursts(applyEventSort(scoped));
        const meta = document.getElementById('eventsScopeMeta');
        if (meta) meta.textContent = `${scopeMetaText('events', scope)} • ${evList.length.toLocaleString()}/${allEvents.length.toLocaleString()}`;
        const hiCrit = evList.reduce((n, e) => {
          const s = String(severityLabel(e) || '').toLowerCase();
          return n + ((s === 'high' || s === 'critical') ? 1 : 0);
        }, 0);
        const uniqUsers = new Set(evList.map((e) => getBestUser(e)).filter(Boolean)).size;
        const uniqSrc = new Set(evList.map((e) => e?.network?.src_ip || e?.network?.dst_ip || '').filter(Boolean)).size;
        paintKpiStrip('eventsKpiStrip', [
          { k: 'kpi.total', v: allEvents.length },
          { k: 'kpi.inScope', v: evList.length },
          { k: 'kpi.highCrit', v: hiCrit },
          { k: 'kpi.uniqueUsers', v: uniqUsers },
          { k: 'kpi.uniqueSources', v: uniqSrc },
        ]);
        renderRowsSmart(
          eventsBody,
          evList,
          LIMITS.maxEvents,
          (e, isActive) => buildEventsMainRowTr(e, isActive),
          (e) => eventKey(e),
          (e) => eventKey(e),
          activeEventKey,
        );

        // ── Pagination controls (ISS-055) ──────────────────────────────────
        paintPaginationBar('eventsPagination', {
          total: state._lastSearchTotal || evList.length,
          offset: state._searchOffset || 0,
          limit: LIMITS.maxEvents,
          onPage: (newOffset) => {
            state._searchOffset = newOffset;
            if (typeof window.PerceptaData !== 'undefined' && window.PerceptaData.fetchEvents) {
              window.PerceptaData.fetchEvents(newOffset);
            }
          },
        });

        return;
      }

      if (view === 'honeypot') {
        const honeyBody = document.getElementById('tblHoneypot');
        const allHp = filtered(state.honeypot, 'event');
        const scope = String(tabs.honeypot || 'all');
        const scoped = allHp.filter((e) => honeypotInScope(e, scope));
        const hpList = applyEventSort(scoped);
        const meta = document.getElementById('honeypotScopeMeta');
        if (meta) meta.textContent = `${scopeMetaText('honeypot', scope)} • ${hpList.length.toLocaleString()}/${allHp.length.toLocaleString()}`;
        const attackers = new Set(hpList.map((e) => e?.network?.src_ip || getBestIp(e) || '').filter(Boolean)).size;
        const credN = hpList.filter((e) => /credential|canary|login|password|brute/.test(eventFilterText(e))).length;
        const trapN = hpList.filter((e) => (e?.tags || []).some(t => t === 'trap')).length;
        const tcpN = hpList.filter((e) => (e?.metadata?.['honeypot.trap'] === 'tcp_port')).length;
        const webN = hpList.filter((e) => /http|https|web|uri|path|sql|xss|lfi|rfi|phpmyadmin|wp-/.test(eventFilterText(e))).length;
        paintKpiStrip('honeypotKpiStrip', [
          { k: 'kpi.total', v: allHp.length },
          { k: 'kpi.inScope', v: hpList.length },
          { k: 'kpi.attackers', v: attackers },
          { k: 'kpi.credAttempts', v: credN },
          { k: 'kpi.trapHits', v: trapN },
          { k: 'kpi.tcpPort', v: tcpN },
          { k: 'kpi.web', v: webN },
        ]);
        // Also update the intelligence strip cards
        updateHoneypotIntelStrip(allHp);
        renderRowsSmart(
          honeyBody,
          hpList,
          LIMITS.maxEvents,
          (e, isActive) => buildHoneypotRowTr(e, isActive),
          (e) => eventKey(e),
          (e) => eventKey(e),
          activeEventKey,
        );
        return;
      }

      if (view === 'ids') {
        const idsBody = document.getElementById('tblIds');
        const allIds = filtered(state.ids, 'event');
        const scope = String(tabs.ids || 'detections');
        const scoped = allIds.filter((e) => idsInScope(e, scope));
        const idsList = applyEventSort(scoped);
        const meta = document.getElementById('idsScopeMeta');
        if (meta) meta.textContent = `${scopeMetaText('ids', scope)} · ${idsList.length.toLocaleString()}/${allIds.length.toLocaleString()} detections`;
        const blockedN = idsList.filter((e) => {
          const action = String(e?.event?.action || '').toLowerCase();
          const sig = String(e?.event?.summary || e?.message || '').toLowerCase();
          return /drop|reject|block|deny/.test(action) || /blocked|dropped|rejected/.test(sig);
        }).length;
        const malwareN = idsList.filter((e) => /malware|trojan|ransom|c2|command\s*and\s*control|botnet|exploit\s*kit/.test(String(e?.event?.summary || e?.message || '').toLowerCase())).length;
        const scanN = idsList.filter((e) => /scan|nmap|recon|sweep|portscan|probe|fingerprint/.test(String(e?.event?.summary || e?.message || '').toLowerCase())).length;

        /* KPI cards */
        const idsKpiEls = { total: 'idsKpiTotal', scope: 'idsKpiScope', blocked: 'idsKpiBlocked', malware: 'idsKpiMalware', scan: 'idsKpiScan' };
        const idsKpiVals = { total: allIds.length, scope: idsList.length, blocked: blockedN, malware: malwareN, scan: scanN };
        for (const [key, elId] of Object.entries(idsKpiEls)) {
          const el = document.getElementById(elId);
          if (el) el.textContent = Number(idsKpiVals[key]).toLocaleString();
        }

        /* Top signatures breakdown (top 6 by count) */
        const sigMap = new Map();
        for (const e of idsList.slice(0, 500)) {
          const sig = idsSignatureLabel(e);
          sigMap.set(sig, (sigMap.get(sig) || 0) + 1);
        }
        const topSigs = Array.from(sigMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
        const topSigsEl = document.getElementById('idsTopSigs');
        if (topSigsEl) {
          while (topSigsEl.firstChild) topSigsEl.removeChild(topSigsEl.firstChild);
          if (topSigs.length > 0) {
            const fragment = document.createDocumentFragment();
            for (const [name, count] of topSigs) {
              const card = document.createElement('div');
              card.className = 'ids-sig-card';

              const countEl = document.createElement('span');
              countEl.className = 'ids-sig-count';
              countEl.textContent = String(count);

              const nameEl = document.createElement('span');
              nameEl.className = 'ids-sig-name';
              nameEl.title = String(name);
              nameEl.textContent = String(name);

              card.appendChild(countEl);
              card.appendChild(nameEl);
              fragment.appendChild(card);
            }
            topSigsEl.appendChild(fragment);
          }
        }

        /* Empty state */
        const emptyEl = document.getElementById('idsEmptyState');
        const tableWrap = idsBody?.closest('.tableWrap');
        if (emptyEl && tableWrap) {
          if (idsList.length === 0) {
            tableWrap.style.display = 'none';
            emptyEl.style.display = 'flex';
          } else {
            tableWrap.style.display = '';
            emptyEl.style.display = 'none';
          }
        }

        renderRowsSmart(
          idsBody,
          idsList,
          LIMITS.maxEvents,
          (e, isActive) => buildIdsRowTr(e, isActive),
          (e) => eventKey(e),
          (e) => eventKey(e),
          activeEventKey,
        );
        return;
      }

      if (view === 'alerts') {
        const alertsBody = document.getElementById('tblAlerts');
        const allAlerts = filtered(state.alerts, 'alert');
        const scope = String(tabs.alerts || 'queue');
        const scoped = allAlerts.filter((a) => alertInScope(a, scope));
        const alList = applyAlertSort(scoped);
        const meta = document.getElementById('alertsScopeMeta');
        if (meta) meta.textContent = `${scopeMetaText('alerts', scope)} • ${alList.length.toLocaleString()}/${allAlerts.length.toLocaleString()}`;
        const stCount = (re) => alList.filter((a) => re.test(String(a?.status || 'new').toLowerCase())).length;
        const investigatingN = stCount(/investigat|triage|in_progress|in-progress|working/);
        const resolvedN = stCount(/resolved|closed|done|mitigated/);
        const falseN = stCount(/false|benign|allow|suppress/);
        const openN = Math.max(0, alList.length - resolvedN - falseN);
        paintKpiStrip('alertsKpiStrip', [
          { k: 'kpi.total', v: allAlerts.length },
          { k: 'kpi.inScope', v: alList.length },
          { k: 'kpi.open', v: openN },
          { k: 'kpi.investigating', v: investigatingN },
          { k: 'kpi.resolved', v: resolvedN },
          { k: 'kpi.falsePositive', v: falseN },
        ]);

        // Prime device labels for alert agents (best-effort) so the Agent column can
        // render stable device names by MAC when available.
        try {
          const macs = [];
          for (const a of alList.slice(0, 120)) {
            const aid = String(a?.agent_id || a?.agent?.id || '').trim();
            if (!aid) continue;
            const mac = normalizeMac(String(state.agentMacById.get(aid) || ''));
            if (mac) macs.push(mac);
          }
          if (macs.length) enqueueDeviceNameLookup(macs);
        } catch {}

        renderRowsSmart(
          alertsBody,
          alList,
          LIMITS.maxAlerts,
          (a, isActive) => buildAlertRowTr(a, isActive),
          (a) => alertKey(a),
          (a) => alertRowSig(a),
          activeAlertKey,
        );
        return;
      }
    }

    function getEventByKey(key) {
      if (!key) return null;
      const find = (arr) => arr.find((e) => eventKey(e) === key) || null;
      return find(state.events) || find(state.honeypot) || find(state.ids);
    }

    function getAlertByKey(key) {
      if (!key) return null;
      return state.alerts.find((a) => alertKey(a) === key) || null;
    }

