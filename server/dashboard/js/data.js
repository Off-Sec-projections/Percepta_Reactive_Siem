    // ── Cache to avoid rebuilding alert details on every render tick ──
    let _paintedAlertKey = null;
    let _paintedAlertJson = null;

    function paintAlertDetails(alertObj) {
      const el = document.getElementById('alertDetails');
      if (!el) return;

      if (!alertObj) {
        _paintedAlertKey = null;
        _paintedAlertJson = null;
        clearEl(el);
        el.innerHTML = `<div class="muted">${escapeHtml(t('alerts.selectToView'))}</div>`;
        return;
      }

      // Skip full rebuild if we're already showing this exact alert data.
      const incomingKey = String(alertObj.id || alertObj.key || '');
      const incomingJson = JSON.stringify(alertObj);
      if (incomingKey && incomingKey === _paintedAlertKey && incomingJson === _paintedAlertJson) {
        return; // nothing changed — keep the existing DOM (preserves <details> open state)
      }
      _paintedAlertKey = incomingKey;
      _paintedAlertJson = incomingJson;

      clearEl(el);
      const shell = buildAlertDetailsShell(el, alertObj);
      const paneOverview = shell.panes.overview;
      const paneEvidence = shell.panes.evidence;
      const paneRelated = shell.panes.related;
      const paneResponse = shell.panes.response;
      const paneTraceback = shell.panes.traceback;
      const paneAudit = shell.panes.audit;
      const paneRaw = shell.panes.raw;

      const roleLower = String(state.auth?.status?.role || '').toLowerCase();
      const isAuthority = () => roleLower === 'authority';
      const canContain = () => (roleLower === 'authority' || roleLower === 'analyst');
      const alertId = String(alertObj.id || '').trim();

      const isIpv4 = (s) => {
        const v = String(s || '').trim();
        if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return false;
        const parts = v.split('.').map((x) => Number(x));
        return parts.length === 4 && parts.every((n) => Number.isFinite(n) && n >= 0 && n <= 255);
      };
      const isIpv6Loose = (s) => {
        const v = String(s || '').trim();
        if (!v || !v.includes(':')) return false;
        // Loose check: allow common IPv6 forms; avoid over-validating here.
        return /^[0-9a-fA-F:]{2,}$/.test(v);
      };

      const isPrivateIpv4 = (s) => {
        const v = String(s || '').trim();
        if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return false;
        const p = v.split('.').map((x) => Number(x));
        if (p.length !== 4 || p.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;
        if (p[0] === 10) return true;
        if (p[0] === 127) return true;
        if (p[0] === 169 && p[1] === 254) return true;
        if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
        if (p[0] === 192 && p[1] === 168) return true;
        if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
        if (p[0] === 0) return true;
        return false;
      };

      const extractEvidenceFieldsFromAlert = (a) => {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const evRaw = md.evidence_json || md.evidenceJson;
        if (!evRaw) return { ip: '', user: '', domain: '' };
        let ev = null;
        try { 
          ev = JSON.parse(String(evRaw)); 
        } catch (err) { 
          console.warn('[Evidence Parse Error]', err.message, 'Raw:', String(evRaw).slice(0, 100));
          ev = null; 
        }
        if (!ev || typeof ev !== 'object') return { ip: '', user: '', domain: '' };
        const conds = Array.isArray(ev.conditions) ? ev.conditions : [];
        const out = { ip: '', user: '', domain: '' };
        for (const c of conds.slice(0, 80)) {
          const field = String(c?.field || '').toLowerCase();
          const actual = String(c?.actual ?? '').trim();
          if (!actual) continue;
          if (!out.ip && (field.includes('ip') || field.includes('src') || field.includes('client'))) {
            if (isIpv4(actual) || isIpv6Loose(actual)) out.ip = actual;
          }
          if (!out.user && (field.includes('user') || field.includes('account') || field.includes('principal'))) {
            out.user = actual;
          }
          if (!out.domain && field.includes('domain')) {
            out.domain = actual;
          }
          if (out.ip && out.user) break;
        }
        return out;
      };

      const extractKvFromText = (text, key) => {
        const src = String(text || '');
        const k = String(key || '').replaceAll(/[^a-zA-Z0-9_]/g, '');
        if (!k) return '';
        const re = new RegExp(`\\b${k}\\b\\s*[:=]\\s*([^\\n\\r]+)`, 'i');
        const m = re.exec(src);
        if (!m || !m[1]) return '';
        let v = String(m[1]).trim();
        // Stop if another key=value begins after this.
        const nextKeyIdx = v.search(/\s+[A-Za-z_]{2,24}\s*=/);
        if (nextKeyIdx > 0) v = v.slice(0, nextKeyIdx).trim();
        // Cut off common separators.
        v = v.split(';')[0].split(',')[0].trim();
        v = v.replace(/^['"]+|['"]+$/g, '').trim();
        return v;
      };

      const extractIpFromAlert = (a) => {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const keys = [
          'src_ip', 'source_ip', 'client_ip', 'remote_ip', 'attacker_ip',
          'ip',
          'norm.src_ip', 'norm.client_ip',
          'src.ip', 'client.ip', 'source.ip',
        ];
        const candidates = [];
        for (const k of keys) {
          const v = md[k];
          if (!v) continue;
          const s = String(v).trim();
          if (!s) continue;
          if (isIpv4(s) || isIpv6Loose(s)) candidates.push(s);
        }
        const publicFirst = candidates.find((ip) => isIpv6Loose(ip) || !isPrivateIpv4(ip));
        if (publicFirst) return publicFirst;
        if (candidates.length) return candidates[0];

        const ev = extractEvidenceFieldsFromAlert(a);
        if (ev.ip) return ev.ip;

        const msg = String(a?.message || '');
        const msgKeys = ['src_ip', 'source_ip', 'client_ip', 'remote_ip', 'attacker_ip', 'ip'];
        for (const k of msgKeys) {
          const v = extractKvFromText(msg, k);
          if (isIpv4(v) || isIpv6Loose(v)) return v;
        }
        // Last resort: first IP-looking token.
        const m4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(msg);
        if (m4 && isIpv4(m4[0])) return m4[0];
        const m6 = /\b[0-9a-fA-F:]{2,}\b/.exec(msg);
        if (m6 && isIpv6Loose(m6[0])) return m6[0];
        return '';
      };

      const extractUserFromAlert = (a) => {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const pick = (k) => {
          const v = md[k];
          return v != null ? String(v).trim() : '';
        };

        // Prefer server normalization when present.
        const nu = pick('norm.user') || pick('metadata.norm.user');
        const nd = pick('norm.user_domain') || pick('metadata.norm.user_domain');
        if (nu) return nd ? `${nd}\\${nu}` : nu;

        const keys = [
          'user', 'username', 'account', 'account_name', 'target_user',
          'user.name', 'account.name', 'principal',
        ];
        for (const k of keys) {
          const v = md[k];
          if (!v) continue;
          const s = String(v).trim();
          if (s) return s;
        }

        const ev = extractEvidenceFieldsFromAlert(a);
        if (ev.user) return ev.domain ? `${ev.domain}\\${ev.user}` : ev.user;

        const msg = String(a?.message || '');
        const fromMsg = (
          extractKvFromText(msg, 'username') ||
          extractKvFromText(msg, 'user') ||
          extractKvFromText(msg, 'account')
        );
        if (fromMsg) return fromMsg;

        return '';
      };

      const isSystemOrServicePrincipal = (s) => {
        const n = String(s || '').trim().toLowerCase();
        if (!n) return false;
        if (n === 'system' || n === 'local system') return true;
        if (n === 'nt authority\\system') return true;
        if (n === 'nt authority\\local service' || n === 'local service') return true;
        if (n === 'nt authority\\network service' || n === 'network service') return true;
        return false;
      };

      const isMachineAccount = (s) => {
        const raw = String(s || '').trim();
        if (!raw) return false;
        const user = raw.split('\\').pop().split('/').pop().trim();
        return user.endsWith('$');
      };

      const isUuidLike = (s) => {
        const t = String(s || '').trim();
        if (!t) return false;
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(t);
      };

      const isSidLike = (s) => {
        const t = String(s || '').trim();
        if (!t) return false;
        return /^S-\d-\d+(?:-\d+)+$/i.test(t);
      };

      const normalizeEndpointUsername = (s) => {
        const raw = String(s || '').trim();
        if (!raw) return '';
        // Agent-side logoff/disable uses Windows commands that generally want the account name,
        // not DOMAIN\\user. `query user` also typically shows just the username.
        const short = raw.split('\\').pop().split('/').pop().trim();
        if (!short) return '';
        if (short.toLowerCase() === 'unknown') return '';
        if (isUuidLike(short) || isSidLike(short)) return '';
        return short;
      };

      const extractInteractiveUserFromAlert = (a) => {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const pick = (k) => {
          const v = md[k];
          return v != null ? String(v).trim() : '';
        };

        const accept = (candidate) => {
          const v = String(candidate || '').trim();
          if (!v) return '';
          if (v.toLowerCase() === 'unknown') return '';
          if (isSystemOrServicePrincipal(v)) return '';
          if (isMachineAccount(v)) return '';
          if (isUuidLike(v) || isSidLike(v)) return '';
          return v;
        };

        // 1) Prefer an explicit interactive hint if present.
        const cu = accept(pick('current_user') || pick('metadata.current_user'));
        if (cu) return cu;

        // 2) Then take the best-effort extracted user (may include norm.user).
        const u0 = accept(extractUserFromAlert(a));
        if (u0) return u0;

        // 3) Additional keys that sometimes carry interactive usernames.
        const keys = [
          'winlog.event_data.targetusername',
          'winlog.event_data.subjectusername',
          'targetusername',
          'subjectusername',
          'user',
          'username',
          'account',
          'account_name',
          'target_user',
          'user.name',
          'account.name',
          'principal',
        ];
        for (const k of keys) {
          const v = accept(pick(k));
          if (v) return v;
        }

        const ev = extractEvidenceFieldsFromAlert(a);
        const evUser = accept(ev.user ? (ev.domain ? `${ev.domain}\\${ev.user}` : ev.user) : '');
        if (evUser) return evUser;
        return '';
      };

      const buildFieldQualityBadge = () => {
        const missing = [];
        const ip = extractIpFromAlert(alertObj);
        const user = extractInteractiveUserFromAlert(alertObj);
        const agentId = String(alertObj?.agent_id || alertObj?.agent?.id || '').trim();
        if (!agentId) missing.push('agent');
        if (!ip) missing.push('src_ip');
        if (!user) missing.push('user');
        const badge = document.createElement('span');
        badge.className = `badge ${missing.length ? 'warn' : ''}`;
        badge.textContent = missing.length ? `Missing: ${missing.join(', ')}` : 'Forensics: OK';
        return badge;
      };

      const header = document.createElement('div');
      header.className = 'kv';
      header.append(...kvRow(t('label.rule'), alertObj?.rule_name || alertObj?.rule_id || ''));
      header.append(...kvRow(t('label.severity'), alertSeverityLabel(alertObj)));
      header.append(...kvRow('Risk Score', String(alertRiskScore(alertObj))));
      header.append(...kvRow(t('label.status'), alertObj?.status || 'new'));
      header.append(...kvRow(t('label.agent'), agentIdentityLabelForAlert(alertObj) || alertObj?.agent_hostname || alertObj?.agent_id || ''));
      header.append(...kvRow(t('label.lastSeen'), formatTime(alertObj?.last_seen || alertObj?.first_seen)));
      header.append(...kvRow(t('label.message'), alertObj?.message || ''));
      header.append(...kvRow('Forensics', buildFieldQualityBadge()));

      // MITRE ATT&CK badges
      {
        const md = (alertObj && alertObj.metadata && typeof alertObj.metadata === 'object') ? alertObj.metadata : {};
        const tactics = String(md.mitre_tactics || '').split(',').map(s => s.trim()).filter(Boolean);
        const techniques = String(md.mitre_attack || '').split(',').map(s => s.trim()).filter(Boolean);
        if (tactics.length || techniques.length) {
          const mitreWrap = document.createElement('span');
          mitreWrap.style.display = 'flex';
          mitreWrap.style.flexWrap = 'wrap';
          mitreWrap.style.gap = '4px';
          for (const tac of tactics) {
            const b = document.createElement('span');
            b.className = 'badge';
            b.style.background = 'var(--accent, #4f8cff)';
            b.style.color = '#fff';
            b.style.fontSize = '11px';
            b.textContent = tac;
            mitreWrap.appendChild(b);
          }
          for (const tech of techniques) {
            const b = document.createElement('a');
            b.className = 'badge';
            b.style.background = 'var(--surface2, #333)';
            b.style.color = 'var(--fg, #eee)';
            b.style.fontSize = '11px';
            b.style.textDecoration = 'none';
            b.href = 'https://attack.mitre.org/techniques/' + encodeURIComponent(tech.replace('.', '/')) + '/';
            b.target = '_blank';
            b.rel = 'noopener noreferrer';
            b.textContent = tech;
            mitreWrap.appendChild(b);
          }
          header.append(...kvRow('MITRE ATT&CK', mitreWrap));
        }
      }

      paneOverview.appendChild(header);

      // Fusion: show other signals correlated to this alert pattern/event.
      {
        const key = getRelatedSignalsKeyFromAlert(alertObj);
        const agentId = String(alertObj?.agent_id || alertObj?.agent?.id || '').trim();
        paneRelated.appendChild(buildRelatedSignalsSection({ key, agentId, title: t('relatedSignals.title'), lookbackHours: 24, limit: 25 }));
      }

      // Evidence (why the alert fired)
      const evRaw = alertObj?.metadata && (alertObj.metadata.evidence_json || alertObj.metadata.evidenceJson);
      if (evRaw) {
        const sec = document.createElement('div');
        sec.className = 'section';
        sec.innerHTML = `<h3>${escapeHtml(t('alerts.whyFired'))}</h3>`;

        let ev = null;
        try { ev = JSON.parse(String(evRaw)); } catch { ev = null; }

        if (!ev || typeof ev !== 'object') {
          const m = document.createElement('div');
          m.className = 'muted';
          m.textContent = t('alerts.evidenceUnavailable');
          sec.appendChild(m);
        } else {
          const threshold = ev.threshold;
          const groupKey = ev.group_key;
          if (threshold && typeof threshold === 'object') {
            const thDiv = document.createElement('div');
            thDiv.className = 'muted text-12';
            const cnt = threshold.count ?? '';
            const win = threshold.window_seconds ?? '';
            thDiv.textContent = t('alerts.threshold', { cnt, win, group: groupKey ? String(groupKey) : '' });
            sec.appendChild(thDiv);
          }

          const conds = Array.isArray(ev.conditions) ? ev.conditions : [];
          if (!conds.length) {
            const m = document.createElement('div');
            m.className = 'muted';
            m.textContent = t('alerts.noConditionDetails');
            sec.appendChild(m);
          } else {
            const wrap = document.createElement('div');
            wrap.className = 'tableWrap maxh-250';
            const table = document.createElement('table');
            table.innerHTML = `<thead><tr>
              <th width="210">${escapeHtml(t('tbl.field'))}</th>
              <th width="120">${escapeHtml(t('tbl.op'))}</th>
              <th>${escapeHtml(t('tbl.expected'))}</th>
              <th>${escapeHtml(t('tbl.actual'))}</th>
            </tr></thead>`;
            const tbody = document.createElement('tbody');
            for (const c of conds.slice(0, 50)) {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td class="mono">${escapeHtml(String(c.field || ''))}</td>
                <td>${escapeHtml(String(c.operator || ''))}</td>
                <td class="mono">${escapeHtml(String(c.expected ?? ''))}</td>
                <td class="mono">${escapeHtml(String(c.actual ?? ''))}</td>`;
              tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
            sec.appendChild(wrap);
          }
        }

        paneEvidence.appendChild(sec);
      }

      // ─────────────────────────────────────────────────────────────────────
      // ALERT TIMELINE CHART (event correlation timeline)
      // ─────────────────────────────────────────────────────────────────────
      {
        const timelineEvents = [];

        // Add the alert itself as a node
        const alertTs = Number(alertObj?.first_seen ? new Date(alertObj.first_seen).getTime() : 0);
        const alertLastTs = Number(alertObj?.last_seen ? new Date(alertObj.last_seen).getTime() : 0);
        if (alertTs) timelineEvents.push({ ts: alertTs, label: 'Alert first seen', kind: 'alert', icon: '⚡' });
        if (alertLastTs && alertLastTs !== alertTs) timelineEvents.push({ ts: alertLastTs, label: 'Alert last seen', kind: 'alert-end', icon: '⚡' });

        // Source events
        const srcEvts = Array.isArray(alertObj?.source_events) ? alertObj.source_events : [];
        for (let i = 0; i < Math.min(srcEvts.length, 20); i++) {
          const ev = srcEvts[i];
          if (!ev || typeof ev !== 'object') continue;
          const evTs = Number(ev.ts_unix ? ev.ts_unix * 1000 : ev.ts ? new Date(ev.ts).getTime() : 0);
          if (!evTs) continue;
          const kind = String(ev.kind || ev.type || ev.category || '').toLowerCase();
          const icon = kind.includes('auth') ? '🔑' : kind.includes('net') ? '🌐' : kind.includes('proc') ? '⚙' : kind.includes('file') ? '📄' : '•';
          timelineEvents.push({ ts: evTs, label: String(ev.message || ev.kind || ev.type || `Event ${i + 1}`), kind: 'event', icon });
        }

        // Metadata events (if any structured log entries)
        const md = alertObj?.metadata || {};
        if (md.last_activity_ts) {
          const lts = Number(new Date(String(md.last_activity_ts)).getTime());
          if (lts) timelineEvents.push({ ts: lts, label: 'Last activity', kind: 'activity', icon: '📍' });
        }

        timelineEvents.sort((a, b) => a.ts - b.ts);

        if (timelineEvents.length >= 1) {
          const tlSec = document.createElement('div');
          tlSec.className = 'section';
          tlSec.innerHTML = '<h3>Event Timeline</h3>';

          const minTs = timelineEvents[0].ts;
          const maxTs = timelineEvents[timelineEvents.length - 1].ts;
          const span = Math.max(maxTs - minTs, 1);

          const tlWrap = document.createElement('div');
          tlWrap.className = 'alert-timeline';
          tlWrap.style.cssText = 'position:relative;padding:8px 0 24px;overflow:hidden;';

          // Draw the horizontal axis line
          const axisLine = document.createElement('div');
          axisLine.style.cssText = 'position:absolute;top:20px;left:0;right:0;height:2px;background:var(--surface3,#2a2a2a);';
          tlWrap.appendChild(axisLine);

          for (const ev of timelineEvents) {
            const pct = ((ev.ts - minTs) / span) * 100;
            const dot = document.createElement('div');
            const isAlert = ev.kind.startsWith('alert');
            dot.style.cssText = `position:absolute;left:${pct.toFixed(2)}%;top:12px;transform:translateX(-50%);cursor:pointer;user-select:none;`;
            dot.innerHTML = `<div style="width:16px;height:16px;border-radius:50%;background:${isAlert ? 'var(--accent-red,#e05252)' : 'var(--accent,#4f8cff)'};display:flex;align-items:center;justify-content:center;font-size:10px;border:2px solid var(--surface,#1a1a1a);" title="${escapeHtml(ev.label + '\n' + new Date(ev.ts).toLocaleString())}">${ev.icon}</div><div style="position:absolute;top:20px;left:50%;transform:translateX(-50%);white-space:nowrap;font-size:10px;color:var(--fg-muted,#888);max-width:80px;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(ev.label)}">${escapeHtml(ev.label.substring(0, 12))}</div>`;
            tlWrap.appendChild(dot);
          }

          // Time labels
          const t0Label = document.createElement('div');
          t0Label.style.cssText = 'position:absolute;bottom:0;left:0;font-size:10px;color:var(--fg-muted,#888);';
          t0Label.textContent = new Date(minTs).toLocaleTimeString();
          tlWrap.appendChild(t0Label);

          if (maxTs !== minTs) {
            const t1Label = document.createElement('div');
            t1Label.style.cssText = 'position:absolute;bottom:0;right:0;font-size:10px;color:var(--fg-muted,#888);text-align:right;';
            t1Label.textContent = new Date(maxTs).toLocaleTimeString();
            tlWrap.appendChild(t1Label);
          }

          tlSec.appendChild(tlWrap);

          // Event list below timeline
          const evList = document.createElement('div');
          evList.className = 'tableWrap maxh-200';
          evList.style.marginTop = '8px';
          const evTable = document.createElement('table');
          evTable.innerHTML = `<thead><tr><th width="150">Time</th><th width="80">Type</th><th>Description</th></tr></thead>`;
          const evTbody = document.createElement('tbody');
          for (const ev of timelineEvents) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td class="mono text-xs">${escapeHtml(new Date(ev.ts).toLocaleString())}</td><td>${escapeHtml(ev.icon + ' ' + ev.kind)}</td><td>${escapeHtml(ev.label.substring(0, 120))}</td>`;
            evTbody.appendChild(tr);
          }
          evTable.appendChild(evTbody);
          evList.appendChild(evTable);
          tlSec.appendChild(evList);

          paneEvidence.appendChild(tlSec);
        }
      }

      // ─────────────────────────────────────────────────────────────────────
      // EXPORT EVIDENCE BUTTON
      // ─────────────────────────────────────────────────────────────────────
      {
        const exportSec = document.createElement('div');
        exportSec.className = 'section';

        const exportRow = document.createElement('div');
        exportRow.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:4px;';

        const exportPdfBtn = document.createElement('button');
        exportPdfBtn.className = 'btn sm';
        exportPdfBtn.textContent = '📄 Export Evidence PDF';
        exportPdfBtn.onclick = () => exportAlertEvidencePdf(alertObj);

        const exportCsvBtn = document.createElement('button');
        exportCsvBtn.className = 'btn sm';
        exportCsvBtn.textContent = '📊 Export CSV';
        exportCsvBtn.onclick = () => exportAlertEvidenceCsv(alertObj);

        exportRow.appendChild(exportPdfBtn);
        exportRow.appendChild(exportCsvBtn);
        exportSec.appendChild(exportRow);
        paneEvidence.appendChild(exportSec);
      }

      const actions = document.createElement('div');
      actions.className = 'section';
      actions.innerHTML = `<h3>${escapeHtml(t('section.actions'))}</h3>`;
      const btnRow = document.createElement('div');
      btnRow.className = 'row-inline-wrap';

      const setStatusBtn = (label, status, cls = 'btn sm') => {
        const b = document.createElement('button');
        b.className = cls;
        b.textContent = label;
        b.dataset.actionStatus = String(status || '');
        b.onclick = async () => {
          try {
            await apiRequestJson(`/api/alerts/${encodeURIComponent(alertObj.id)}/status`, {
              method: 'POST',
              bodyObj: { status },
              timeoutMs: 2500,
            });
            showToast(t('toast.alertUpdated', { status: escapeHtml(status) }));
            await fetchAlerts();
            state.dirty.tables = true;
            scheduleRender();
          } catch (err) {
            handleActionError(err, label);
          }
        };
        return b;
      };

      const removeBtn = document.createElement('button');
      removeBtn.className = 'btn sm';
      removeBtn.textContent = t('btn.remove');
      removeBtn.onclick = async () => {
        if (!(await uiConfirm(t('confirm.removeAlert'), { danger: true }))) return;
        try {
          await apiRequestJson(`/api/alerts/${encodeURIComponent(alertObj.id)}`, { method: 'DELETE', timeoutMs: 2500 });
          showToast(t('toast.alertRemoved'));
          state.selectedAlertKey = null;
          await fetchAlerts();
          state.dirty.tables = true;
          state.dirty.details = true;
          scheduleRender();
        } catch (err) {
          handleActionError(err, t('btn.remove'));
        }
      };

      const clearAllBtn = document.createElement('button');
      clearAllBtn.className = 'btn sm';
      clearAllBtn.textContent = t('btn.clearAllAlerts');
      clearAllBtn.onclick = async () => {
        if (!(await uiConfirm(t('confirm.clearAllAlerts'), { danger: true }))) return;
        try {
          await apiRequestJson('/api/alerts/clear', { method: 'POST', bodyObj: {}, timeoutMs: 3000 });
          showToast(t('toast.alertsCleared'));
          state.selectedAlertKey = null;
          await fetchAlerts();
          state.dirty.tables = true;
          state.dirty.details = true;
          scheduleRender();
        } catch (err) {
          handleActionError(err, t('btn.clearAllAlerts'));
        }
      };

      const ackBtn = setStatusBtn(t('btn.ack'), 'acknowledged');
      const invBtn = setStatusBtn(t('btn.investigating'), 'investigating');
      const resBtn = setStatusBtn(t('btn.resolved'), 'resolved', 'btn sm primary');
      const fpBtn = setStatusBtn(t('btn.falsePositive'), 'false_positive');

      btnRow.appendChild(ackBtn);
      btnRow.appendChild(invBtn);
      btnRow.appendChild(resBtn);
      btnRow.appendChild(fpBtn);

      // ─────────────────────────────────────────────────────────────────────
      // CONTEXTUAL ACTION BUTTONS (extracted from alert data)
      // ─────────────────────────────────────────────────────────────────────
      const contextualButtons = [];

      // Extract contextual data from alert
      const alertIp = extractIpFromAlert(alertObj);
      const alertUser = extractUserFromAlert(alertObj);
      const alertHostname = String(alertObj?.agent_hostname || '').trim();

      // Block IP button (if IP available)
      if (alertIp && isIpv4(alertIp)) {
        const blockIpBtn = document.createElement('button');
        blockIpBtn.className = 'btn sm danger';
        blockIpBtn.innerHTML = `⛔ Block IP&nbsp;<code>${escapeHtml(alertIp.substring(0, 20))}</code>`;
        blockIpBtn.title = `Block ${escapeHtml(alertIp)} from accessing honeypot`;
        blockIpBtn.onclick = async () => {
          const reason = prompt(`Block IP ${escapeHtml(alertIp)}?\nEnter reason (5+ chars required):`, '');
          if (!reason || reason.length < 5) return;
          try {
            await apiPostJson('/api/honeypot/block', { ip: alertIp, ttl_seconds: 3600 });
            showToast(`Blocked ${escapeHtml(alertIp)} for 1 hour`);
          } catch (err) {
            handleActionError(err, `Block IP ${alertIp}`);
          }
        };
        contextualButtons.push(blockIpBtn);
      }

      // Block User button (if user available and not system account)
      if (alertUser && !isSystemOrServicePrincipal(alertUser) && !isMachineAccount(alertUser)) {
        const blockUserBtn = document.createElement('button');
        blockUserBtn.className = 'btn sm warn';
        blockUserBtn.innerHTML = `🔒 Disable&nbsp;<code>${escapeHtml(alertUser.substring(0, 20))}</code>`;
        blockUserBtn.title = `Disable user ${escapeHtml(alertUser)} account`;
        blockUserBtn.onclick = async () => {
          const reason = prompt(`Disable user ${escapeHtml(alertUser)}?\nEnter reason (5+ chars required):`, '');
          if (!reason || reason.length < 5) return;
          try {
            await apiPostJson('/api/playbook/execute', {
              playbook_id: 'disable-user',
              context: { value: alertUser, reason },
            });
            showToast(`User ${escapeHtml(alertUser)} disabled`);
          } catch (err) {
            handleActionError(err, `Disable user ${alertUser}`);
          }
        };
        contextualButtons.push(blockUserBtn);
      }

      // Create Case button (pre-filled with alert context)
      const createCaseBtn = document.createElement('button');
      createCaseBtn.className = 'btn sm primary';
      createCaseBtn.textContent = '📋 Create Case';
      createCaseBtn.title = 'Create a new case with pre-filled alert context';
      createCaseBtn.onclick = async () => {
        if (createCaseBtn.disabled) return;
        createCaseBtn.disabled = true;
        const caseContext = {
          title: `Case for: ${String(alertObj?.rule_name || alertObj?.message || 'Alert')}`,
          description: `Incident triggered by alert ${String(alertId || 'N/A')}\n\nIP: ${alertIp || 'N/A'}\nUser: ${alertUser || 'N/A'}\nHost: ${alertHostname || 'N/A'}`,
          severity: alertObj?.severity || 'medium',
          related_alert_id: alertId,
          alert_ids: alertId ? [alertId] : [],
        };
        try {
          if (typeof window.createCaseFromAlertContext === 'function') {
            await window.createCaseFromAlertContext(caseContext);
            return;
          }
          if (typeof window.openCreateCaseModal === 'function') {
            await window.openCreateCaseModal(caseContext);
            return;
          }
          const created = await apiPostJson('/api/cases', caseContext);
          showToast('Case created', 'ok');
          if (created?.id && typeof window.openCaseDetailById === 'function') {
            await window.openCaseDetailById(created.id);
          }
        } catch {
          showToast('Failed to create case', 'error');
        } finally {
          createCaseBtn.disabled = false;
        }
      };
      contextualButtons.push(createCaseBtn);

      // Search Events button (pivot to events with filters)
      const searchEventsBtn = document.createElement('button');
      searchEventsBtn.className = 'btn sm';
      searchEventsBtn.textContent = '🔍 Search Events';
      searchEventsBtn.title = 'Pivot to Events view with same context filters';
      searchEventsBtn.onclick = () => {
        // Store filter context for event view
        if (state.ui) {
          state.ui.eventSearchContext = {
            alertId,
            hostname: alertHostname,
            ip: alertIp,
            user: alertUser,
          };
        }
        setView('events');
        scheduleRender();
      };
      contextualButtons.push(searchEventsBtn);

      // ─────────────────────────────────────────────────────────────────────

      shell.mountQuickActions([
        setStatusBtn(t('btn.ack'), 'acknowledged'),
        setStatusBtn(t('btn.investigating'), 'investigating'),
        setStatusBtn(t('btn.resolved'), 'resolved', 'btn sm primary'),
        ...contextualButtons, // Add contextual buttons after status buttons
      ]);

      const suppress24hBtn = document.createElement('button');
      suppress24hBtn.className = 'btn sm';
      suppress24hBtn.textContent = t('btn.suppress24h');
      suppress24hBtn.onclick = async () => {
        try {
          await apiRequestJson(`/api/alerts/${encodeURIComponent(alertObj.id)}/suppress`, {
            method: 'POST',
            bodyObj: { seconds: 86400 },
            timeoutMs: 3000,
          });
          showToast(t('toast.suppressed24h'));
        } catch (err) {
          handleActionError(err, t('btn.suppress24h'));
        }
      };

      const allowlistBtn = document.createElement('button');
      allowlistBtn.className = 'btn sm';
      allowlistBtn.textContent = t('btn.allowlistExpected');
      allowlistBtn.onclick = async () => {
        if (!(await uiConfirm(t('confirm.allowlistExpected'), { danger: true }))) return;
        try {
          await apiRequestJson(`/api/alerts/${encodeURIComponent(alertObj.id)}/allowlist`, {
            method: 'POST',
            bodyObj: {},
            timeoutMs: 3000,
          });
          showToast(t('toast.allowlisted'));
        } catch (err) {
          handleActionError(err, t('btn.allowlistExpected'));
        }
      };

      const disableRuleBtn = document.createElement('button');
      disableRuleBtn.className = 'btn sm danger';
      disableRuleBtn.textContent = t('btn.disableRuleForAgent');
      disableRuleBtn.onclick = async () => {
        if (!(await uiConfirm(t('confirm.disableRuleForAgent'), { danger: true }))) return;
        try {
          await apiRequestJson(`/api/alerts/${encodeURIComponent(alertObj.id)}/disable_rule_for_agent`, {
            method: 'POST',
            bodyObj: {},
            timeoutMs: 3000,
          });
          showToast(t('toast.ruleDisabledForAgent'));
        } catch (err) {
          handleActionError(err, t('btn.disableRuleForAgent'));
        }
      };

      const danger = document.createElement('details');
      danger.className = 'dangerActions';
      const dsum = document.createElement('summary');
      dsum.textContent = 'High-impact controls';
      danger.appendChild(dsum);
      const drow = document.createElement('div');
      drow.className = 'actionGrid';
      drow.style.marginTop = '8px';
      drow.appendChild(suppress24hBtn);
      drow.appendChild(allowlistBtn);
      drow.appendChild(disableRuleBtn);
      drow.appendChild(removeBtn);
      if (isAuthority()) drow.appendChild(clearAllBtn);
      danger.appendChild(drow);
      const escBtn = document.createElement('button');
      escBtn.className = 'btn primary';
      escBtn.textContent = t('btn.escalate');
      escBtn.onclick = async () => {
        try {
          const id = await escalateAlert(alertObj);
          if (id) showToast(`Escalation submitted (id: ${escapeHtml(id)}). Check <a href="/analyst">/analyst</a>.`, undefined, undefined, { html: true });
          else showToast('Escalation submitted. Check <a href="/analyst">/analyst</a>.', undefined, undefined, { html: true });
        } catch (err) {
          handleActionError(err, 'Escalate');
        }
      };
      btnRow.appendChild(escBtn);
      actions.appendChild(danger);
      actions.appendChild(btnRow);
      paneOverview.appendChild(actions);

      // Response drawer (endpoint + containment + enrichment + notes)
      const responseDrawer = document.createElement('div');
      responseDrawer.className = 'section drawer';
      responseDrawer.innerHTML = '<h3>Response</h3>';
      const responseTabs = document.createElement('div');
      responseTabs.className = 'tabBar';
      const responseBody = document.createElement('div');

      const tabKeys = [
        { key: 'endpoint', label: 'Endpoint' },
        { key: 'containment', label: 'Containment' },
        { key: 'enrichment', label: 'Enrichment' },
        { key: 'notes', label: 'Notes' },
      ];

      const setResponseTab = (key) => {
        const panes = responseBody.querySelectorAll('.responsePane');
        panes.forEach((p) => p.classList.toggle('hidden', p.getAttribute('data-tab') !== key));
        responseTabs.querySelectorAll('.tabBtn').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === key));
        if (!state.ui) state.ui = {};
        state.ui.responseTab = key;
      };

      for (const t of tabKeys) {
        const btn = document.createElement('button');
        btn.className = 'tabBtn';
        btn.textContent = t.label;
        btn.setAttribute('data-tab', t.key);
        btn.addEventListener('click', () => setResponseTab(t.key));
        responseTabs.appendChild(btn);
      }

      responseDrawer.appendChild(responseTabs);
      responseDrawer.appendChild(responseBody);

      // Reactive behaviours (endpoint response via agent command channel)
      const reactiveEndpointSec = document.createElement('div');
      reactiveEndpointSec.className = 'section responsePane';
      reactiveEndpointSec.setAttribute('data-tab', 'endpoint');
      reactiveEndpointSec.innerHTML = '<h3>Endpoint response</h3>';

      const role = String(state.auth?.status?.role || '').toLowerCase();
      if (role !== 'authority') {
        const m = document.createElement('div');
        m.className = 'muted';
        m.textContent = 'Endpoint response actions require Authority role.';
        reactiveEndpointSec.appendChild(m);
      } else {
        const meta = alertObj?.metadata || {};
        const pickFirst = (keys) => {
          for (const k of keys) {
            const v = meta[k];
            if (v != null && String(v).trim()) return String(v).trim();
          }
          return '';
        };
        const srcIp = extractIpFromAlert(alertObj) || pickFirst(['src_ip', 'source_ip', 'ip', 'remote_ip', 'attacker_ip']);
        const userRaw = extractInteractiveUserFromAlert(alertObj) || pickFirst(['user', 'username', 'account', 'account_name', 'target_user']);
        const user = normalizeEndpointUsername(userRaw);
        const agentId = String(alertObj?.agent_id || alertObj?.agent?.id || pickFirst(['agent_id', 'agent', 'agentId'])).trim();

        const row = document.createElement('div');
        row.className = 'actionGrid hidden';

        // Per-session toggle state for endpoint actions.
        if (!state.reactiveToggles) state.reactiveToggles = new Map();
        const tkey = (kind, val) => `${alertId || ''}|${kind}|${String(val || '').trim()}`;

        const statusLine = document.createElement('div');
        statusLine.className = 'muted';
        statusLine.style.marginTop = '8px';

        const statusChip = document.createElement('span');
        statusChip.className = 'badge';
        statusChip.textContent = 'idle';

        const statusLabel = (code) => {
          // ResultStatus: 1 started, 2 succeeded, 3 failed, 4 heartbeat
          if (code === 1) return 'started';
          if (code === 2) return 'succeeded';
          if (code === 3) return 'failed';
          if (code === 4) return 'heartbeat';
          return 'unknown';
        };

        const dispatch = async (kind, value, ttlSeconds) => {
          if (!agentId) {
            showToast('No agent id found for this alert; cannot run endpoint response.');
            return null;
          }

          // Endpoint response is delivered over the agent response channel, which can be disconnected
          // even while ingestion is healthy. Prefer a clear message before attempting dispatch.
          const respIds = Array.isArray(state?.stats?.response_connected_agent_ids) ? state.stats.response_connected_agent_ids : null;
          if (respIds && respIds.length && !respIds.includes(agentId)) {
            showToast(
              `Agent is not connected to endpoint-response channel (agent_id=${escapeHtml(agentId)}). ` +
              'Ensure the agent is running and can reach gRPC on port 50051.'
            );
            return null;
          }

          const res = await apiRequestJson('/api/reactive/dispatch', {
            method: 'POST',
            bodyObj: {
              agent_id: agentId,
              kind,
              value: value || null,
              ttl_seconds: ttlSeconds || 0,
              reason: `from alert ${alertId || ''}`,
              context_alert_id: alertId || null,
            },
            timeoutMs: 3500,
          }).catch((err) => {
            // 409 is used when the agent isn't connected to the response channel.
            if (err?.status === 409) {
              showToast(
                `Endpoint action failed: agent not connected to response channel (agent_id=${escapeHtml(agentId)}). ` +
                'Check /api/stats → response_connected_agent_ids and verify gRPC connectivity.'
              );
              return null;
            }
            throw err;
          });
          if (!res) return null;
          return String(res?.command_id || '').trim();
        };

        const poll = async (commandId) => {
          if (!commandId) return;
          for (let i = 0; i < 60; i++) {
            const st = await apiFetchJson(`/api/reactive/command/${encodeURIComponent(commandId)}`, { timeoutMs: 3000, headers: { 'Accept': 'application/json' } });
            const s = statusLabel(Number(st?.status));
            statusLine.textContent = `Endpoint action ${commandId.slice(0, 8)}…: ${s}${st?.message ? ' — ' + String(st.message) : ''}`;
            statusChip.textContent = s;

            if (s === 'succeeded' || s === 'failed') {
              if (s === 'succeeded' && st?.has_artifact) {
                try {
                  const r = await fetch(`/api/reactive/command/${encodeURIComponent(commandId)}/artifact`, { credentials: 'same-origin' });
                  if (r.ok) {
                    const blob = await r.blob();
                    downloadBlob(st?.artifact_name || `percepta_${commandId}.zip`, blob);
                    showToast('Triage bundle downloaded.');
                  } else {
                    showToast('Failed to download artifact: ' + r.statusText, 'error');
                  }
                } catch (e) {
                  showToast('Artifact download failed: ' + (e?.message || 'Network error'), 'error');
                }
              }
              return;
            }
            await new Promise(r => setTimeout(r, 1000));
          }
        };

        const mkBtn = (label, onClick, cls = 'btn sm') => {
          const b = document.createElement('button');
          b.className = cls;
          b.textContent = label;
          b.onclick = async () => {
            try { await onClick(); } catch (err) { handleActionError(err, label); }
          };
          return b;
        };

        const actionBar = document.createElement('div');
        actionBar.className = 'actionBar';

        const actionLabel = document.createElement('label');
        actionLabel.textContent = 'Endpoint action';
        actionBar.appendChild(actionLabel);

        const actionSelect = document.createElement('select');
        actionSelect.className = 'select';

        const ttlLabel = document.createElement('label');
        ttlLabel.textContent = 'TTL';
        actionBar.appendChild(ttlLabel);

        const ttlSelect = document.createElement('select');
        ttlSelect.className = 'select';
        const ttlOptions = [
          { label: '15m', value: 15 * 60 },
          { label: '1h', value: 60 * 60 },
          { label: '4h', value: 4 * 60 * 60 },
          { label: '24h', value: 24 * 60 * 60 },
        ];
        for (const tOpt of ttlOptions) {
          const opt = document.createElement('option');
          opt.value = String(tOpt.value);
          opt.textContent = tOpt.label;
          ttlSelect.appendChild(opt);
        }

        const actionList = [];
        const addAction = (value, label, cfg = {}) => {
          const opt = document.createElement('option');
          opt.value = value;
          opt.textContent = label;
          actionSelect.appendChild(opt);
          actionList.push({ value, label, ...cfg });
        };

        addAction('triage_bundle', 'Triage bundle (endpoint)', { kind: 'triage_bundle', ttlFixed: 0 });
        addAction('isolate_host_15m', 'Isolate host (15m)', { kind: 'isolate_host', ttlFixed: 15 * 60 });
        addAction('restore_network', 'Restore network', { kind: 'restore_network', ttlFixed: 0 });
        addAction('logoff_active_user', 'Logoff active user', { kind: 'logoff_active_user', ttlFixed: 0 });
        addAction('lock_workstation', 'Lock workstation', { kind: 'lock_workstation', ttlFixed: 0 });

        if (srcIp) {
          addAction('block_ip', `Block IP (${srcIp})`, { kind: 'block_ip', value: srcIp, ttlUsesSelect: true });
          addAction('unblock_ip', `Unblock IP (${srcIp})`, { kind: 'unblock_ip', value: srcIp, ttlFixed: 0 });
        }

        if (user) {
          addAction('disable_user', `Disable user (${user})`, { kind: 'disable_user', value: user, ttlUsesSelect: true });
          addAction('enable_user', `Enable user (${user})`, { kind: 'enable_user', value: user, ttlFixed: 0 });
          addAction('logoff_user', `Logoff user (${user})`, { kind: 'logoff_user', value: user, ttlFixed: 0 });
        }

        actionBar.appendChild(actionSelect);
        actionBar.appendChild(ttlSelect);
        actionBar.appendChild(statusChip);

        const runBtn = document.createElement('button');
        runBtn.className = 'btn sm primary';
        runBtn.textContent = 'Run';
        runBtn.onclick = async () => {
          try {
            const sel = actionList.find((a) => a.value === actionSelect.value);
            if (!sel) return;
            if (!agentId) return showToast('No agent id found for this alert; cannot run endpoint response.');

            if (sel.kind === 'isolate_host') {
              if (!(await uiConfirm(t('reactive.isolateConfirm'), { danger: true }))) return;
            }

            const ttlSeconds = sel.ttlUsesSelect ? Number(ttlSelect.value || 0) : Number(sel.ttlFixed || 0);
            const val = sel.value || '';
            const id = await dispatch(sel.kind, val, ttlSeconds);
            if (!id) return;
            showToast(`Dispatched ${sel.label.toLowerCase()} to agent.`);
            await poll(id);
          } catch (err) {
            handleActionError(err, 'Endpoint action');
          }
        };
        actionBar.appendChild(runBtn);

        const advBtn = document.createElement('button');
        advBtn.className = 'btn sm ghost';
        advBtn.textContent = 'Show quick buttons';
        advBtn.onclick = () => {
          const open = row.classList.toggle('hidden');
          advBtn.textContent = open ? 'Show quick buttons' : 'Hide quick buttons';
        };
        actionBar.appendChild(advBtn);
        reactiveEndpointSec.appendChild(actionBar);

        row.appendChild(mkBtn('Triage bundle (endpoint)', async () => {
          const id = await dispatch('triage_bundle', '', 0);
          if (!id) return;
          showToast('Dispatched triage bundle collection to agent.');
          await poll(id);
        }, 'btn sm'));

        {
          const kindIsolate = 'isolate_host';
          const kindRestore = 'restore_network';
          const key = tkey(kindIsolate, agentId || '');
          const isIsolated = () => Boolean(state.reactiveToggles.get(key));
          const isolated = isIsolated();
          row.appendChild(mkBtn(isolated ? t('reactive.restoreNetworkNow') : t('reactive.isolateHost15m'), async () => {
            if (!agentId) return showToast('No agent id found for this alert; cannot run endpoint response.');
            const nowIso = isIsolated();
            if (!nowIso) {
              if (!(await uiConfirm(t('reactive.isolateConfirm'), { danger: true }))) return;
            }
            const k = nowIso ? kindRestore : kindIsolate;
            const ttl = nowIso ? 0 : 900;
            const id = await dispatch(k, '', ttl);
            if (!id) return;
            showToast(nowIso ? 'Dispatched network restore to agent.' : 'Dispatched host isolation to agent.');
            await poll(id);
            state.reactiveToggles.set(key, !nowIso);
            scheduleRender();
          }, isolated ? 'btn sm' : 'btn sm danger'));
        }

        row.appendChild(mkBtn(t('reactive.logoffActiveUserNow'), async () => {
          if (!agentId) return showToast('No agent id found for this alert; cannot run endpoint response.');
          const id = await dispatch('logoff_active_user', '', 0);
          if (!id) return;
          showToast('Dispatched active-session logoff to agent.');
          await poll(id);
        }, agentId ? 'btn sm' : 'btn sm'));

        row.appendChild(mkBtn(t('reactive.lockWorkstationNow'), async () => {
          if (!agentId) return showToast('No agent id found for this alert; cannot run endpoint response.');
          const id = await dispatch('lock_workstation', '', 0);
          if (!id) return;
          showToast('Dispatched workstation lock to agent.');
          await poll(id);
        }, agentId ? 'btn sm' : 'btn sm'));

        {
          const kindBlock = 'block_ip';
          const kindUnblock = 'unblock_ip';
          const key = tkey(kindBlock, srcIp);
          const isBlocked = () => Boolean(state.reactiveToggles.get(key));
          const blocked = isBlocked();
          row.appendChild(mkBtn(blocked ? 'Unblock IP now (endpoint)' : 'Block IP 15m (endpoint)', async () => {
            if (!srcIp) return showToast('No source IP found in alert.');
            const nowBlocked = isBlocked();
            const k = nowBlocked ? kindUnblock : kindBlock;
            const ttl = nowBlocked ? 0 : 900;
            const id = await dispatch(k, srcIp, ttl);
            if (!id) return;
            showToast(nowBlocked ? 'Dispatched firewall unblock to agent.' : 'Dispatched firewall block to agent.');
            await poll(id);
            // Toggle after a successful dispatch+poll completes.
            state.reactiveToggles.set(key, !nowBlocked);
            scheduleRender();
          }, srcIp ? (blocked ? 'btn sm' : 'btn sm danger') : 'btn sm'));
        }

        {
          const kindDisable = 'disable_user';
          const kindEnable = 'enable_user';
          const key = tkey(kindDisable, user);
          const isDisabled = () => Boolean(state.reactiveToggles.get(key));
          const disabled = isDisabled();
          row.appendChild(mkBtn(disabled ? 'Enable user now (endpoint)' : 'Disable user 15m (endpoint)', async () => {
            if (!user) return showToast('No interactive username found for this alert.');
            const nowDisabled = isDisabled();
            const k = nowDisabled ? kindEnable : kindDisable;
            const ttl = nowDisabled ? 0 : 900;
            const id = await dispatch(k, user, ttl);
            if (!id) return;
            showToast(nowDisabled ? 'Dispatched user enable to agent.' : 'Dispatched user disable to agent.');
            await poll(id);
            state.reactiveToggles.set(key, !nowDisabled);
            scheduleRender();
          }, user ? (disabled ? 'btn sm' : 'btn sm danger') : 'btn sm'));
        }

        row.appendChild(mkBtn('Logoff user now (endpoint)', async () => {
          if (!user) return showToast('No interactive username found for this alert.');
          const id = await dispatch('logoff_user', user, 0);
          if (!id) return;
          showToast('Dispatched user logoff to agent.');
          await poll(id);
        }, user ? 'btn sm' : 'btn sm'));

        // Recommended preset selection
        if (srcIp && actionSelect.querySelector('option[value="block_ip"]')) {
          actionSelect.value = 'block_ip';
        } else if (user && actionSelect.querySelector('option[value="disable_user"]')) {
          actionSelect.value = 'disable_user';
        } else {
          actionSelect.value = 'triage_bundle';
        }

        reactiveEndpointSec.appendChild(row);
        reactiveEndpointSec.appendChild(statusLine);
      }

      responseBody.appendChild(reactiveEndpointSec);

      // Reactive containment (Analyst+Authority): block IP / block user login / revoke sessions.
      const reactiveWebSec = document.createElement('div');
      reactiveWebSec.className = 'section responsePane';
      reactiveWebSec.setAttribute('data-tab', 'containment');
      reactiveWebSec.innerHTML = '<h3>Containment (server-side)</h3>';
      const ip = extractIpFromAlert(alertObj);
      const uname = extractInteractiveUserFromAlert(alertObj);

      if (!canContain()) {
        const m = document.createElement('div');
        m.className = 'muted';
        m.textContent = 'Reactive containment requires Analyst or Authority role.';
        reactiveWebSec.appendChild(m);
      } else {
        const row = document.createElement('div');
        row.className = 'actionGrid hidden';

        const mkBtn = (label, fn, cls = 'btn sm danger') => {
          const b = document.createElement('button');
          b.className = cls;
          b.textContent = label;
          b.onclick = fn;
          return b;
        };

        const actionBar = document.createElement('div');
        actionBar.className = 'actionBar';
        const actionLabel = document.createElement('label');
        actionLabel.textContent = 'Containment action';
        actionBar.appendChild(actionLabel);

        const actionSelect = document.createElement('select');
        actionSelect.className = 'select';
        const actionList = [];
        const addAction = (value, label, cfg = {}) => {
          const opt = document.createElement('option');
          opt.value = value;
          opt.textContent = label;
          actionSelect.appendChild(opt);
          actionList.push({ value, label, ...cfg });
        };

        const ttlLabel = document.createElement('label');
        ttlLabel.textContent = 'TTL';
        actionBar.appendChild(ttlLabel);
        const ttlSelect = document.createElement('select');
        ttlSelect.className = 'select';
        const ttlOptions = [
          { label: '15m', value: 15 * 60 },
          { label: '1h', value: 60 * 60 },
          { label: '4h', value: 4 * 60 * 60 },
          { label: '24h', value: 24 * 60 * 60 },
        ];
        for (const tOpt of ttlOptions) {
          const opt = document.createElement('option');
          opt.value = String(tOpt.value);
          opt.textContent = tOpt.label;
          ttlSelect.appendChild(opt);
        }

        if (ip) addAction('block_ip', `Block IP (${ip})`, { endpoint: '/api/reactive/block_ip', value: ip });
        if (ip) addAction('unblock_ip', `Unblock IP (${ip})`, { endpoint: '/api/reactive/unblock_ip', value: ip });
        if (uname) addAction('block_user', `Block user (${uname})`, { endpoint: '/api/reactive/block_user', value: uname });
        if (uname) addAction('unblock_user', `Unblock user (${uname})`, { endpoint: '/api/reactive/unblock_user', value: uname });

        actionBar.appendChild(actionSelect);
        actionBar.appendChild(ttlSelect);

        const runBtn = document.createElement('button');
        runBtn.className = 'btn sm primary';
        runBtn.textContent = 'Run';
        runBtn.onclick = async () => {
          const sel = actionList.find((a) => a.value === actionSelect.value);
          if (!sel) return;
          try {
            await apiRequestJson(sel.endpoint, {
              method: 'POST',
              bodyObj: { value: sel.value, ttl_seconds: Number(ttlSelect.value || 0), reason: `from alert ${alertId || ''}`, context_alert_id: alertId || null },
              timeoutMs: 2500,
            });
            showToast(`Dispatched ${sel.label.toLowerCase()}.`);
          } catch (err) {
            handleActionError(err, sel.label);
          }
        };
        actionBar.appendChild(runBtn);

        const advBtn = document.createElement('button');
        advBtn.className = 'btn sm ghost';
        advBtn.textContent = 'Show quick buttons';
        advBtn.onclick = () => {
          const hidden = row.classList.toggle('hidden');
          advBtn.textContent = hidden ? 'Show quick buttons' : 'Hide quick buttons';
        };
        actionBar.appendChild(advBtn);

        if (ip && actionSelect.querySelector('option[value="block_ip"]')) {
          actionSelect.value = 'block_ip';
        } else if (uname && actionSelect.querySelector('option[value="block_user"]')) {
          actionSelect.value = 'block_user';
        }

        if (ip) {
          row.appendChild(mkBtn(`Block IP 15m (${ip})`, async () => {
            try {
              await apiRequestJson('/api/reactive/block_ip', {
                method: 'POST',
                bodyObj: { value: ip, ttl_seconds: 15 * 60, reason: `from alert ${alertId || ''}`, context_alert_id: alertId || null },
                timeoutMs: 2500,
              });
              showToast(`Blocked IP ${escapeHtml(ip)} for 15m (HTTP/UI access).`);
            } catch (err) {
              handleActionError(err, 'Block IP');
            }
          }));
          row.appendChild(mkBtn(`Unblock IP (${ip})`, async () => {
            try {
              await apiRequestJson('/api/reactive/unblock_ip', {
                method: 'POST',
                bodyObj: { value: ip },
                timeoutMs: 2500,
              });
              showToast(`Unblocked IP ${escapeHtml(ip)} (HTTP/UI access).`);
            } catch (err) {
              handleActionError(err, 'Unblock IP');
            }
          }, 'btn sm'));
        }

        if (uname) {
          row.appendChild(mkBtn(`Block user 15m (${uname})`, async () => {
            try {
              await apiRequestJson('/api/reactive/block_user', {
                method: 'POST',
                bodyObj: { value: uname, ttl_seconds: 15 * 60, reason: `from alert ${alertId || ''}`, context_alert_id: alertId || null },
                timeoutMs: 2500,
              });
              showToast(`Blocked user ${escapeHtml(uname)} for 15m (login denied).`);
            } catch (err) {
              handleActionError(err, 'Block user');
            }
          }));
          row.appendChild(mkBtn(`Unblock user (${uname})`, async () => {
            try {
              await apiRequestJson('/api/reactive/unblock_user', {
                method: 'POST',
                bodyObj: { value: uname },
                timeoutMs: 2500,
              });
              showToast(`Unblocked user ${escapeHtml(uname)} (login allowed).`);
            } catch (err) {
              handleActionError(err, 'Unblock user');
            }
          }, 'btn sm'));
        }

        if (!ip && !uname) {
          const m = document.createElement('div');
          m.className = 'muted';
          m.textContent = 'No attacker IP or username found in this alert metadata.';
          reactiveWebSec.appendChild(m);
        } else {
          reactiveWebSec.appendChild(actionBar);
          reactiveWebSec.appendChild(row);
          const note = document.createElement('div');
          note.className = 'muted';
          note.style.marginTop = '8px';
          note.style.fontSize = '12px';
          note.textContent = 'Note: IP blocking applies to HTTP/UI requests to this server (it does not configure OS firewall rules).';
          reactiveWebSec.appendChild(note);
        }
      }

      responseBody.appendChild(reactiveWebSec);

      // Enrichment panel (links to event detail workflows)
      const enrichPane = document.createElement('div');
      enrichPane.className = 'section responsePane';
      enrichPane.setAttribute('data-tab', 'enrichment');
      enrichPane.innerHTML = '<h3>Enrichment</h3>';
      const enrichMsg = document.createElement('div');
      enrichMsg.className = 'muted';
      enrichMsg.textContent = 'Threat intel enrichment is available in event details.';
      const enrichBtn = document.createElement('button');
      enrichBtn.className = 'btn sm';
      enrichBtn.textContent = 'Open events view';
      enrichBtn.addEventListener('click', () => { setView('events'); scheduleRender(); });
      enrichPane.appendChild(enrichMsg);
      enrichPane.appendChild(enrichBtn);
      responseBody.appendChild(enrichPane);

      // Notes panel (local)
      const notesPane = document.createElement('div');
      notesPane.className = 'section responsePane';
      notesPane.setAttribute('data-tab', 'notes');
      notesPane.innerHTML = '<h3>Notes</h3>';
      const noteArea = document.createElement('textarea');
      noteArea.placeholder = t('notes.placeholder');
      noteArea.style.width = '100%';
      noteArea.style.minHeight = '92px';
      noteArea.style.resize = 'vertical';
      noteArea.style.border = '1px solid var(--stroke2)';
      noteArea.style.background = 'rgba(255,255,255,0.03)';
      noteArea.style.color = 'var(--text)';
      noteArea.style.borderRadius = '12px';
      noteArea.style.padding = '10px 11px';
      noteArea.style.fontSize = '13px';
      const noteMeta = document.createElement('div');
      noteMeta.className = 'muted';
      noteMeta.style.fontSize = '12px';
      const noteKey = `percepta.alert.notes.v1:${String(alertId || '') || String(alertObj?.id || '')}`;
      try {
        const existing = localStorage.getItem(noteKey) || '';
        noteArea.value = existing;
        noteMeta.textContent = existing ? t('notes.loadedFromLocal') : t('notes.empty');
      } catch {
        noteMeta.textContent = t('notes.storageBlocked');
      }
      let noteT = null;
      noteArea.addEventListener('input', () => {
        noteMeta.textContent = t('notes.saving');
        clearTimeout(noteT);
        noteT = setTimeout(() => {
          try {
            localStorage.setItem(noteKey, String(noteArea.value || ''));
            noteMeta.textContent = t('notes.savedAt', { time: new Date().toLocaleTimeString() });
          } catch {
            noteMeta.textContent = t('notes.saveFailed');
          }
        }, 400);
      });
      notesPane.appendChild(noteArea);
      notesPane.appendChild(noteMeta);
      responseBody.appendChild(notesPane);

      // Attach hotkeys (Alt+1..4 tabs, Ctrl+Enter run endpoint)
      state.responseHotkeys = {
        setTab: setResponseTab,
        runEndpoint: () => runBtn?.click(),
      };
      if (!state._responseHotkeysAttached) {
        state._responseHotkeysAttached = true;
        window.addEventListener('keydown', (e) => {
          const hk = state.responseHotkeys;
          if (!hk) return;
          if (e.altKey && !e.ctrlKey && !e.metaKey) {
            if (e.key === '1') hk.setTab('endpoint');
            if (e.key === '2') hk.setTab('containment');
            if (e.key === '3') hk.setTab('enrichment');
            if (e.key === '4') hk.setTab('notes');
          }
          if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            hk.runEndpoint();
          }
        });
      }

      const defaultTab = (state.ui && state.ui.responseTab) ? state.ui.responseTab : 'endpoint';
      setResponseTab(defaultTab);

      paneResponse.appendChild(responseDrawer);

      // Traceback pivots (safe, defensive correlation + OSINT).
      const traceSec = document.createElement('div');
      traceSec.className = 'section';
      traceSec.innerHTML = '<h3>Traceback</h3>';

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

      const agentId = String(alertObj?.agent_id || alertObj?.agent?.id || '').trim();
      pivRow.appendChild(mkPivotBtn(t('alerts.pivot.ip'), ip));
      pivRow.appendChild(mkPivotBtn(t('alerts.pivot.user'), uname));
      pivRow.appendChild(mkPivotBtn(t('alerts.pivot.agent'), agentId));
      traceSec.appendChild(pivRow);

      if (ip) {
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
        intelTop.innerHTML = `<span class="mono">${escapeHtml(ip)}</span><span class="muted">${escapeHtml(t('intel.ipOsint'))}</span>`;
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
            const resp = await apiPostJson('/api/intel/ip', { ip }, { timeoutMs: 4500 });
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
          const u = intelUrlForIp(p, ip);
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

      if (!ip && !uname && !agentId) {
        const m = document.createElement('div');
        m.className = 'muted';
        m.style.marginTop = '8px';
        m.textContent = t('alerts.noPivots');
        traceSec.appendChild(m);
      }

      paneTraceback.appendChild(traceSec);

      // Audit trail for reactive actions
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
      paneAudit.appendChild(auditSec);

      const rawSec = document.createElement('div');
      rawSec.className = 'section';
      rawSec.innerHTML = `<h3>${escapeHtml(t('section.raw'))}</h3>`;
      rawSec.appendChild(buildRawJsonDetails(alertObj));
      paneRaw.appendChild(rawSec);

      const ensurePaneContent = (pane, text) => {
        if (!pane || pane.childNodes.length) return;
        const m = document.createElement('div');
        m.className = 'muted';
        m.textContent = text;
        pane.appendChild(m);
      };
      ensurePaneContent(paneEvidence, 'No parsed evidence available for this alert.');
      ensurePaneContent(paneRelated, 'No related signals were found for this alert key.');
      ensurePaneContent(paneResponse, 'No response actions are available in this context.');
      ensurePaneContent(paneTraceback, 'No traceback pivots are available.');
      ensurePaneContent(paneAudit, 'No audit history found for this alert yet.');

      shell.setTab(String(state?.ui?.alertDetailsTab || 'overview'));
    }

    function handleActionError(err, actionName) {
      const status = err?.status;
      if (status === 401) {
        showToast(t('actionError.requireLoginHtml', { action: escapeHtml(actionName) }));
        return;
      }
      if (status === 403) {
        showToast(t('actionError.forbiddenNeedRole', { action: escapeHtml(actionName) }));
        return;
      }
      const body = (err?.body || '').toString().slice(0, 220);
      showToast(t('actionError.failed', {
        action: escapeHtml(actionName),
        status: escapeHtml(String(status || '')),
        body: escapeHtml(body),
      }));
    }

    // ── In-flight guards to prevent overlapping API requests ──────────────────
    // When a request is in progress, new calls are skipped to avoid NS_BINDING_ABORTED.
    let _fetchHealthInFlight = false;
    let _fetchStatsInFlight = false;
    let _fetchAlertsInFlight = false;
    let _fetchEventsInFlight = false;
    let _fetchDashboardSummaryInFlight = false;

    async function fetchHealth() {
      if (_fetchHealthInFlight) return;
      _fetchHealthInFlight = true;
      try {
        const h = await apiFetchJson(API.healthz, { timeoutMs: 5000, headers: { 'Accept': 'application/json' } });
        // Core services (DB, CA, storage) determine whether the server is truly healthy.
        // DR readiness is informational and should not degrade the status indicator.
        const dbOk = h?.database?.status !== 'degraded';
        const caOk = h?.ca_service?.status !== 'degraded';
        const coreOk = h && dbOk && caOk;
        state.lastHealthStatus = coreOk ? 'ok' : 'degraded';
        markApiOk();
      } catch (e) {
        state.lastHealthStatus = 'offline';
        showApiFailureOnce('GET /healthz', e);
      } finally {
        _fetchHealthInFlight = false;
      }
      state.dirty.health = true;
    }

    async function fetchStats() {
      if (_fetchStatsInFlight) return;
      _fetchStatsInFlight = true;
      try {
        const stats = await apiFetchJson(API.stats);
        state.stats = Object.assign({}, state.stats || {}, stats || {});
        if (typeof state.stats?.ingest_total_received === 'number') state.ingestTotalReceived = state.stats.ingest_total_received;
        const connectedPrimary = Array.isArray(state.stats.connected_agent_ids) ? state.stats.connected_agent_ids : [];
        const connectedResponse = Array.isArray(state.stats.response_connected_agent_ids) ? state.stats.response_connected_agent_ids : [];
        state.agentIds = Array.from(new Set(
          [...connectedPrimary, ...connectedResponse]
            .map((v) => String(v || '').trim())
            .filter(Boolean)
        ));
        state.knownAgents = Array.isArray(state.stats.known_agents) ? state.stats.known_agents : [];

        // Seed MAC bindings + stable ordinals from server-known agent inventory.
        for (const a of state.knownAgents) {
          const aid = String(a?.agent_id || '').trim();
          if (!aid) continue;
          const mac = normalizeMac(String(a?.mac || ''));
          if (mac) state.agentMacById.set(aid, mac);

          const u = String(a?.last_user || a?.user || '').trim();
          if (u) state.agentUserById.set(aid, u);

          const hn = String(a?.hostname || '').trim();
          if (hn) state.agentNameById.set(aid, hn);

          agentOrdinalForAgentId(aid);
        }

        // Only set dirty flags if there's actual change to prevent redundant renders
        // during high-frequency events. Compare agent IDs and stats ingest counter.
        const prevAgentCount = Array.isArray(state._prevAgentIds) ? state._prevAgentIds.length : 0;
        const agentCountChanged = state.agentIds.length !== prevAgentCount;
        const agentListChanged = agentCountChanged || 
          (state.agentIds.some(id => !state._prevAgentIds?.includes(id)) ||
           (state._prevAgentIds || []).some(id => !state.agentIds.includes(id)));
           
        if (agentListChanged) {
          state._prevAgentIds = [...state.agentIds];
          state.dirty.agents = true;
        }
        state.dirty.counters = true;
        markApiOk();
      } catch (e) {
        showApiFailureOnce('GET /api/stats', e);
      } finally {
        _fetchStatsInFlight = false;
      }
    }

    async function fetchDashboardSummary() {
      if (_fetchDashboardSummaryInFlight) return;
      _fetchDashboardSummaryInFlight = true;
      try {
        const summary = await apiFetchJson(`${API.dashboardSummary}?window_minutes=60`);
        state.dashboardSummary = (summary && typeof summary === 'object') ? summary : null;
        state.dirty.counters = true;
        markApiOk();
      } catch (e) {
        showApiFailureOnce('GET /api/dashboard/summary', e);
      } finally {
        _fetchDashboardSummaryInFlight = false;
      }
    }

    function pagerTotalPages(kind) {
      const p = state.pagination?.[kind] || { total: 0, pageSize: 100 };
      return Math.max(1, Math.ceil((Number(p.total || 0) || 0) / Math.max(1, Number(p.pageSize || 100) || 100)));
    }

    function syncPagerUi(kind) {
      const p = state.pagination?.[kind];
      if (!p) return;
      const totalPages = pagerTotalPages(kind);
      const page = Math.min(totalPages, Math.max(1, Number(p.page || 1) || 1));
      p.page = page;

      const labelId = kind === 'alerts' ? 'alertsPageLabel' : 'eventsPageLabel';
      const prevId = kind === 'alerts' ? 'alertsPrevPage' : 'eventsPrevPage';
      const nextId = kind === 'alerts' ? 'alertsNextPage' : 'eventsNextPage';

      const label = document.getElementById(labelId);
      if (label) label.textContent = `Page ${page}/${totalPages} • Total ${Number(p.total || 0).toLocaleString()}`;

      const prevBtn = document.getElementById(prevId);
      const nextBtn = document.getElementById(nextId);
      if (prevBtn) prevBtn.disabled = page <= 1;
      if (nextBtn) nextBtn.disabled = page >= totalPages;
    }

    async function fetchAlerts(opts = {}) {
      if (_fetchAlertsInFlight && !opts.retried) return;
      _fetchAlertsInFlight = true;
      try {
        const retried = Boolean(opts && opts.retried);
        const pager = state.pagination.alerts;
        const limit = Math.max(1, Math.min(LIMITS.maxAlerts, Number(pager.pageSize || 100) || 100));
        const offset = Math.max(0, ((Number(pager.page || 1) || 1) - 1) * limit);

        // Build filter query params from UI controls
        const params = new URLSearchParams({ limit, offset });
        const qVal = document.getElementById('alertsSearchQ')?.value?.trim() || '';
        if (qVal) params.set('q', qVal);
        const sev = document.getElementById('alertsFilterSeverity')?.value || '';
        if (sev) params.set('severity', sev);
        const cat = document.getElementById('alertsFilterCategory')?.value || '';
        if (cat) params.set('category', cat);
        const agent = document.getElementById('alertsFilterAgent')?.value || '';
        if (agent) params.set('agent', agent);
        const sort = document.getElementById('alertsFilterSort')?.value || 'last_seen';
        if (sort && sort !== 'last_seen') params.set('sort', sort);
        const order = document.getElementById('alertsFilterOrder')?.value || 'desc';
        if (order && order !== 'desc') params.set('order', order);
        const fromDt = document.getElementById('alertsFilterFrom')?.value || '';
        if (fromDt) params.set('from', new Date(fromDt).toISOString());
        const toDt = document.getElementById('alertsFilterTo')?.value || '';
        if (toDt) params.set('to', new Date(toDt).toISOString());

        // Important: don't de-dupe against the previous fetch.
        state.alertIndex.clear();
        const payload = await apiFetchJson(`${API.alerts}?${params.toString()}`);
        const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
        const total = Number(payload?.total || 0) || 0;
        pager.total = total;
        const totalPages = pagerTotalPages('alerts');
        if (pager.page > totalPages && !retried) {
          pager.page = totalPages;
          syncPagerUi('alerts');
          return fetchAlerts({ retried: true });
        }

        // De-dupe while preserving order.
        const uniq = [];
        for (const a of alerts) {
          const k = alertKey(a);
          if (state.alertIndex.has(k)) continue;
          rememberKeyLRU(state.alertIndex, k, DEDUPE.maxAlertKeys);
          uniq.push(a);
          if (uniq.length >= LIMITS.maxAlerts) break;
        }
        if (total > 0 && uniq.length === 0 && Array.isArray(state.alerts) && state.alerts.length) {
          state.dirty.tables = true;
          state.dirty.counters = true;
          syncPagerUi('alerts');
          return;
        }

        state.alerts = uniq;
        if (typeof window._populateAlertFilterDropdowns === 'function') {
          window._populateAlertFilterDropdowns(uniq);
        }
        if (state.selectedAlertKeys instanceof Set) {
          const liveKeys = new Set(uniq.map((a) => alertKey(a)));
          for (const key of Array.from(state.selectedAlertKeys)) {
            if (!liveKeys.has(key)) state.selectedAlertKeys.delete(key);
          }
        }
        state.dirty.tables = true;
        state.dirty.counters = true;
        syncPagerUi('alerts');
        markApiOk();
      } catch (e) {
        showApiFailureOnce('GET /api/alerts', e);
      } finally {
        _fetchAlertsInFlight = false;
      }
    }

    async function fetchEvents(opts = {}) {
      if (_fetchEventsInFlight && !opts.retried) return;
      _fetchEventsInFlight = true;
      // Show skeleton while loading (ISS-049)
      if (typeof showTableSkeleton === 'function') showTableSkeleton('tblEvents');
      try {
        const retried = Boolean(opts && opts.retried);
        const pager = state.pagination.events;
        const limit = Math.max(1, Math.min(LIMITS.maxEvents, Number(pager.pageSize || 100) || 100));
        const offset = Math.max(0, ((Number(pager.page || 1) || 1) - 1) * limit);

        const q = state.searchText.trim();
        // Collect additional filters from hunt UI controls
        const huntQ = document.getElementById('huntQueryInput')?.value?.trim() || '';
        const huntCat = document.getElementById('huntFilterCategory')?.value?.trim() || '';
        const huntSev = document.getElementById('huntFilterSeverity')?.value?.trim() || '';
        const lookback = Number(document.getElementById('huntLookback')?.value) || 168;
        // Combine global search and hunt query
        const combinedQ = [q, huntQ, huntCat ? `category:${huntCat}` : '', huntSev ? `severity:${huntSev}` : ''].filter(Boolean).join(' ');
        const url = combinedQ
          ? `${API.search}?limit=${limit}&offset=${offset}&lookback_hours=${lookback}&q=${encodeURIComponent(combinedQ)}`
          : `${API.search}?limit=${limit}&offset=${offset}&lookback_hours=${lookback}`;
        const payload = await apiFetchJson(url);
        const events = Array.isArray(payload.events) ? payload.events : [];
        const total = Number(payload?.total || 0) || 0;
        pager.total = total;
        state._lastSearchTotal = total;
        state._searchOffset = offset;
        const totalPages = pagerTotalPages('events');
        if (pager.page > totalPages && !retried) {
          pager.page = totalPages;
          syncPagerUi('events');
          return fetchEvents({ retried: true });
        }

        const uniq = [];
        const hp = [];
        const ids = [];
        state.eventIndex.clear();
        for (const e of events) {
          if (!acceptEventUnderWatermark(e)) continue;
          const k = eventKey(e);
          if (state.eventIndex.has(k)) continue;
          rememberKeyLRU(state.eventIndex, k, DEDUPE.maxEventKeys);
          uniq.push(e);
          observeAgentFromEvent(e);
          if (isHoneypotEvent(e)) hp.push(e);
          if (isIdsEvent(e)) ids.push(e);
          if (uniq.length >= LIMITS.maxEvents) break;
        }
        state.events = uniq;
        state.honeypot = hp;
        state.ids = ids;
        // Prime device name cache for current view.
        enqueueDeviceNameLookup(state.events.map(getBestMac).filter(Boolean));
        state.dirty.tables = true;
        state.dirty.counters = true;
        syncPagerUi('events');
        markApiOk();
      } catch (e) {
        showApiFailureOnce('GET /api/search', e);
      } finally {
        _fetchEventsInFlight = false;
      }
    }

    function paintAgents() {
      const el = document.getElementById('agentsList');
      if (!el) return;
      clearEl(el);

      const connected = new Set(Array.isArray(state.agentIds) ? state.agentIds : []);
      const nowMs = Date.now();
      const recentMaxAgeMs = 5 * 60 * 1000;
      const evs = Array.isArray(state.events) ? state.events : [];
      for (const e of evs) {
        const aid = String(e?.agent?.id || e?.agent_id || '').trim();
        if (!aid) continue;
        const eventMs = (typeof eventIngestMs === 'function') ? Number(eventIngestMs(e) || 0) : 0;
        if (!eventMs || (nowMs - eventMs) <= recentMaxAgeMs) connected.add(aid);
      }
      const known = Array.isArray(state.knownAgents) ? state.knownAgents : [];

      if (!connected.size && !known.length) {
        el.innerHTML = '<div class="agent empty">No agents connected</div>';
        return;
      }

      // Prefer connected first, then recently-seen offline agents.
      const rows = [];
      for (const a of known) {
        const aid = String(a?.agent_id || '').trim();
        if (!aid) continue;
        const lastSeen = Number(a?.last_seen_unix || 0) * 1000;
        const isRecent = lastSeen > 0 && (nowMs - lastSeen) <= recentMaxAgeMs;
        rows.push({ aid, connected: connected.has(aid) || isRecent, lastSeen });
      }
      // If a connected agent isn't in known yet, include it.
      for (const id of connected) {
        if (!rows.some(r => r.aid === id)) rows.push({ aid: id, connected: true, lastSeen: 0 });
      }

      rows.sort((a, b) => {
        if (a.connected !== b.connected) return a.connected ? -1 : 1;
        return (b.lastSeen || 0) - (a.lastSeen || 0);
      });

      for (const r of rows.slice(0, 300)) {
        const div = document.createElement('div');
        div.className = 'agent';
        const ageMs = r.lastSeen ? Math.max(0, nowMs - r.lastSeen) : 0;
        const offline = !r.connected;
        div.style.opacity = offline ? '0.65' : '1';
        div.textContent = `${agentLabel(r.aid)}${offline ? ' (offline)' : ''}`;
        div.title = r.lastSeen ? `${r.aid} • last seen ${Math.round(ageMs / 1000)}s ago` : r.aid;
        el.appendChild(div);
      }
    }

    async function escalateAlert(alertObj) {
      const title = alertObj?.rule_name || alertObj?.rule_id || 'Alert escalation';
      const eventHash = (Array.isArray(alertObj?.source_events) && alertObj.source_events.length) ? alertObj.source_events[0] : '';
      const agentLine = agentIdentityLabelForAlert(alertObj) || (alertObj?.agent_hostname || alertObj?.agent_id || '');
      const description = `${alertObj?.message || ''}\n\nSeverity: ${alertObj?.severity || ''}\nAgent: ${agentLine}\nRule: ${alertObj?.rule_id || ''}\nAlertId: ${alertObj?.id || ''}`;

      const body = toEscalationCreateForm({ title, description, event_hash: eventHash });

      const res = await fetch(API.escalations, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body,
        redirect: 'follow',
        credentials: 'same-origin',
      });

      // If middleware ever returns HTML/redirect (browser-style), treat as auth failure.
      if (res.redirected && (res.url.includes('/login') || res.url.includes('/adminlogin'))) {
        const err = new Error('Unauthorized');
        err.status = 401;
        throw err;
      }

      if (res.status === 401) {
        const err = new Error('Unauthorized');
        err.status = 401;
        throw err;
      }
      if (res.status === 403) {
        const err = new Error('Forbidden');
        err.status = 403;
        throw err;
      }
      if (!res.ok && res.status !== 302) {
        const t = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}`);
        err.status = res.status;
        err.body = t;
        throw err;
      }

      state.dirty.escalations = true;
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (ct.includes('application/json')) {
        const data = await res.json().catch(() => null);
        if (data && data.ok && data.id) return String(data.id);
      }
      return '';
    }

    function getEventHash(e) {
      return e?.hash || e?.event?.hash || e?.event_id || '';
    }

    async function escalateEvent(eventObj) {
      const hash = getEventHash(eventObj);
      const summary = eventObj?.event?.summary || eventObj?.event?.original_message || eventObj?.message || 'Manual event alert';
      const agent = eventObj?.agent?.hostname || eventObj?.agent?.id || eventObj?.agent_id || '';
      const time = formatTime(eventPrimaryTime(eventObj));

      const title = `Manual alert: ${String(summary).slice(0, 80)}`;
      const description = `${summary}\n\nAgent: ${agent}\nTime: ${time}\nEventHash: ${hash}\n\n--- Raw JSON ---\n${JSON.stringify(eventObj, null, 2)}`;

      const body = toEscalationCreateForm({ title, description, event_hash: hash });

      const res = await fetch(API.escalations, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body,
        redirect: 'follow',
        credentials: 'same-origin',
      });

      if (res.redirected && (res.url.includes('/login') || res.url.includes('/adminlogin'))) {
        const err = new Error('Unauthorized');
        err.status = 401;
        throw err;
      }

      if (res.status === 401) {
        const err = new Error('Unauthorized');
        err.status = 401;
        throw err;
      }
      if (res.status === 403) {
        const err = new Error('Forbidden');
        err.status = 403;
        throw err;
      }
      if (!res.ok && res.status !== 302) {
        const t = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}`);
        err.status = res.status;
        err.body = t;
        throw err;
      }

      state.dirty.escalations = true;
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (ct.includes('application/json')) {
        const data = await res.json().catch(() => null);
        if (data && data.ok && data.id) return String(data.id);
      }
      return '';
    }

    // Helper: relative time ago string.
    function escTimeAgo(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      const s = Math.floor((Date.now() - d.getTime()) / 1000);
      if (s < 60) return 'just now';
      if (s < 3600) return `${Math.floor(s / 60)}m ago`;
      if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
      if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
      return `${Math.floor(s / 604800)}w ago`;
    }

    // Helper: infer priority from escalation (uses title keywords or stored priority).
    function escInferPriority(e) {
      const p = String(e?.priority || '').toLowerCase();
      if (['critical','high','medium','low'].includes(p)) return p;
      const txt = String(e?.title || '').toLowerCase() + ' ' + String(e?.description || '').toLowerCase();
      if (/\bcritical\b|\bsev\s*1\b|\bp1\b/.test(txt)) return 'critical';
      if (/\bhigh\b|\bsev\s*2\b|\bp2\b|\burgent\b/.test(txt)) return 'high';
      if (/\blow\b|\bsev\s*4\b|\bp4\b|\bminor\b/.test(txt)) return 'low';
      return 'medium';
    }

    async function paintEscalations() {
      const queueWrap = document.getElementById('escQueueWrap');
      const reviewWrap = document.getElementById('escReviewWrap');
      const form = document.getElementById('createEscForm');

      // Wire form submit once.
      if (form && !form._escWired) {
        form._escWired = true;
        form.addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const btn = form.querySelector('button[type="submit"]');
          if (btn) { btn.disabled = true; btn.textContent = 'Submitting…'; }
          const fd = new FormData(form);
          const body = new URLSearchParams();
          body.set('title', String(fd.get('title') || ''));
          body.set('description', String(fd.get('description') || ''));
          const priority = String(fd.get('priority') || 'medium');
          body.set('priority', priority);
          const eh = String(fd.get('event_hash') || '').trim();
          if (eh) body.set('event_hash', eh);
          try {
            const res = await fetch(API.escalations, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, body, credentials: 'same-origin' });
            if (btn) { btn.disabled = false; btn.textContent = 'Submit Escalation'; }
            if (res.status === 401) return showToast(t('escalations.create.requireLogin'));
            if (res.status === 403) return showToast(t('escalations.create.forbidden'));
            if (!res.ok && res.status !== 302) {
              return showToast(`Create failed: HTTP ${res.status}`);
            }
            showToast('✓ Escalation submitted successfully');
            form.reset();
            document.querySelector('#escTabs .tabBtn[data-esc-tab="queue"]')?.click();
            state.dirty.escalations = true;
            scheduleRender();
          } catch (e) {
            if (btn) { btn.disabled = false; btn.textContent = 'Submit Escalation'; }
            showToast(t('escalations.create.failedConsole'));
          }
        });
      }

      // Fetch escalation data.
      let esc = [];
      let fetchErr = null;
      try {
        const data = await apiFetchJson(API.escalations, { headers: { 'Accept': 'application/json' }, timeoutMs: 3500 });
        esc = Array.isArray(data.escalations) ? data.escalations : [];
      } catch (err) {
        fetchErr = err;
      }

      // KPI counters.
      const counts = { total: esc.length, open: 0, approved: 0, rejected: 0, closed: 0 };
      for (const e of esc) {
        const s = String(e.status || '').toLowerCase();
        if (s === 'open' || s === 'pending') counts.open++;
        else if (s === 'approved') counts.approved++;
        else if (s === 'rejected') counts.rejected++;
        else if (s === 'closed') counts.closed++;
        else counts.open++;
      }
      const setKpi = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = String(val); };
      setKpi('escKpiTotal', counts.total);
      setKpi('escKpiOpen', counts.open);
      setKpi('escKpiApproved', counts.approved);
      setKpi('escKpiRejected', counts.rejected);
      setKpi('escKpiClosed', counts.closed);

      // Update scope meta with live count.
      const scopeMeta = document.getElementById('escScopeMeta');
      if (scopeMeta) {
        const activeTab = document.querySelector('#escTabs .tabBtn.active')?.dataset?.escTab || 'queue';
        const msgs = {
          queue: `${counts.total} escalation${counts.total !== 1 ? 's' : ''} · ${counts.open} open · click a row for details`,
          create: 'Raise a new incident for analyst review and triage',
          review: `Authority decision queue · ${counts.open} awaiting review`
        };
        scopeMeta.textContent = msgs[activeTab] || '';
      }

      // Helper: status badge.
      const statusBadge = (status) => {
        const s = String(status || '').toLowerCase();
        const cls = ['open','pending'].includes(s) ? 'open' : s === 'approved' ? 'approved' : s === 'rejected' ? 'rejected' : 'closed';
        const label = s.charAt(0).toUpperCase() + s.slice(1);
        return `<span class="esc-status-badge ${escapeHtml(cls)}">${escapeHtml(label || 'Unknown')}</span>`;
      };

      // Helper: priority badge.
      const priorityBadge = (e) => {
        const p = escInferPriority(e);
        const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
        return `<span class="esc-priority-badge p-${escapeHtml(p)}">${icons[p] || ''} ${escapeHtml(p)}</span>`;
      };

      // Helper: time cell with relative + absolute.
      const timeCell = (dateStr) => {
        const ago = escTimeAgo(dateStr);
        const abs = escapeHtml(formatTime(dateStr));
        return `<div class="esc-time-ago"><span>${escapeHtml(ago)}</span><span class="abs">${abs}</span></div>`;
      };

      // Helper: render escalation table.
      const renderEscTable = (container, items, opts) => {
        if (fetchErr) {
          const is401 = fetchErr?.status === 401;
          const is403 = fetchErr?.status === 403;
          container.innerHTML = `<div class="esc-empty">
            <div class="esc-empty-icon">${is401 ? '🔒' : is403 ? '🚫' : '⚠️'}</div>
            <div class="esc-empty-title">${is401 ? 'Authentication Required' : is403 ? 'Access Denied' : 'Connection Error'}</div>
            <div class="esc-empty-msg">${is401 ? 'Please log in to view escalations.' : is403 ? 'Your role does not have permission to view this section.' : 'Failed to load escalation data. Try refreshing.'}</div>
            ${is401 ? '<a class="btn sm link-btn-inline" href="/login">Log In</a>' : '<button class="btn sm" id="escRetryBtn">Retry</button>'}
          </div>`;
          const retryBtn = container.querySelector('#escRetryBtn');
          if (retryBtn) {
            retryBtn.addEventListener('click', () => {
              state.dirty.escalations = true;
              scheduleRender();
            });
          }
          return;
        }
        if (!items.length) {
          const isReview = opts?.actions === true;
          container.innerHTML = `<div class="esc-empty">
            <div class="esc-empty-icon">${isReview ? '✅' : '📋'}</div>
            <div class="esc-empty-title">${isReview ? 'Review Queue Clear' : 'No Escalations'}</div>
            <div class="esc-empty-msg">${isReview ? 'All escalations have been reviewed. Great work!' : 'No escalations have been created yet. Use the <strong>New Escalation</strong> tab to raise an incident.'}</div>
            ${!isReview ? '<button class="btn sm" id="escCreateFirstBtn">＋ Create First Escalation</button>' : ''}
          </div>`;
          const createBtn = container.querySelector('#escCreateFirstBtn');
          if (createBtn) {
            createBtn.addEventListener('click', () => {
              document.querySelector('#escTabs .tabBtn[data-esc-tab=create]')?.click();
            });
          }
          return;
        }
        const showActions = opts?.actions === true;
        const wrap = document.createElement('div');
        wrap.className = 'tableWrap esc-table-wrap';
        const table = document.createElement('table');
        let headHtml = `<thead><tr>
          <th width="130">When</th>
          <th width="70">Priority</th>
          <th width="130">By</th>
          <th>Title</th>
          <th width="110">Status</th>`;
        if (showActions) headHtml += `<th width="240">Actions</th>`;
        headHtml += `</tr></thead>`;
        table.innerHTML = headHtml;
        const tbody = document.createElement('tbody');
        for (const e of items) {
          const tr = document.createElement('tr');
          tr.className = 'esc-row-clickable';
          tr.dataset.escId = String(e.id || '');
          const noteId = `escNote_${String(e.id || '').replaceAll(/[^a-zA-Z0-9_-]/g, '_')}`;
          let rowHtml = `
            <td>${timeCell(e.created_at)}</td>
            <td>${priorityBadge(e)}</td>
            <td>${escapeHtml(e.created_by || '—')}</td>
            <td><span class="esc-row-title">${escapeHtml(e.title || '')}</span>${e.event_hash ? `<div class="mono esc-row-hash">${escapeHtml(String(e.event_hash).slice(0, 24))}…</div>` : ''}</td>
            <td>${statusBadge(e.status)}</td>`;
          if (showActions) {
            rowHtml += `<td><div class="esc-action-cell">
              <input id="${escapeHtml(noteId)}" class="field sm" placeholder="Note…" />
              <button class="btn sm" data-act="approve" data-id="${escapeHtml(e.id)}" title="Approve">✓</button>
              <button class="btn sm danger" data-act="reject" data-id="${escapeHtml(e.id)}" title="Reject">✕</button>
              <button class="btn sm" data-act="close" data-id="${escapeHtml(e.id)}" title="Close">⊘</button>
            </div></td>`;
          }
          tr.innerHTML = rowHtml;
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        container.innerHTML = '';
        container.appendChild(wrap);

        // Row click → open details in drawer.
        wrap.addEventListener('click', async (ev) => {
          if (ev.target.closest('button') || ev.target.closest('input')) return;
          const tr = ev.target?.closest?.('tr');
          const id = tr?.dataset?.escId;
          if (!id) return;
          state.escalationsUi.selectedId = id;
          // Highlight selected row.
          wrap.querySelectorAll('tr').forEach((r) => r.classList.remove('esc-row-selected'));
          tr.classList.add('esc-row-selected');
          const escObj = items.find(x => String(x.id || '') === String(id));
          if (!escObj) return;
          const drawerBody = document.getElementById('evDetailBody');
          if (drawerBody) {
            drawerBody.innerHTML = `<div class="muted p-16">${escapeHtml(t('common.loadingDetails'))}</div>`;
            openEventDetailDrawer();
            let linked = state.escalationsUi.linkedEventByEscId.get(id) || null;
            if (!linked && escObj?.event_hash) {
              linked = await fetchEventByLooseHash(escObj.event_hash);
              if (linked) state.escalationsUi.linkedEventByEscId.set(id, linked);
            }
            drawerBody.innerHTML = '';
            drawerBody.appendChild(buildEscalationDetailsBox(escObj, linked));
          }
        });
      };

      // Render Queue tab (all escalations).
      if (queueWrap) renderEscTable(queueWrap, esc, { actions: false });

      // Render Review tab (authority — all escalations with action buttons).
      if (reviewWrap) renderEscTable(reviewWrap, esc, { actions: true });
    }

    async function approveRenewal(requestId) {
      const body = JSON.stringify({ request_id: String(requestId || '') });
      const res = await fetch(API.renewApprove, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body,
        redirect: 'follow',
        credentials: 'same-origin',
      });

      if (res.redirected && (res.url.includes('/login') || res.url.includes('/adminlogin'))) {
        showToast(t('renewals.approve.requireLogin'));
        return;
      }

      if (res.status === 401) return showToast(t('renewals.approve.requireLogin'));
      if (res.status === 403) return showToast(t('renewals.forbiddenGeneric'));
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        return showToast(t('renewals.approve.failedHttp', { status: res.status, body: escapeHtml(t.slice(0, 180)) }));
      }

      showToast(t('renewals.approve.ok'));
      // Refresh whichever view is currently showing renewals.
      if (state.view === 'settings') {
        paintSettingsRenewals({ force: true });
      }
      scheduleRender();
    }

    async function rejectRenewal(requestId) {
      const body = JSON.stringify({ request_id: String(requestId || '') });
      const res = await fetch(API.renewReject, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body,
        redirect: 'follow',
        credentials: 'same-origin',
      });

      if (res.redirected && (res.url.includes('/login') || res.url.includes('/adminlogin'))) {
        showToast(t('renewals.reject.requireLogin'));
        return;
      }
      if (res.status === 401) return showToast(t('renewals.reject.requireLogin'));
      if (res.status === 403) return showToast(t('renewals.forbiddenGeneric'));
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        return showToast(t('renewals.reject.failedHttp', { status: res.status, body: escapeHtml(t.slice(0, 180)) }));
      }

      showToast(t('renewals.reject.ok'));
      if (state.view === 'settings') {
        paintSettingsRenewals({ force: true });
      }
      scheduleRender();
    }

    async function decideEscalation(id, action) {
      const noteEl = document.getElementById(`escNote_${String(id || '').replaceAll(/[^a-zA-Z0-9_-]/g, '_')}`);
      const note = noteEl ? String(noteEl.value || '').trim() : '';
      const form = new URLSearchParams();
      form.set('action', action);
      if (note) form.set('note', note);
      const res = await fetch(`/api/escalations/${encodeURIComponent(id)}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: form,
        redirect: 'follow',
        credentials: 'same-origin',
      });

      // If middleware ever returns HTML/redirect (browser-style), treat as auth failure.
      if (res.redirected && (res.url.includes('/login') || res.url.includes('/adminlogin'))) {
        return showToast(t('escalations.decision.requireLogin'));
      }

      if (res.status === 401) return showToast(t('escalations.decision.requireLogin'));
      if (res.status === 403) return showToast(t('renewals.forbiddenGeneric'));
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        if (res.status === 405) {
          return showToast(t('escalations.decision.failed405'));
        }
        if (res.status === 415) {
          return showToast(t('escalations.decision.failed415'));
        }
        return showToast(t('escalations.decision.failedHttp', { status: res.status, body: escapeHtml(t.slice(0, 180)) }));
      }
      showToast(t('escalations.decision.saved'));
      state.dirty.escalations = true;
      scheduleRender();
    }

    function flushRender() {
      const needsOverviewPaint = Boolean(state.dirty.counters || state.dirty.tables || state.dirty.health || state.dirty.ws);

      if (state.dirty.health) { state.dirty.health = false; paintHealth(); }
      if (state.dirty.ws) { state.dirty.ws = false; paintWs(); }
      if (state.dirty.counters) { state.dirty.counters = false; paintCountersThrottled(); }
      if (state.dirty.auth) { state.dirty.auth = false; paintAuth(); }
      if (state.dirty.agents) { state.dirty.agents = false; paintAgents(); }
      if (state.dirty.tables) { state.dirty.tables = false; paintTables(); }
      if (state.view === 'overview' && (needsOverviewPaint || typeof eliteMap === 'undefined' || eliteMap === null)) {
        paintOverviewDashThrottled();
      }
      if (state.view === 'settings') paintSettingsAgentsThrottled();
      if (state.dirty.details) {
        state.dirty.details = false;
        const ev = getEventByKey(state.selected.key);

        // Only open the event detail drawer on views that actually show event rows.
        const eventDetailViews = ['events', 'honeypot', 'ids'];
        if (eventDetailViews.includes(state.view)) {
          paintEventDetails('evDetailBody', ev);
          // Only open the drawer if the user explicitly clicked a row or if
          // the drawer is already visible (content refresh).  This prevents
          // background refreshAll / WS reconnects from forcibly reopening a
          // drawer the user already dismissed.
          const _drEl = document.getElementById('evDetailDrawer');
          const _alreadyOpen = _drEl && _drEl.classList.contains('open');
          if (ev && (_alreadyOpen || state._detailOpenRequested)) {
            openEventDetailDrawer();
          }
          state._detailOpenRequested = false;
        }
        if (state.view === 'alerts') paintAlertDetails(getAlertByKey(state.selectedAlertKey));
      }
      if (state.dirty.escalations) {
        state.dirty.escalations = false;
        paintEscalations();
      }
    }

    // ── API Degradation Banner (ISS-040) ───────────────────────────────────
    function showDegradationBanner(failedServices) {
      let banner = document.getElementById('apiDegradationBanner');
      if (!failedServices || failedServices.length === 0) {
        if (banner) banner.remove();
        return;
      }
      if (!banner) {
        banner = document.createElement('div');
        banner.id = 'apiDegradationBanner';
        banner.className = 'api-degradation-banner';
        document.body.prepend(banner);
      }
      banner.innerHTML = `<span>⚠ Services unavailable: ${failedServices.join(', ')}</span>` +
        `<button onclick="document.getElementById('apiDegradationBanner')?.remove()">Dismiss</button>`;
    }

    async function refreshAll() {
      const results = await Promise.allSettled([
        fetchHealth(),
        fetchStats(),
        fetchDashboardSummary(),
        fetchAlerts(),
        fetchEvents(),
        fetchWhoAmI(),
        fetchIntelStatus(),
      ]);

      // ── Degradation banner (ISS-040) ──────────────────────────────────────
      const labels = ['Health','Stats','Summary','Alerts','Events','Auth','Intel'];
      const failed = [];
      results.forEach((r, i) => { if (r.status === 'rejected') failed.push(labels[i]); });
      showDegradationBanner(failed);

      state.dirty.counters = true;
      state.dirty.tables = true;
      state.dirty.details = true;
      scheduleRender();
    }

    function startPollingFallback() {
      if (state.pollTimer) clearInterval(state.pollTimer);
      let ticks = 0;
      state.pollTimer = setInterval(() => {
        ticks++;
        const hidden = Boolean(document.hidden);
        const wsUp = Boolean(state.wsOk);

        // Background tab: check very occasionally.
        if (hidden && (ticks % 15 !== 0)) return;

        // Health check: always needed (not streamed), but at a relaxed cadence.
        // Every 12s when WS is up, every 2s when down (optimized).
        const healthCadence = wsUp ? 6 : 1;
        if (ticks % healthCadence === 0) {
          fetchHealth().finally(() => { state.dirty.health = true; scheduleRender(); });
        }

        // When WS is up, the stream supplies events/alerts/stats.
        // Only do a light stats refresh every ~30s for counters the stream doesn't cover.
        if (wsUp) {
          if (ticks % 15 === 0) {
            fetchStats().finally(() => { state.dirty.counters = true; scheduleRender(); });
          }
          if (!hidden && state.view === 'overview' && (ticks % 15 === 0)) {
            fetchDashboardSummary().finally(() => { state.dirty.counters = true; scheduleRender(); });
          }
        } else {
          // WS is down — true fallback polling for everything.
          if (ticks % 3 === 0) {
            fetchStats().finally(() => { state.dirty.counters = true; scheduleRender(); });
          }
          if (!hidden && state.view === 'overview' && (ticks % 3 === 0)) {
            fetchDashboardSummary().finally(() => { state.dirty.counters = true; scheduleRender(); });
          }
          if (!hidden && (ticks % 6 === 0)) {
            fetchAlerts().finally(() => { state.dirty.tables = true; state.dirty.counters = true; scheduleRender(); });
            fetchEvents().finally(() => { state.dirty.tables = true; state.dirty.counters = true; scheduleRender(); });
          }
        }

        // LAN topology polling (only needed when showing LAN mode).
        if (!hidden && state.view === 'overview' && state.mapMode === 'lan') {
          fetchLanTopology().finally(() => { scheduleRender(); });
        }
      }, 10000);
    }

    let _wsBackoff = 400;
    const _WS_BACKOFF_MAX = 15000;
    let _wsReconnectTimer = null;

    function startStream() {
      try {
        if (_wsReconnectTimer) { clearTimeout(_wsReconnectTimer); _wsReconnectTimer = null; }
        if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
          try { state.ws.close(); } catch {}
        }
        const ws = new WebSocket(buildWsUrl(API.streamV2));
        state.ws = ws;

        ws.onopen = () => {
          _wsBackoff = 400; // reset on successful connection
          state.wsOk = true;
          state.dirty.ws = true;
          scheduleRender();
          // Hide reconnection banner
          const banner = document.getElementById('wsBanner');
          if (banner) banner.style.display = 'none';

          // Send Stream v2 hello early so the server can replay missed alerts and
          // apply our preferred telemetry pacing. Then retry shortly after open
          // in case the initial hello was missed due to startup delays.
          sendStreamHello({ force: true });
          setTimeout(() => sendStreamHello({ force: true }), 650);

          refreshAll().finally(() => clearUiLoadingOnce());
        };

        ws.onerror = (ev) => {
          const msg = ev?.message || 'WebSocket error';
          console.error('[WS Error]', msg);
          showToast(`WebSocket error: ${msg.slice(0, 80)}`, 'warn');
        };

        ws.onclose = (ev) => {
          state.wsOk = false;
          state.dirty.ws = true;
          scheduleRender();
          // Show reconnection banner
          const banner = document.getElementById('wsBanner');
          if (banner) banner.style.display = 'flex';
          const isClean = ev && (ev.code === 1000 || ev.code === 1001);
          const delay = isClean
            ? Math.min(400 + Math.floor(Math.random() * 200), 2000)
            : Math.min(_wsBackoff + Math.floor(Math.random() * 400), _WS_BACKOFF_MAX);
          if (!isClean) _wsBackoff = Math.min(_wsBackoff * 1.5, _WS_BACKOFF_MAX);
          else _wsBackoff = 400;
          _wsReconnectTimer = setTimeout(startStream, delay);
        };

        ws.onmessage = (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch { return; }

          if (msg?.type === 'connected_v2') {
            // v2 connected marker
            return;
          }

          if (msg?.type === 'alert_rt' && msg.data) {
            try {
              const a = msg.data;
              
              if (!a || typeof a !== 'object') {
                console.warn('[WS Alert] Invalid alert data received');
                return;
              }
              
              const key = alertKey(a);
              
              if (!key || typeof key !== 'string' || key.length < 4) {
                console.warn('[WS Alert] Failed to generate valid alert key');
                return;
              }
              
              if (!state.alertIndex.has(key)) {
                rememberKeyLRU(state.alertIndex, key, DEDUPE.maxAlertKeys);
                state.alerts.unshift(a);
                if (state.alerts.length > LIMITS.maxAlerts) {
                  state.alerts.length = LIMITS.maxAlerts;
                  try { resetEventIndexesFromLists(); } catch {}
                }
                if (state.view === 'alerts') state.dirty.tables = true;
                state.dirty.counters = true;
                scheduleRender();
              }
              
              const seq = Number(msg.seq || 0);
              if (seq > 0 && Number.isFinite(seq)) {
                if (seq > Number(state.alertSeq || 0)) {
                  state.alertSeq = seq;
                  try { localStorage.setItem('percepta_alert_seq', String(seq)); } catch {}
                }
                try { ws.send(JSON.stringify({ type: 'ack', alert_seq: seq })); } catch {}
              }
            } catch (err) {
              console.error('[WS Alert Handler] Error processing alert:', err.message);
            }
            return;
          }

          if (msg?.type === 'telemetry_rt' && msg.data) {
            state.telemetry = msg.data;
            state.dirty.counters = true;
            if (state.view === 'overview') scheduleRender();
            return;
          }

          if (msg?.type === 'sample_rt' && msg.data?.recent) {
            // Full mode: ignore sampled headers for tables.
            // Events/Overview tables use /api/search to render full events.
            return;
          }
        };
      } catch {
        // Ignore; polling will keep it live.
      }
    }

    function initShowcaseInteractions() {
      if (state._showcaseInit) return;
      state._showcaseInit = true;

      document.querySelectorAll('[data-quick-query]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const q = String(btn.getAttribute('data-quick-query') || '').trim();
          if (!q) return;
          pivotSearch(q, 'events');
        });
      });

      document.querySelectorAll('[data-quick-view]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const v = String(btn.getAttribute('data-quick-view') || '').trim();
          if (!v) return;
          setView(v);
        });
      });

      const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduceMotion) return;

      const cards = document.querySelectorAll('.card');
      cards.forEach((card) => {
        let raf = 0;
        let lx = 50;
        let ly = 50;

        const paint = () => {
          raf = 0;
          if (document.documentElement.classList.contains('perf-lite')) return;
          card.style.setProperty('--mx', `${lx}%`);
          card.style.setProperty('--my', `${ly}%`);
          card.classList.add('cardHot');
        };

        card.addEventListener('pointermove', (ev) => {
          const r = card.getBoundingClientRect();
          if (!r.width || !r.height) return;
          lx = Math.max(0, Math.min(100, ((ev.clientX - r.left) / r.width) * 100));
          ly = Math.max(0, Math.min(100, ((ev.clientY - r.top) / r.height) * 100));
          if (!raf) raf = requestAnimationFrame(paint);
        }, { passive: true });

        card.addEventListener('pointerleave', () => {
          card.classList.remove('cardHot');
        });
      });
    }

