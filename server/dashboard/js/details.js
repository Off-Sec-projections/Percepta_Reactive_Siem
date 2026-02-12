    function kvRow(k, v) {
      const kk = document.createElement('div');
      kk.className = 'k';
      kk.textContent = k;
      const vv = document.createElement('div');
      vv.className = 'v';
      if (v instanceof Node) vv.appendChild(v);
      else vv.textContent = String(v ?? '');
      return [kk, vv];
    }

    function buildRawJsonDetails(obj) {
      const d = document.createElement('details');
      d.open = false;
      const s = document.createElement('summary');
      s.textContent = 'Raw JSON';
      const p = document.createElement('pre');
      p.textContent = JSON.stringify(obj, null, 2);
      d.appendChild(s);
      d.appendChild(p);
      return d;
    }

    function buildJsonDetails(title, obj, { open = false } = {}) {
      const d = document.createElement('details');
      d.open = Boolean(open);
      const s = document.createElement('summary');
      s.textContent = String(title || 'Details');
      const p = document.createElement('pre');
      p.textContent = JSON.stringify(obj, null, 2);
      d.appendChild(s);
      d.appendChild(p);
      return d;
    }

    function getRelatedSignalsKeyFromEvent(e) {
      if (!e || typeof e !== 'object') return '';
      const meta = (e?.metadata && typeof e.metadata === 'object') ? e.metadata : {};
      const fpGlobal = String(meta?.['event.fingerprint_global'] || '').trim();
      if (fpGlobal) return fpGlobal;
      const corr = String(e?.correlation_id || '').trim();
      if (corr) return corr;
      const fp = String(meta?.['event.fingerprint'] || '').trim();
      if (fp) return fp;
      // Fallback only: hash is unique, so it's usually a poor correlation key.
      const hash = String(e?.hash || e?.event?.hash || '').trim();
      if (hash) return hash;
      return '';
    }

    function getRelatedSignalsKeyFromAlert(a) {
      if (!a || typeof a !== 'object') return '';
      const md = (a?.metadata && typeof a.metadata === 'object') ? a.metadata : {};
      const hinted = String(md?.['event.fingerprint_global'] || md?.correlation_id || md?.['event.fingerprint'] || md?.event_hash || md?.hash || '').trim();
      if (hinted) return hinted;
      const src = Array.isArray(a?.source_events) ? a.source_events : [];
      if (src.length) {
        const first = String(src[0] || '').trim();
        if (first) return first;
      }
      return '';
    }

    function buildRelatedSignalsSection({ key, agentId, title = t('relatedSignals.title'), lookbackHours = 24, limit = 25 } = {}) {
      const sec = document.createElement('div');
      sec.className = 'section';
      sec.innerHTML = `<h3>${escapeHtml(title)}</h3>`;

      const k = String(key || '').trim();
      const aid = String(agentId || '').trim();
      if (!k) {
        const m = document.createElement('div');
        m.className = 'muted';
        m.textContent = t('relatedSignals.noKey');
        sec.appendChild(m);
        return sec;
      }

      const cacheKey = `${k}|${aid}|${Number(lookbackHours) || 24}|${Number(limit) || 25}`;
      const out = document.createElement('div');
      out.className = 'muted';
      out.textContent = t('common.loading');
      sec.appendChild(out);

      const render = (payload) => {
        const items = Array.isArray(payload?.items) ? payload.items : [];
        const countsObj = (payload?.counts && typeof payload.counts === 'object') ? payload.counts : {};

        out.innerHTML = '';

        const counts = Object.entries(countsObj)
          .map(([k, v]) => ({ k: String(k || ''), v: Number(v || 0) }))
          .filter((x) => x.k && Number.isFinite(x.v) && x.v > 0)
          .sort((a, b) => b.v - a.v);

        if (counts.length) {
          const row = document.createElement('div');
          row.className = 'details-signal-chips-row';
          for (const c of counts.slice(0, 10)) {
            const chip = document.createElement('span');
            chip.className = 'chip';
            chip.textContent = `${c.k}: ${c.v}`;
            row.appendChild(chip);
          }
          out.appendChild(row);
        }

        if (!items.length) {
          const m = document.createElement('div');
          m.className = 'muted';
          m.textContent = t('relatedSignals.none');
          out.appendChild(m);
          return;
        }

        const wrap = document.createElement('div');
        wrap.className = 'tableWrap details-related-table-wrap';
        const table = document.createElement('table');
        table.innerHTML = `<thead><tr>
          <th width="170">${escapeHtml(t('tbl.time'))}</th>
          <th width="120">${escapeHtml(t('tbl.sensor'))}</th>
          <th>${escapeHtml(t('tbl.summary'))}</th>
          <th width="220">${escapeHtml(t('tbl.agent'))}</th>
          <th width="120">${escapeHtml(t('tbl.pivot'))}</th>
        </tr></thead>`;
        const tbody = document.createElement('tbody');
        for (const it of items.slice(0, limit)) {
          const tr = document.createElement('tr');
          const iso = String(it?.event_time || it?.ingest_time || '').trim();
          const ts = iso ? formatTime(iso) : '';
          const sensor = String(it?.sensor || '').trim();
          const summary = String(it?.summary || '').trim();
          const hash = String(it?.hash || '').trim();
          const agent = (() => {
            const aid = String(it?.agent_id || '').trim();
            if (aid) {
              const ord = agentOrdinalForAgentId(aid);
              return ord > 0 ? `Agent ${ord}` : 'Agent';
            }
            const hn = String(it?.agent_hostname || '').trim();
            if (hn) return hn;
            return '';
          })();
          const pivot = document.createElement('button');
          pivot.className = 'btn sm';
          pivot.textContent = t('btn.search');
          pivot.disabled = !hash;
          pivot.addEventListener('click', () => {
            if (!hash) return;
            pivotSearch(hash, 'events');
          });

          const tdPivot = document.createElement('td');
          tdPivot.appendChild(pivot);

          tr.innerHTML = `
            <td>${escapeHtml(ts)}</td>
            <td>${escapeHtml(sensor || t('common.unknown'))}</td>
            <td>${escapeHtml(shortText(summary, 140))}</td>
            <td>${escapeHtml(agent)}</td>
          `;
          tr.appendChild(tdPivot);
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        out.appendChild(wrap);
      };

      const cached = state.relatedSignals.cache.get(cacheKey);
      const now = Date.now();
      if (cached && (now - Number(cached.atMs || 0) < 30_000)) {
        render(cached.payload);
        return sec;
      }

      const doFetch = async () => {
        const url = `${API.relatedSignals}?key=${encodeURIComponent(k)}${aid ? `&agent_id=${encodeURIComponent(aid)}` : ''}&lookback_hours=${encodeURIComponent(String(lookbackHours))}&limit=${encodeURIComponent(String(limit))}`;
        const payload = await apiFetchJson(url, { timeoutMs: 4500, headers: { 'Accept': 'application/json' } });
        state.relatedSignals.cache.set(cacheKey, { atMs: Date.now(), payload });
        return payload;
      };

      const inflight = state.relatedSignals.inflight.get(cacheKey);
      const p = inflight || doFetch();
      if (!inflight) state.relatedSignals.inflight.set(cacheKey, p);

      Promise.resolve(p)
        .then((payload) => render(payload))
        .catch((err) => {
          out.className = 'muted';
          const st = Number(err?.status || 0);
          if (st === 401) {
            out.innerHTML = t('actionError.requireLoginHtml', { action: escapeHtml(title) });
            return;
          }
          if (st === 403) {
            out.textContent = t('actionError.forbiddenNeedRole', { action: title });
            return;
          }
          out.textContent = t('relatedSignals.unavailable');
        })
        .finally(() => {
          // Only clear if the same promise is still stored.
          const cur = state.relatedSignals.inflight.get(cacheKey);
          if (cur === p) state.relatedSignals.inflight.delete(cacheKey);
        });

      return sec;
    }

    function paintEventDetails(targetElId, eventObj) {
      const el = document.getElementById(targetElId);
      if (!el) return;
      clearEl(el);
      if (!eventObj) {
        el.innerHTML = `<div class="muted">${escapeHtml(t('details.selectToView'))}</div>`;
        return;
      }

      // Header section
      const summary = eventObj?.event?.summary || eventObj?.event?.original_message || eventObj?.message || '';
      const hash = eventObj?.hash || eventObj?.event?.hash || eventObj?.correlation_id || '';
      const sev = severityLabel(eventObj);
      const time = formatTime(eventPrimaryTime(eventObj));

      const header = document.createElement('div');
      header.className = 'kv';
      header.append(...kvRow(t('label.summary'), summary));
      header.append(...kvRow(t('label.severity'), sev));
      header.append(...kvRow(t('label.time'), time));
      if (hash) header.append(...kvRow(t('label.correlationHash'), hash));
      el.appendChild(header);

      // Event Core (SIEM-standard fields)
      const core = document.createElement('div');
      core.className = 'section';
      core.innerHTML = `<h3>Event Core</h3>`;
      const ck = document.createElement('div');
      ck.className = 'kv';
      const meta = eventObj?.metadata || {};
      const ev = eventObj?.event || {};
      const agent = eventObj?.agent || {};
      const eid = getEventIdValue(eventObj);
      if (ev?.provider) ck.append(...kvRow(t('label.provider'), ev.provider));
      if (eid) ck.append(...kvRow(t('label.eventId'), eid));
      if (ev?.action) ck.append(...kvRow(t('label.action'), ev.action));
      if (ev?.outcome !== undefined) ck.append(...kvRow(t('label.outcome'), ev.outcome));
      const cat = meta?.['ecs.event.category'] || categoryActionLabel(eventObj);
      if (cat) ck.append(...kvRow('Category', cat));
      if (meta?.['ecs.event.type']) ck.append(...kvRow('Type', meta['ecs.event.type']));
      if (meta?.['event.kind']) ck.append(...kvRow('Kind', meta['event.kind']));
      if (meta?.['event.dataset']) ck.append(...kvRow('Dataset', meta['event.dataset']));
      if (meta?.['event.module']) ck.append(...kvRow('Module', meta['event.module']));
      const ingestTime = formatTime(eventObj?.ingest_time || '');
      if (ingestTime) ck.append(...kvRow('Ingest time', ingestTime));
      if (meta?.['time.skew_seconds']) ck.append(...kvRow('Time skew (s)', meta['time.skew_seconds']));
      if (meta?.['event_time.corrected']) ck.append(...kvRow('Time corrected', meta['event_time.corrected']));
      if (ck.childNodes.length) core.appendChild(ck);
      else core.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(core);

      // Identity (Agent/Host/User)
      const ident = document.createElement('div');
      ident.className = 'section';
      ident.innerHTML = `<h3>Identity</h3>`;
      const ik = document.createElement('div');
      ik.className = 'kv';
      const agentNum = agentNumberLabelForEvent(eventObj);
      const agentIpVal = agentIpForEvent(eventObj);
      const agentId = eventObj?.agent?.id || eventObj?.agent_id || '';
      const hostName = hostDisplayName(eventObj);
      const userName = getBestUser(eventObj);
      if (agentNum || agentIpVal) ik.append(...kvRow(t('label.agent'), [agentNum, agentIpVal].filter(Boolean).join(' · ')));
      if (agentId) ik.append(...kvRow('Agent ID', agentId));
      if (hostName) ik.append(...kvRow(t('label.hostname'), hostName));
      if (userName) ik.append(...kvRow(t('label.user'), userName));
      if (ik.childNodes.length) ident.appendChild(ik);
      else ident.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(ident);

      // Network
      const net = eventObj?.network || {};
      const netSec = document.createElement('div');
      netSec.className = 'section';
      netSec.innerHTML = `<h3>${escapeHtml(t('section.network'))}</h3>`;
      const nk = document.createElement('div');
      nk.className = 'kv';
      if (net?.src_ip) nk.append(...kvRow(t('label.srcIp'), net.src_ip));
      if (net?.src_port) nk.append(...kvRow(t('label.srcPort'), net.src_port));
      if (net?.dst_ip) nk.append(...kvRow(t('label.dstIp'), net.dst_ip));
      if (net?.dst_port) nk.append(...kvRow(t('label.dstPort'), net.dst_port));
      if (net?.protocol) nk.append(...kvRow(t('label.protocol'), net.protocol));
      if (net?.direction !== undefined) nk.append(...kvRow(t('label.direction'), net.direction));
      if (net?.bytes_in) nk.append(...kvRow('Bytes in', net.bytes_in));
      if (net?.bytes_out) nk.append(...kvRow('Bytes out', net.bytes_out));
      if (net?.tls_sni) nk.append(...kvRow('TLS SNI', net.tls_sni));
      if (net?.ja3) nk.append(...kvRow('JA3', net.ja3));
      if (net?.ja3s) nk.append(...kvRow('JA3S', net.ja3s));
      if (nk.childNodes.length) netSec.appendChild(nk);
      else netSec.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(netSec);

      // Detection (IDS/Honeypot)
      if (isIdsEvent(eventObj) || isHoneypotEvent(eventObj)) {
        const det = document.createElement('div');
        det.className = 'section';
        det.innerHTML = `<h3>Detection</h3>`;
        const dk = document.createElement('div');
        dk.className = 'kv';
        const sig = meta?.['ids.signature'] || meta?.['suricata.signature'] || meta?.signature || '';
        const sid = meta?.['ids.sid'] || meta?.['suricata.sid'] || meta?.sid || '';
        const engine = meta?.['ids.engine'] || meta?.['sensor.kind'] || '';
        if (sig) dk.append(...kvRow('Signature', sig));
        if (sid) dk.append(...kvRow('SID', sid));
        if (engine) dk.append(...kvRow('Engine', engine));
        if (meta?.['ids.category']) dk.append(...kvRow('Category', meta['ids.category']));
        if (meta?.['ids.severity']) dk.append(...kvRow('Severity', meta['ids.severity']));
        if (meta?.['ids.action']) dk.append(...kvRow('Action', meta['ids.action']));
        if (dk.childNodes.length) det.appendChild(dk);
        else det.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
        el.appendChild(det);
      }

      // Event intelligence (meaning, why it happens, how to investigate)
      const intel = lookupEventKnowledge(eventObj);
      const intelSec = document.createElement('div');
      intelSec.className = 'section';
      intelSec.innerHTML = `<h3>${escapeHtml(t('intel.event.title'))}</h3>`;
      if (intel) {
        const box = document.createElement('div');
        box.className = 'kv';
        if (intel?.title) box.append(...kvRow(t('intel.event.what'), intel.title));
        if (intel?.meaning) box.append(...kvRow(t('intel.event.meaning'), intel.meaning));
        if (Array.isArray(intel?.why_it_happens) && intel.why_it_happens.length) box.append(...kvRow(t('intel.event.why'), intel.why_it_happens.join(' • ')));
        if (Array.isArray(intel?.investigation) && intel.investigation.length) box.append(...kvRow(t('intel.event.how'), intel.investigation.join(' • ')));
        if (Array.isArray(intel?.false_positives) && intel.false_positives.length) box.append(...kvRow(t('intel.event.falsePos'), intel.false_positives.join(' • ')));
        if (Array.isArray(intel?.related_event_ids) && intel.related_event_ids.length) {
          const wrap = document.createElement('div');
          wrap.style.display = 'flex';
          wrap.style.flexWrap = 'wrap';
          wrap.style.gap = '8px';
          for (const id of intel.related_event_ids.slice(0, 10)) {
            const b = document.createElement('button');
            b.className = 'btn sm';
            b.textContent = t('btn.searchEid', { id });
            b.addEventListener('click', () => pivotSearch(String(id), 'events'));
            wrap.appendChild(b);
          }
          box.append(...kvRow(t('label.related'), wrap));
        }
        intelSec.appendChild(box);
      } else {
        intelSec.innerHTML += `<div class="muted">${escapeHtml(t('intel.event.none'))}</div>`;
      }
      el.appendChild(intelSec);

      // SOC triage summary (fast pivots)
      const tri = document.createElement('div');
      tri.className = 'section';
      tri.innerHTML = `<h3>${escapeHtml(t('triage.title'))}</h3>`;
      const tv = document.createElement('div');
      tv.className = 'kv';

      const agentBits = [];
      if (agentNum) agentBits.push(agentNum);
      if (agentIpVal) agentBits.push(agentIpVal);
      const agentLine = agentBits.join(' · ');
      if (agentLine) tv.append(...kvRow(t('label.agent'), agentLine));

      if (hostName) tv.append(...kvRow(t('label.hostname'), hostName));

      if (ev?.provider) tv.append(...kvRow(t('label.provider'), ev.provider));
      if (eid) tv.append(...kvRow(t('label.eventId'), eid));
      if (ev?.action) tv.append(...kvRow(t('label.action'), ev.action));
      if (ev?.outcome !== undefined) tv.append(...kvRow(t('label.outcome'), ev.outcome));

      const ipVal = getBestIp(eventObj);
      if (ipVal) {
        const wrap = document.createElement('div');
        wrap.style.display = 'flex';
        wrap.style.flexWrap = 'wrap';
        wrap.style.gap = '8px';
        const val = document.createElement('span');
        val.className = 'mono';
        val.textContent = ipVal;
        wrap.appendChild(val);
        const b = document.createElement('button');
        b.className = 'btn sm';
        b.textContent = t('btn.searchIp');
        b.addEventListener('click', () => pivotSearch(ipVal, 'events'));
        wrap.appendChild(b);
        tv.append(...kvRow(t('label.primaryIp'), wrap));
      }

      // Evidence strip (SOC pivots): IPs, domains/SNI, hashes, CVEs.
      const evidence = extractEvidence(eventObj);
      const hasEvidence =
        (evidence.ips && evidence.ips.length) ||
        (evidence.domains && evidence.domains.length) ||
        (evidence.sha256s && evidence.sha256s.length) ||
        (evidence.cves && evidence.cves.length);
      if (hasEvidence) {
        const wrap = document.createElement('div');
        wrap.style.display = 'flex';
        wrap.style.flexWrap = 'wrap';
        wrap.style.gap = '8px';

        const addPill = (label, value, query) => {
          const b = document.createElement('button');
          b.className = 'btn sm';
          b.textContent = label;
          b.title = value;
          b.addEventListener('click', async () => {
            const ok = await copyTextToClipboard(value);
            if (ok) showToast(t('toast.copiedValue', { value: `<span class="mono">${escapeHtml(value)}</span>` }), undefined, undefined, { html: true });
            pivotSearch(query || value, 'events');
          });
          wrap.appendChild(b);
        };

        for (const ip of (evidence.ips || []).slice(0, 6)) addPill(`ip:${shortText(ip, 24)}`, ip, `ip:${ip}`);
        for (const d of (evidence.domains || []).slice(0, 4)) addPill(`dom:${shortText(d, 28)}`, d, d);
        for (const h of (evidence.sha256s || []).slice(0, 3)) addPill(`sha256:${h.slice(0, 10)}…`, h, `sha256:${h}`);
        for (const c of (evidence.cves || []).slice(0, 4)) addPill(c, c, `cve:${c}`);

        tv.append(...kvRow(t('label.evidence'), wrap));
      }

      // Persistent device naming by MAC (server-backed; falls back to legacy local storage).
      {
        const mac = getBestMac(eventObj);
        const current = mac ? getDeviceNameForMac(mac) : '';
        const suggested = (() => {
          const u = getBestUser(eventObj);
          if (u && u !== 'unknown') return u;
          const a = eventObj?.agent || {};
          return String(a?.hostname || a?.id || '').trim();
        })();

        const wrap = document.createElement('div');
        wrap.style.display = 'flex';
        wrap.style.flexWrap = 'wrap';
        wrap.style.gap = '8px';

        const label = document.createElement('span');
        label.className = 'mono';
        label.textContent = current || t('device.unnamed');
        wrap.appendChild(label);

        const btn = document.createElement('button');
        btn.className = 'btn sm';
        btn.textContent = current ? t('btn.renameDevice') : t('btn.nameDevice');
        btn.addEventListener('click', async () => {
          if (!mac) {
            showToast(t('device.noMac'));
            return;
          }
          const v = await uiPrompt(t('prompt.deviceNameByMac'), current || suggested || '', { title: t('btn.nameDevice'), confirmLabel: t('btn.save') });
          if (v === null) return;
          setDeviceNameForMac(mac, v);
          state.dirty.tables = true;
          state.dirty.details = true;
          scheduleRender();
        });
        wrap.appendChild(btn);

        if (current) {
          const clr = document.createElement('button');
          clr.className = 'btn sm';
          clr.textContent = t('btn.clearName');
          clr.addEventListener('click', async () => {
            if (!mac) return;
            if (!(await uiConfirm(t('confirm.clearDeviceNameMapping'), { danger: true }))) return;
            clearDeviceNameForMac(mac);
            state.dirty.tables = true;
            state.dirty.details = true;
            scheduleRender();
          });
          wrap.appendChild(clr);
        }

        tv.append(...kvRow(t('label.deviceName'), wrap));
      }

      tv.append(...kvRow(t('label.user'), getBestUser(eventObj)));

      if (net?.src_ip || net?.dst_ip) {
        const src = net?.src_ip ? `${net.src_ip}${net.src_port ? ':' + net.src_port : ''}` : '';
        const dst = net?.dst_ip ? `${net.dst_ip}${net.dst_port ? ':' + net.dst_port : ''}` : '';
        tv.append(...kvRow(t('label.flow'), `${src}${(src && dst) ? ' → ' : ''}${dst}`));
      }

      const proc = eventObj?.process || {};
      if (proc?.name) tv.append(...kvRow(t('label.process'), shortText(`${proc.name}${proc.command_line ? ' ' + proc.command_line : ''}`, 180)));

      if (hash) {
        const wrap = document.createElement('div');
        wrap.style.display = 'flex';
        wrap.style.flexWrap = 'wrap';
        wrap.style.gap = '8px';
        const val = document.createElement('span');
        val.className = 'mono';
        val.textContent = shortId(hash);
        val.title = hash;
        wrap.appendChild(val);
        const b = document.createElement('button');
        b.className = 'btn sm';
        b.textContent = t('btn.searchHash');
        b.addEventListener('click', () => pivotSearch(hash, 'events'));
        wrap.appendChild(b);
        tv.append(...kvRow(t('label.pivot'), wrap));
      }

      if (Array.isArray(eventObj?.tags) && eventObj.tags.length) tv.append(...kvRow(t('label.tags'), eventObj.tags.join(', ')));

      tri.appendChild(tv);
      el.appendChild(tri);

      if (isIdsEvent(eventObj)) {
        const idsSec = document.createElement('div');
        idsSec.className = 'section';
        idsSec.innerHTML = `<h3>IDS Actions</h3>`;
        const btn = document.createElement('button');
        btn.className = 'btn sm';
        btn.textContent = 'Suppress signature (24h)';
        btn.addEventListener('click', () => suppressSignatureForEvent(eventObj));
        idsSec.appendChild(btn);
        el.appendChild(idsSec);
      }

      // Fusion: show correlated signals across modules without duplicating pipelines.
      {
        const key = getRelatedSignalsKeyFromEvent(eventObj);
        const relatedAgentId = String(eventObj?.agent?.id || eventObj?.agent_id || '').trim();
        el.appendChild(buildRelatedSignalsSection({ key, agentId: relatedAgentId, title: t('relatedSignals.title'), lookbackHours: 24, limit: 25 }));
      }

      // Response drawer (actions + enrichment + notes)
      const responseDrawer = document.createElement('div');
      responseDrawer.className = 'section drawer';
      responseDrawer.innerHTML = '<h3>Response</h3>';
      const responseTabs = document.createElement('div');
      responseTabs.className = 'tabBar';
      const responseBody = document.createElement('div');

      const eventTabKeys = [
        { key: 'actions', label: 'Actions' },
        { key: 'enrichment', label: 'Enrichment' },
        { key: 'notes', label: 'Notes' },
      ];

      const setEventResponseTab = (key) => {
        const panes = responseBody.querySelectorAll('.responsePane');
        panes.forEach((p) => p.classList.toggle('hidden', p.getAttribute('data-tab') !== key));
        responseTabs.querySelectorAll('.tabBtn').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === key));
        if (!state.ui) state.ui = {};
        state.ui.eventResponseTab = key;
      };

      for (const t of eventTabKeys) {
        const btn = document.createElement('button');
        btn.className = 'tabBtn';
        btn.textContent = t.label;
        btn.setAttribute('data-tab', t.key);
        btn.addEventListener('click', () => setEventResponseTab(t.key));
        responseTabs.appendChild(btn);
      }

      responseDrawer.appendChild(responseTabs);
      responseDrawer.appendChild(responseBody);
      el.appendChild(responseDrawer);

      // Threat Intel (real APIs, demo-safe)
      const intelSec2 = document.createElement('div');
      intelSec2.className = 'section responsePane';
      intelSec2.setAttribute('data-tab', 'enrichment');
      intelSec2.innerHTML = `<h3>${escapeHtml(t('threatIntel.title'))}</h3>`;
      const intelBox = document.createElement('div');
      intelBox.className = 'kv';

      const ipForIntel = getBestIp(eventObj);
      const shaForIntel = getBestSha256(eventObj);
      const cves = extractCvesFromEvent(eventObj);
      const eventKey = String(state.selected?.key || '');
      state.intel.lastForKey = eventKey;
      let refreshIp = null;
      let refreshHash = null;
      let refreshKev = null;

      if (ipForIntel || shaForIntel || cves.length) {
        const intelActions = document.createElement('div');
        intelActions.className = 'actionBar';
        const intelLabel = document.createElement('label');
        intelLabel.textContent = 'Enrichment';
        intelActions.appendChild(intelLabel);

        const intelSelect = document.createElement('select');
        intelSelect.className = 'select';
        const addOpt = (value, label) => {
          const opt = document.createElement('option');
          opt.value = value;
          opt.textContent = label;
          intelSelect.appendChild(opt);
        };
        if (ipForIntel) addOpt('ip', `Refresh IP intel (${ipForIntel})`);
        if (shaForIntel) addOpt('hash', `Refresh hash intel (${shaForIntel.slice(0, 10)}…${shaForIntel.slice(-6)})`);
        if (cves.length) addOpt('kev', 'Refresh CISA KEV');
        if ((ipForIntel || shaForIntel) && cves.length) addOpt('all', 'Refresh all');

        const runBtn = document.createElement('button');
        runBtn.className = 'btn sm primary';
        runBtn.textContent = 'Run';
        runBtn.onclick = async () => {
          const val = String(intelSelect.value || '');
          if (runBtn.disabled) return;
          runBtn.disabled = true;
          const originalText = runBtn.textContent;
          runBtn.textContent = '⏳ Running…';
          try {
            if (val === 'ip' && refreshIp) await refreshIp();
            else if (val === 'hash' && refreshHash) await refreshHash();
            else if (val === 'kev' && refreshKev) await refreshKev();
            else if (val === 'all') {
              if (refreshIp) await refreshIp();
              if (refreshHash) await refreshHash();
              if (refreshKev) await refreshKev();
            }
            runBtn.textContent = '✓ Done';
            setTimeout(() => { runBtn.textContent = originalText; runBtn.disabled = false; }, 2000);
          } catch (err) {
            handleActionError(err, 'Enrichment');
            runBtn.textContent = originalText;
            runBtn.disabled = false;
          }
        };
        intelActions.appendChild(intelSelect);
        intelActions.appendChild(runBtn);
        intelSec2.appendChild(intelActions);
      }

      if (!ipForIntel && !shaForIntel) {
        intelSec2.innerHTML += `<div class="muted">${escapeHtml(t('threatIntel.noneToEnrich'))}</div>`;
      } else {
        if (ipForIntel) {
          const ipContainer = document.createElement('div');
          ipContainer.style.display = 'flex';
          ipContainer.style.flexDirection = 'column';
          ipContainer.style.gap = '8px';

          const ipWrap = document.createElement('div');
          ipWrap.style.display = 'flex';
          ipWrap.style.flexWrap = 'wrap';
          ipWrap.style.gap = '8px';
          const ipMono = document.createElement('span');
          ipMono.className = 'mono';
          ipMono.textContent = ipForIntel;
          ipWrap.appendChild(ipMono);
          const ipOut = document.createElement('span');
          ipOut.className = 'muted';
          ipOut.textContent = '…';
          ipWrap.appendChild(ipOut);
          ipContainer.appendChild(ipWrap);

          const ipActions = document.createElement('div');
          ipActions.style.display = 'flex';
          ipActions.style.flexWrap = 'wrap';
          ipActions.style.gap = '8px';
          for (const p of ['abuseipdb', 'otx', 'urlhaus']) {
            const u = intelUrlForIp(p, ipForIntel);
            if (!u) continue;
            const b = document.createElement('button');
            b.className = 'btn sm';
            b.textContent = t('btn.openProvider', { name: p });
            b.addEventListener('click', () => openExternal(u));
            ipActions.appendChild(b);
          }
          ipContainer.appendChild(ipActions);

          const ipDetails = document.createElement('div');
          ipContainer.appendChild(ipDetails);
          intelBox.append(...kvRow(t('label.ipReputation'), ipContainer));

          const renderIp = (resp) => {
            const s = summarizeIpIntel(resp);
            const parts = [];
            if (s.score !== null) parts.push(t('intel.abuseScore', { score: s.score }));
            if (s.reports !== null) parts.push(t('intel.reports', { n: s.reports }));
            if (s.otxPulses !== null) parts.push(t('intel.otxPulses', { n: s.otxPulses }));
            if (!parts.length) parts.push(t('intel.noData'));
            ipOut.textContent = parts.join(' · ');
            ipOut.classList.toggle('bad', s.score !== null && s.score >= 50);

            ipDetails.innerHTML = '';
            if (resp && typeof resp === 'object') {
              if (Array.isArray(resp.errors) && resp.errors.length) {
                const err = document.createElement('div');
                err.className = 'muted';
                err.style.fontSize = '12px';
                err.textContent = t('intel.errorsPrefix', { errors: resp.errors.join(' | ') });
                ipDetails.appendChild(err);
              }
              const providers = resp.providers && typeof resp.providers === 'object' ? resp.providers : {};
              for (const [name, obj] of Object.entries(providers)) {
                ipDetails.appendChild(buildJsonDetails(t('intel.apiResponseTitle', { name }), obj, { open: false }));
              }
            }
          };

          const fetchIpIntel = async (force = false) => {
            if (force) state.intel.ipCache.delete(ipForIntel);
            const cached = state.intel.ipCache.get(ipForIntel);
            if (cached) {
              renderIp(cached);
              return;
            }
            try {
              const resp = await apiPostJson('/api/intel/ip', { ip: ipForIntel }, { timeoutMs: 3500 });
              if (state.intel.lastForKey !== eventKey) return;
              state.intel.ipCache.set(ipForIntel, resp);
              renderIp(resp);
            } catch {
              if (state.intel.lastForKey !== eventKey) return;
              ipOut.textContent = t('intel.unavailable');
              ipDetails.innerHTML = '';
            }
          };

          refreshIp = async () => fetchIpIntel(true);
          fetchIpIntel(false);
        }

        if (shaForIntel) {
          const hContainer = document.createElement('div');
          hContainer.style.display = 'flex';
          hContainer.style.flexDirection = 'column';
          hContainer.style.gap = '8px';

          const hWrap = document.createElement('div');
          hWrap.style.display = 'flex';
          hWrap.style.flexWrap = 'wrap';
          hWrap.style.gap = '8px';
          const hMono = document.createElement('span');
          hMono.className = 'mono';
          hMono.textContent = `${shaForIntel.slice(0, 10)}…${shaForIntel.slice(-6)}`;
          hMono.title = shaForIntel;
          hWrap.appendChild(hMono);
          const hOut = document.createElement('span');
          hOut.className = 'muted';
          hOut.textContent = '…';
          hWrap.appendChild(hOut);
          hContainer.appendChild(hWrap);

          const hActions = document.createElement('div');
          hActions.style.display = 'flex';
          hActions.style.flexWrap = 'wrap';
          hActions.style.gap = '8px';
          for (const p of ['malwarebazaar', 'otx']) {
            const u = intelUrlForHash(p, shaForIntel);
            if (!u) continue;
            const b = document.createElement('button');
            b.className = 'btn sm';
            b.textContent = t('btn.openProvider', { name: p });
            b.addEventListener('click', () => openExternal(u));
            hActions.appendChild(b);
          }
          hContainer.appendChild(hActions);

          const hDetails = document.createElement('div');
          hContainer.appendChild(hDetails);
          intelBox.append(...kvRow(t('label.sha256Reputation'), hContainer));

          const renderHash = (resp) => {
            const s = summarizeHashIntel(resp);
            const parts = [];
            if (s.mbStatus) parts.push(t('intel.malwarebazaarStatus', { status: s.mbStatus }));
            if (s.mbFamily) parts.push(t('intel.familyEq', { value: s.mbFamily }));
            if (s.mbTags.length) parts.push(t('intel.tagsEq', { value: s.mbTags.join(', ') }));
            if (!parts.length) parts.push(t('intel.noData'));
            hOut.textContent = parts.join(' · ');
            hOut.classList.toggle('bad', s.mbStatus === 'ok' && Boolean(s.mbFamily));

            hDetails.innerHTML = '';
            if (resp && typeof resp === 'object') {
              if (Array.isArray(resp.errors) && resp.errors.length) {
                const err = document.createElement('div');
                err.className = 'muted';
                err.style.fontSize = '12px';
                err.textContent = t('intel.errorsPrefix', { errors: resp.errors.join(' | ') });
                hDetails.appendChild(err);
              }
              const providers = resp.providers && typeof resp.providers === 'object' ? resp.providers : {};
              for (const [name, obj] of Object.entries(providers)) {
                hDetails.appendChild(buildJsonDetails(t('intel.apiResponseTitle', { name }), obj, { open: false }));
              }
            }
          };

          const fetchHashIntel = async (force = false) => {
            if (force) state.intel.hashCache.delete(shaForIntel);
            const cachedH = state.intel.hashCache.get(shaForIntel);
            if (cachedH) {
              renderHash(cachedH);
              return;
            }
            try {
              const resp = await apiPostJson('/api/intel/hash', { sha256: shaForIntel }, { timeoutMs: 4500 });
              if (state.intel.lastForKey !== eventKey) return;
              state.intel.hashCache.set(shaForIntel, resp);
              renderHash(resp);
            } catch {
              if (state.intel.lastForKey !== eventKey) return;
              hOut.textContent = t('intel.unavailable');
              hDetails.innerHTML = '';
            }
          };

          refreshHash = async () => fetchHashIntel(true);
          fetchHashIntel(false);
        }

        // CISA KEV checks (keyless) for any CVEs visible in this event.
        if (cves.length) {
          const kevWrap = document.createElement('div');
          kevWrap.style.display = 'flex';
          kevWrap.style.flexWrap = 'wrap';
          kevWrap.style.gap = '8px';

          const kevItems = [];

          for (const cve of cves.slice(0, 8)) {
            const pill = document.createElement('span');
            pill.className = 'chip';
            pill.textContent = `${cve}: …`;
            kevWrap.appendChild(pill);

            const renderKev = (resp) => {
              const ok = Boolean(resp && resp.ok);
              const inKev = Boolean(resp && resp.in_kev);
              if (!ok) {
                pill.textContent = `${cve}: unavailable`;
                pill.classList.remove('bad');
                return;
              }
              pill.textContent = inKev ? `${cve}: KEV (known exploited)` : `${cve}: not in KEV`;
              pill.classList.toggle('bad', inKev);
            };
            kevItems.push({ cve, pill, renderKev });
          }

          const fetchKev = async (force = false) => {
            for (const item of kevItems) {
              const { cve, pill, renderKev } = item;
              if (force) state.intel.kevCache.delete(cve);
              const cached = state.intel.kevCache.get(cve);
              if (cached) {
                renderKev(cached);
                continue;
              }
              try {
                const resp = await apiPostJson('/api/intel/kev', { cve }, { timeoutMs: 4500 });
                if (state.intel.lastForKey !== eventKey) return;
                state.intel.kevCache.set(cve, resp);
                renderKev(resp);
              } catch {
                if (state.intel.lastForKey !== eventKey) return;
                pill.textContent = `${cve}: unavailable`;
              }
            }
          };

          refreshKev = async () => fetchKev(true);
          fetchKev(false);

          intelBox.append(...kvRow(t('label.cisaKev'), kevWrap));
        }

        const st = state.intel.status;
        if (st && typeof st === 'object') {
          const enabled = [];
          if (st.abuseipdb) enabled.push('AbuseIPDB');
          if (st.otx) enabled.push('OTX');
          if (st.malwarebazaar) enabled.push('MalwareBazaar');
          if (st.cisa_kev) enabled.push('CISA KEV');
          if (!enabled.length) enabled.push('none');
          const note = document.createElement('div');
          note.className = 'muted';
          note.style.fontSize = '12px';
          note.textContent = t('threatIntel.configured', { list: enabled.join(', ') });
          intelSec2.appendChild(note);

          const cb = st.circuit_breaker;
          if (cb && cb.active) {
            const cbWarn = document.createElement('div');
            cbWarn.className = 'muted';
            cbWarn.style.fontSize = '12px';
            cbWarn.style.color = 'var(--warn)';
            const waitSec = Number(cb.retry_after_seconds || 0);
            const failCount = Number(cb.failures_in_window || 0);
            cbWarn.textContent = `Threat intel lookups temporarily paused (circuit breaker): ${failCount} recent failures • retry in ${waitSec}s`;
            intelSec2.appendChild(cbWarn);
          }
        }
      }

      if (intelBox.childNodes.length) intelSec2.appendChild(intelBox);
      responseBody.appendChild(intelSec2);

      // Agent/Host
      // (The detailed section remains below for full forensics.)
      const agentHost = agent?.hostname || '';
      const agentIp = agent?.ip || '';
      const agentMac = agent?.mac || '';
      const os = agent?.os || {};

      const agentSec = document.createElement('div');
      agentSec.className = 'section';
      agentSec.innerHTML = `<h3>${escapeHtml(t('section.agentHost'))}</h3>`;
      const kv = document.createElement('div');
      kv.className = 'kv';
      if (agentId) kv.append(...kvRow(t('label.agentId'), agentId));
      if (agentHost) kv.append(...kvRow(t('label.hostname'), agentHost));
      if (agentIp) kv.append(...kvRow(t('label.agentIp'), agentIp));
      if (agentMac) kv.append(...kvRow(t('label.agentMac'), agentMac));
      if (os?.name) kv.append(...kvRow(t('label.os'), `${os.name}${os.version ? ' ' + os.version : ''}`));
      if (os?.kernel) kv.append(...kvRow(t('label.kernel'), os.kernel));
      const hostIpVal = eventObj?.host?.ip;
      const hostMacVal = eventObj?.host?.mac;
      const hostIpsJoined = Array.isArray(hostIpVal) ? hostIpVal.join(', ') : (hostIpVal ? String(hostIpVal) : '');
      const hostMacsJoined = Array.isArray(hostMacVal) ? hostMacVal.join(', ') : (hostMacVal ? String(hostMacVal) : '');
      if (hostIpsJoined) kv.append(...kvRow(t('label.hostIps'), hostIpsJoined));
      if (hostMacsJoined) kv.append(...kvRow(t('label.hostMacs'), hostMacsJoined));
      agentSec.appendChild(kv);
      el.appendChild(agentSec);

      // User
      const userObj = eventObj?.user || {};
      const userSec = document.createElement('div');
      userSec.className = 'section';
      userSec.innerHTML = `<h3>${escapeHtml(t('section.user'))}</h3>`;
      const uk = document.createElement('div');
      uk.className = 'kv';
      if (userObj?.name) uk.append(...kvRow(t('label.name'), userObj.name));
      if (userObj?.domain) uk.append(...kvRow(t('label.domain'), userObj.domain));
      if (userObj?.id) uk.append(...kvRow(t('label.id'), userObj.id));
      if (Array.isArray(userObj?.privileges) && userObj.privileges.length) uk.append(...kvRow(t('label.privileges'), userObj.privileges.join(', ')));
      if (uk.childNodes.length) userSec.appendChild(uk);
      else userSec.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(userSec);

      // Event core
      const evCore = eventObj?.event || {};
      const coreSec = document.createElement('div');
      coreSec.className = 'section';
      coreSec.innerHTML = `<h3>${escapeHtml(t('section.event'))}</h3>`;
      const ek = document.createElement('div');
      ek.className = 'kv';
      if (evCore?.provider) ek.append(...kvRow(t('label.provider'), evCore.provider));
      if (evCore?.event_id !== undefined) ek.append(...kvRow(t('label.eventId'), evCore.event_id));
      if (evCore?.record_id !== undefined) ek.append(...kvRow(t('label.recordId'), evCore.record_id));
      if (evCore?.category !== undefined) ek.append(...kvRow(t('label.category'), evCore.category));
      if (evCore?.action) ek.append(...kvRow(t('label.action'), evCore.action));
      if (evCore?.outcome !== undefined) ek.append(...kvRow(t('label.outcome'), evCore.outcome));
      if (evCore?.level) ek.append(...kvRow(t('label.level'), evCore.level));
      if (evCore?.original_message) ek.append(...kvRow(t('label.originalMessage'), evCore.original_message));
      coreSec.appendChild(ek);
      el.appendChild(coreSec);

      // Network
      const netObj = eventObj?.network || {};
      const netSec2 = document.createElement('div');
      netSec2.className = 'section';
      netSec2.innerHTML = `<h3>${escapeHtml(t('section.network'))}</h3>`;
      const nk2 = document.createElement('div');
      nk2.className = 'kv';
      if (netObj?.src_ip) nk2.append(...kvRow(t('label.src'), `${netObj.src_ip}${netObj.src_port ? ':' + netObj.src_port : ''}`));
      if (netObj?.dst_ip) nk2.append(...kvRow(t('label.dst'), `${netObj.dst_ip}${netObj.dst_port ? ':' + netObj.dst_port : ''}`));
      if (netObj?.protocol) nk2.append(...kvRow(t('label.protocol'), netObj.protocol));
      if (netObj?.direction !== undefined) nk2.append(...kvRow(t('label.direction'), netObj.direction));
      if (netObj?.bytes_in !== undefined && Number(netObj.bytes_in) > 0) nk2.append(...kvRow(t('label.bytesIn'), Number(netObj.bytes_in).toLocaleString()));
      if (netObj?.bytes_out !== undefined && Number(netObj.bytes_out) > 0) nk2.append(...kvRow(t('label.bytesOut'), Number(netObj.bytes_out).toLocaleString()));
      if (netObj?.flow_duration_ms !== undefined && Number(netObj.flow_duration_ms) > 0) nk2.append(...kvRow(t('label.flowDurationMs'), Number(netObj.flow_duration_ms).toLocaleString()));
      if (netObj?.tls_sni) nk2.append(...kvRow(t('label.tlsSni'), netObj.tls_sni));
      if (netObj?.ja3) nk2.append(...kvRow('JA3', netObj.ja3));
      if (netObj?.ja3s) nk2.append(...kvRow('JA3S', netObj.ja3s));
      if (netObj?.tls_cert_subject) nk2.append(...kvRow(t('label.tlsCertSubject'), netObj.tls_cert_subject));
      if (netObj?.tls_cert_issuer) nk2.append(...kvRow(t('label.tlsCertIssuer'), netObj.tls_cert_issuer));
      if (nk2.childNodes.length) netSec2.appendChild(nk2);
      else netSec2.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(netSec2);

      // GeoIP enrichment for source/destination IPs
      {
        const ipsToLookup = [netObj?.src_ip, netObj?.dst_ip, eventObj?.source_ip, eventObj?.dest_ip].filter(Boolean);
        const uniqueIps = [...new Set(ipsToLookup)].filter(ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.') && ip !== '::1');
        if (uniqueIps.length > 0) {
          // Trigger batch lookup for any uncached IPs
          const uncachedIps = uniqueIps.filter(ip => !state.geoip.cache.has(ip));
          if (uncachedIps.length > 0) {
            try { kickGeoipBatch(uncachedIps); } catch {}
          }
          const geoSec = document.createElement('div');
          geoSec.className = 'section';
          geoSec.innerHTML = '<h3>GeoIP</h3>';
          const gk = document.createElement('div');
          gk.className = 'kv';
          let hasGeo = false;
          for (const ip of uniqueIps) {
            const geo = state.geoip.cache.get(ip);
            if (geo) {
              const parts = [geo.city, geo.country].filter(Boolean).join(', ');
              gk.append(...kvRow(ip, parts || `${geo.lat.toFixed(2)}, ${geo.lon.toFixed(2)}`));
              hasGeo = true;
            }
          }
          if (hasGeo) {
            geoSec.appendChild(gk);
            el.appendChild(geoSec);
          } else if (state.geoip.available === true) {
            geoSec.innerHTML += '<div class="muted text-12">GeoIP lookup pending…</div>';
            el.appendChild(geoSec);
          }
        }
      }

      // Threat Intelligence enrichment
      {
        const ipsForIntel = [netObj?.src_ip, netObj?.dst_ip, eventObj?.source_ip, eventObj?.dest_ip].filter(Boolean);
        const hashes = [];
        const procHash = eventObj?.process?.hash;
        const fileHash = eventObj?.file?.hash;
        if (procHash && typeof procHash === 'object') {
          if (procHash.sha256) hashes.push(procHash.sha256);
        }
        if (fileHash && typeof fileHash === 'object') {
          if (fileHash.sha256) hashes.push(fileHash.sha256);
        }
        const uniqueIntelIps = [...new Set(ipsForIntel)].filter(ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.') && ip !== '::1');

        if (uniqueIntelIps.length > 0 || hashes.length > 0) {
          const intelSec = document.createElement('div');
          intelSec.className = 'section';
          intelSec.innerHTML = '<h3>Threat Intelligence</h3>';
          const intelContainer = document.createElement('div');
          intelContainer.className = 'kv';

          for (const ip of uniqueIntelIps) {
            const btn = document.createElement('button');
            btn.className = 'btnSm';
            btn.textContent = `Lookup ${ip}`;
            btn.style.cssText = 'margin:2px 4px 2px 0;';
            btn.addEventListener('click', async () => {
              btn.disabled = true; btn.textContent = 'Checking…';
              try {
                const data = await apiPostJson('/api/intel/ip', { ip }, { timeoutMs: 10000 });
                const parts = [];
                if (data?.abuseipdb?.abuse_confidence_score !== undefined) parts.push(`AbuseIPDB: ${data.abuseipdb.abuse_confidence_score}%`);
                if (data?.otx?.pulse_count !== undefined) parts.push(`OTX: ${data.otx.pulse_count} pulses`);
                if (data?.urlhaus?.urls_count !== undefined) parts.push(`URLhaus: ${data.urlhaus.urls_count} URLs`);
                btn.textContent = parts.length > 0 ? parts.join(' · ') : `${ip}: clean`;
                btn.classList.toggle('danger', (data?.abuseipdb?.abuse_confidence_score || 0) > 50);
              } catch { btn.textContent = `${ip}: lookup failed`; }
            });
            intelContainer.appendChild(btn);
          }

          for (const hash of hashes) {
            const btn = document.createElement('button');
            btn.className = 'btnSm';
            btn.textContent = `Hash ${hash.substring(0, 12)}…`;
            btn.style.cssText = 'margin:2px 4px 2px 0;';
            btn.addEventListener('click', async () => {
              btn.disabled = true; btn.textContent = 'Checking…';
              try {
                const data = await apiPostJson('/api/intel/hash', { hash }, { timeoutMs: 10000 });
                if (data?.malware_bazaar?.file_type) {
                  btn.textContent = `${data.malware_bazaar.signature || 'Malware'} (${data.malware_bazaar.file_type})`;
                  btn.classList.add('danger');
                } else {
                  btn.textContent = `${hash.substring(0, 12)}: not found`;
                }
              } catch { btn.textContent = `${hash.substring(0, 12)}: lookup failed`; }
            });
            intelContainer.appendChild(btn);
          }

          intelSec.appendChild(intelContainer);
          el.appendChild(intelSec);
        }
      }

      // Process
      const procObj = eventObj?.process || {};
      const parentProc = eventObj?.process?.parent || eventObj?.parent_process || {};
      const procSec = document.createElement('div');
      procSec.className = 'section';
      procSec.innerHTML = `<h3>${escapeHtml(t('section.process'))}</h3>`;
      const pk = document.createElement('div');
      pk.className = 'kv';
      if (procObj?.pid !== undefined) pk.append(...kvRow('PID', procObj.pid));
      if (procObj?.ppid !== undefined) pk.append(...kvRow('PPID', procObj.ppid));
      if (procObj?.name) pk.append(...kvRow(t('label.name'), procObj.name));
      if (procObj?.executable || procObj?.exe) pk.append(...kvRow('Executable', procObj.executable || procObj.exe));
      if (procObj?.command_line) pk.append(...kvRow(t('label.commandLine'), procObj.command_line));
      if (procObj?.working_directory || procObj?.cwd) pk.append(...kvRow('Working Dir', procObj.working_directory || procObj.cwd));
      if (procObj?.user || procObj?.user_name) pk.append(...kvRow('User', procObj.user || procObj.user_name));
      if (procObj?.start_time) pk.append(...kvRow('Started', new Date(procObj.start_time * 1000).toLocaleString()));
      if (procObj?.integrity_level) pk.append(...kvRow('Integrity', procObj.integrity_level));
      if (procObj?.hash && typeof procObj.hash === 'object') pk.append(...kvRow(t('label.hashes'), JSON.stringify(procObj.hash)));
      // Parent process info
      if (parentProc?.name || parentProc?.pid !== undefined) {
        const parentLabel = [parentProc.name, parentProc.pid !== undefined ? `(PID ${parentProc.pid})` : ''].filter(Boolean).join(' ');
        pk.append(...kvRow('Parent', parentLabel));
      }
      if (parentProc?.command_line) pk.append(...kvRow('Parent Cmd', parentProc.command_line));
      if (pk.childNodes.length) procSec.appendChild(pk);
      else procSec.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(procSec);

      // File / Registry
      const file = eventObj?.file || {};
      const reg = eventObj?.registry || {};
      const frSec = document.createElement('div');
      frSec.className = 'section';
      frSec.innerHTML = `<h3>${escapeHtml(t('section.fileRegistry'))}</h3>`;
      const fk = document.createElement('div');
      fk.className = 'kv';
      if (file?.path) fk.append(...kvRow(t('label.filePath'), file.path));
      if (file?.name) fk.append(...kvRow('Filename', file.name));
      if (file?.operation !== undefined) fk.append(...kvRow(t('label.fileOp'), file.operation));
      if (file?.size !== undefined) fk.append(...kvRow('Size', Number(file.size).toLocaleString() + ' bytes'));
      if (file?.owner) fk.append(...kvRow('Owner', file.owner));
      if (file?.group) fk.append(...kvRow('Group', file.group));
      if (file?.permissions) fk.append(...kvRow(t('label.permissions'), file.permissions));
      if (file?.created) fk.append(...kvRow('Created', typeof file.created === 'number' ? new Date(file.created * 1000).toLocaleString() : file.created));
      if (file?.modified) fk.append(...kvRow('Modified', typeof file.modified === 'number' ? new Date(file.modified * 1000).toLocaleString() : file.modified));
      if (file?.hash && typeof file.hash === 'object') fk.append(...kvRow(t('label.fileHashes'), JSON.stringify(file.hash)));
      if (reg?.path) fk.append(...kvRow(t('label.registryPath'), reg.path));
      if (reg?.key) fk.append(...kvRow('Registry Key', reg.key));
      if (reg?.value) fk.append(...kvRow(t('label.registryValue'), reg.value));
      if (reg?.data_type) fk.append(...kvRow('Data Type', reg.data_type));
      if (reg?.old_value) fk.append(...kvRow('Old Value', reg.old_value));
      if (fk.childNodes.length) frSec.appendChild(fk);
      else frSec.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(frSec);

      // Metadata/Tags
      const metaSec = document.createElement('div');
      metaSec.className = 'section';
      metaSec.innerHTML = `<h3>${escapeHtml(t('section.metadata'))}</h3>`;
      const mk = document.createElement('div');
      mk.className = 'kv';
      if (Array.isArray(eventObj?.tags) && eventObj.tags.length) mk.append(...kvRow(t('label.tags'), eventObj.tags.join(', ')));
      if (eventObj?.threat_indicator) mk.append(...kvRow(t('label.threatIndicator'), eventObj.threat_indicator));
      if (eventObj?.threat_source) mk.append(...kvRow(t('label.threatSource'), eventObj.threat_source));
      if (eventObj?.metadata && typeof eventObj.metadata === 'object') {
        const skip = new Set([
          'ecs.version', 'event.kind', 'event.dataset', 'event.module', 'ecs.event.category',
          'ecs.event.type', 'time.skew_seconds', 'time.skew_bucket', 'event_time.corrected',
          'ids.signature', 'ids.sid', 'ids.engine', 'ids.category', 'ids.severity', 'ids.action',
          'suricata.signature', 'suricata.sid', 'signature', 'sid',
        ]);
        const entries = Object.entries(eventObj.metadata)
          .filter(([k, v]) => typeof k === 'string' && typeof v === 'string')
          .filter(([k]) => !skip.has(k))
          .sort(([a], [b]) => a.localeCompare(b));
        const max = 60;
        let shown = 0;
        for (const [k, v] of entries) {
          if (!k) continue;
          mk.append(...kvRow(k, v));
          shown += 1;
          if (shown >= max) break;
        }
        if (entries.length > max) mk.append(...kvRow('…', t('meta.moreFields', { n: entries.length - max })));
      }

      if (mk.childNodes.length) metaSec.appendChild(mk);
      else metaSec.innerHTML += `<div class="muted">${escapeHtml(t('common.none'))}</div>`;
      el.appendChild(metaSec);

      // Actions
      const actions = document.createElement('div');
      actions.className = 'section responsePane';
      actions.setAttribute('data-tab', 'actions');
      actions.innerHTML = `<h3>${escapeHtml(t('section.actions'))}</h3>`;
      const btnRow = document.createElement('div');
      btnRow.style.display = 'flex';
      btnRow.style.gap = '8px';
      btnRow.style.flexWrap = 'wrap';

      const addSmallBtn = (label, onClick, { cls = 'btn sm', title = '' } = {}) => {
        const b = document.createElement('button');
        b.className = cls;
        b.textContent = label;
        if (title) b.title = title;
        b.addEventListener('click', onClick);
        btnRow.appendChild(b);
        return b;
      };

      const ipForActions = getBestIp(eventObj);
      const shaForActions = getBestSha256(eventObj);
      const userForActions = eventObj?.user?.name ? String(eventObj.user.name) : '';
      const procForActions = eventObj?.process?.name ? String(eventObj.process.name) : '';

      if (ipForActions) {
        addSmallBtn(t('btn.copyIp'), async () => {
          const ok = await copyTextToClipboard(ipForActions);
          showToast(ok ? t('toast.copiedIp') : t('toast.copyFailedClipboard'));
        });
        addSmallBtn('AbuseIPDB', () => openExternal(intelUrlForIp('abuseipdb', ipForActions)));
        addSmallBtn('OTX', () => openExternal(intelUrlForIp('otx', ipForActions)));
        addSmallBtn('URLhaus', () => openExternal(intelUrlForIp('urlhaus', ipForActions)));
      }

      if (shaForActions) {
        addSmallBtn(t('btn.copySha256'), async () => {
          const ok = await copyTextToClipboard(shaForActions);
          showToast(ok ? t('toast.copiedSha256') : t('toast.copyFailedClipboard'));
        });
        addSmallBtn('MalwareBazaar', () => openExternal(intelUrlForHash('malwarebazaar', shaForActions)));
        addSmallBtn('OTX file', () => openExternal(intelUrlForHash('otx', shaForActions)));
      }

      if (userForActions) addSmallBtn(t('btn.searchUser'), () => pivotSearch(userForActions, 'events'));
      if (procForActions) addSmallBtn(t('btn.searchProcess'), () => pivotSearch(procForActions, 'events'));

      addSmallBtn(t('btn.copyRawJson'), async () => {
        const ok = await copyTextToClipboard(JSON.stringify(eventObj));
        showToast(ok ? t('toast.copiedRawJson') : t('toast.copyFailedClipboard'));
      });

      addSmallBtn(t('btn.downloadEventJson'), () => {
        const ts = new Date().toISOString().replaceAll(':', '-');
        const key = String(eventKey(eventObj) || 'event');
        downloadText(`percepta-event-${key}-${ts}.json`, JSON.stringify(eventObj, null, 2), 'application/json;charset=utf-8');
      });

      const addBtn = document.createElement('button');
      addBtn.className = 'btn primary';
      addBtn.textContent = t('btn.addToAlert');
      addBtn.onclick = async () => {
        try {
          const eventHash = String(getEventHash(eventObj) || '').trim();
          const summary = String(eventObj?.event?.summary || eventObj?.event?.original_message || eventObj?.message || 'Manual alert').trim();
          const agentId = String(eventObj?.agent?.id || eventObj?.agent_id || '').trim();
          const agentHostname = String(eventObj?.agent?.hostname || eventObj?.agent_hostname || '').trim();

          const res = await apiRequestJson(API.alertsManual, {
            method: 'POST',
            timeoutMs: 3500,
            bodyObj: {
              event_hash: eventHash,
              agent_id: agentId,
              agent_hostname: agentHostname,
              summary,
              event: eventObj,
            }
          });

          await fetchAlerts();
          setView('alerts');
          state.dirty.tables = true;
          scheduleRender();
          if (res && res.id) showToast(t('toast.alertCreatedWithId', { id: escapeHtml(String(res.id)) }));
          else showToast(t('toast.alertCreated'));
        } catch (err) {
          handleActionError(err, t('btn.addToAlert'));
        }
      };
      btnRow.appendChild(addBtn);
      actions.appendChild(btnRow);
      responseBody.appendChild(actions);

      // Analyst Notes (local)
      const notesSec = document.createElement('div');
      notesSec.className = 'section responsePane';
      notesSec.setAttribute('data-tab', 'notes');
      notesSec.innerHTML = `<h3>${escapeHtml(t('section.analystNotes'))}</h3>`;
      const noteWrap = document.createElement('div');
      noteWrap.style.display = 'flex';
      noteWrap.style.flexDirection = 'column';
      noteWrap.style.gap = '8px';

      const noteKey = (() => {
        const h = String(hash || '').trim();
        if (h) return `percepta.notes.v1:${h}`;
        const k = String(eventKey(eventObj) || state.selected?.key || '').trim();
        return k ? `percepta.notes.v1:${k}` : 'percepta.notes.v1:unknown';
      })();

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
      noteMeta.textContent = t('notes.notSavedYet');

      try {
        const existing = localStorage.getItem(noteKey) || '';
        noteArea.value = existing;
        if (existing) noteMeta.textContent = t('notes.loadedFromLocal');
        else noteMeta.textContent = t('notes.empty');
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

      noteWrap.appendChild(noteArea);
      noteWrap.appendChild(noteMeta);
      notesSec.appendChild(noteWrap);
      responseBody.appendChild(notesSec);

      // Default response tab
      const defaultEventTab = (state.ui && state.ui.eventResponseTab) ? state.ui.eventResponseTab : 'actions';
      setEventResponseTab(defaultEventTab);

      // Raw JSON
      const rawSec = document.createElement('div');
      rawSec.className = 'section';
      rawSec.innerHTML = `<h3>${escapeHtml(t('section.raw'))}</h3>`;
      rawSec.appendChild(buildRawJsonDetails(eventObj));
      el.appendChild(rawSec);
    }

