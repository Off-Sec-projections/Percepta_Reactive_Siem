    function paintKpiStrip(hostId, pills) {
      const host = document.getElementById(hostId);
      if (!host) return;
      const rows = Array.isArray(pills) ? pills : [];
      const sig = JSON.stringify(rows);
      if (host.dataset.sig === sig) return;
      host.dataset.sig = sig;
      clearEl(host);
      for (const p of rows) {
        if (!p || p.v == null) continue;
        const el = document.createElement('span');
        el.className = 'kpiPill';
        const k = String(p.k || '').trim();
        const v = Number(p.v);
        const txt = Number.isFinite(v) ? v.toLocaleString() : String(p.v);
        el.innerHTML = `${escapeHtml(t(k) || k)} <strong>${escapeHtml(txt)}</strong>`;
        host.appendChild(el);
      }
    }

    function clearEl(el) {
      if (!el) return;
      // Fast path (modern browsers)
      if (typeof el.replaceChildren === 'function') {
        el.replaceChildren();
        return;
      }
      while (el.firstChild) el.removeChild(el.firstChild);
    }

    function buildSevPill(cls, text) {
      const span = document.createElement('span');
      span.className = `sev ${cls}`;
      span.textContent = text;
      return span;
    }

    function providerToDisplayName(provider) {
      const p = String(provider || '').trim();
      if (!p) return '';
      // Common Windows providers: shorten aggressively.
      if (/^microsoft-windows-/i.test(p)) {
        const rest = p.replace(/^microsoft-windows-/i, '');
        return rest.replaceAll('-', ' ').trim();
      }
      return p;
    }

    function metaStr(e, key) {
      const meta = e?.metadata && typeof e.metadata === 'object' ? e.metadata : null;
      if (!meta) return '';
      const v = meta[key];
      return String(v ?? '').trim();
    }

    function metaFirst(e, keys) {
      for (const k of keys) {
        const v = metaStr(e, k);
        if (v) return v;
      }
      return '';
    }

    function displaySummary(e) {
      const ev = e?.event || {};
      const raw = String(ev?.summary || '').trim();
      if (raw && !/^windows\s+system\s+event\b/i.test(raw)) return shortText(raw, 140);

      const intel = lookupEventKnowledge(e);
      if (intel?.title) return shortText(String(intel.title), 140);

      const provider = providerToDisplayName(ev?.provider);
      if (provider) return shortText(provider, 140);

      const orig = String(ev?.original_message || e?.message || '').trim();
      if (orig) return shortText(orig.replace(/\s+/g, ' '), 140);

      const catAct = categoryActionLabel(e);
      if (catAct) return shortText(catAct, 140);

      const obj = objectLabel(e);
      if (obj) return shortText(obj, 140);

      return 'Event';
    }

    function outcomeLabel(e) {
      const v = e?.event?.outcome ?? e?.outcome;
      if (v === 0 || String(v) === '0') return 'info';
      if (v === 1 || String(v) === '1') return 'success';
      if (v === 2 || String(v) === '2') return 'failure';
      if (v === 3 || String(v) === '3') return 'blocked';
      const s = String(v ?? '').toLowerCase().trim();
      if (!s) return '';
      if (s.includes('success')) return 'success';
      if (s.includes('fail')) return 'failure';
      if (s.includes('block')) return 'blocked';
      return s;
    }

    function categoryLabel(e) {
      const c = e?.event?.category;
      const map = { 1: 'AUTH', 2: 'NETWORK', 3: 'FILE', 4: 'PROCESS', 5: 'REGISTRY', 6: 'SYSTEM', 7: 'OTHER' };
      if (typeof c === 'number' && map[c]) return map[c];
      const s = String(c ?? '').trim();
      return s && s !== '0' ? s : '';
    }

    function categoryActionLabel(e) {
      const cat = categoryLabel(e);
      const act = String(e?.event?.action || '').trim();
      if (cat && act) return `${cat}: ${act}`;
      return cat || act || '';
    }

    function actorLabel(e) {
      return getBestUser(e) || String(e?.process?.name || '').trim();
    }

    function hostLabel(e) {
      const agent = e?.agent || {};
      const host = e?.host || {};

      const primary = metaFirst(e, [
        'agent.display_name',
        'host.hostname',
        'host.name',
        'winlog.computer',
        'winlog.computer_name',
        'winlog.computerName',
        'winlog.event_data.ComputerName',
        'winlog.event_data.WorkstationName',
        'hostname',
        'agent_hostname',
      ]);
      if (primary) return primary;

      const structured = String(host?.hostname || host?.name || '').trim();
      if (structured) return structured;

      const agentHost = String(agent?.hostname || '').trim();
      if (agentHost) return agentHost;

      // Last resort: use workstation / IP hint so the table isn't blank.
      const srcHost = metaFirst(e, ['norm.src_host']);
      if (srcHost) return srcHost;
      const ip = metaFirst(e, ['norm.host_ip', 'norm.src_ip', 'norm.client_ip']);
      return ip;
    }

    function isPrivateIpv4ForDisplay(ip) {
      const s = String(ip || '').trim();
      if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) return false;
      const p = s.split('.').map((x) => Number(x));
      if (p.length !== 4 || p.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;
      if (p[0] === 10) return true;
      if (p[0] === 127) return true;
      if (p[0] === 169 && p[1] === 254) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
      if (p[0] === 0) return true;
      return false;
    }

    function pickBestIpCandidate(candidates) {
      const ips = (Array.isArray(candidates) ? candidates : [])
        .map((v) => String(v || '').trim())
        .filter(Boolean);
      if (!ips.length) return '';
      const publicFirst = ips.find((ip) => !isPrivateIpv4ForDisplay(ip));
      return publicFirst || ips[0];
    }

    function srcLabel(e) {
      const n = e?.network || {};
      const ip = pickBestIpCandidate([
        n?.src_ip,
        metaFirst(e, [
        'norm.src_ip',
        'norm.client_ip',
        'attacker_ip',
        'source_ip',
        'src_ip',
        'winlog.event_data.SourceAddress',
        'winlog.event_data.IpAddress',
        'winlog.event_data.SourceNetworkAddress',
        'winlog.event_data.ClientAddress',
        'winlog.event_data.SourceIp',
        ]),
      ]);
      const port = (n?.src_port ? String(n.src_port) : '') || metaFirst(e, [
        'norm.src_port',
        'winlog.event_data.SourcePort',
        'winlog.event_data.IpPort',
        'winlog.event_data.ClientPort',
      ]);
      return ip ? `${ip}${port ? ':' + port : ''}` : '';
    }

    function dstLabel(e) {
      const n = e?.network || {};
      const ip = pickBestIpCandidate([
        n?.dst_ip,
        metaFirst(e, [
        'norm.dst_ip',
        'destination_ip',
        'dst_ip',
        'winlog.event_data.DestAddress',
        'winlog.event_data.DestinationAddress',
        'winlog.event_data.DestinationIp',
        ]),
      ]);
      const port = (n?.dst_port ? String(n.dst_port) : '') || metaFirst(e, [
        'norm.dst_port',
        'winlog.event_data.DestPort',
        'winlog.event_data.DestinationPort',
      ]);
      return ip ? `${ip}${port ? ':' + port : ''}` : '';
    }

    function processLabel(e) {
      const p = e?.process || {};
      const name = String(p?.name || '').trim();
      if (name) return name;
      const meta = e?.metadata && typeof e.metadata === 'object' ? e.metadata : {};

      // Linux/journald: use stable process identifiers when available.
      const jl = String(meta['linux.journald.syslog_identifier'] || meta['linux.journald.comm'] || '').trim();
      if (jl) return jl;

      // Linux/syslog files: try to extract program name from classic syslog headers.
      const om = String(e?.event?.original_message || '').trim();
      if (om) {
        let m = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([^\s\[]+)(?:\[(\d+)\])?:\s/.exec(om);
        if (!m) m = /^\d{4}-\d{2}-\d{2}[T ]\S+\s+\S+\s+([^\s\[]+)(?:\[(\d+)\])?:\s/.exec(om);
        if (m && m[1]) return String(m[1]).trim();
      }

      return String(
        meta['winlog.event_data.NewProcessName'] ||
        meta['winlog.event_data.ProcessName'] ||
        meta['winlog.event_data.Image'] ||
        meta['winlog.event_data.SourceImage'] ||
        meta['winlog.event_data.TargetImage'] ||
        meta['winlog.event_data.ApplicationName'] ||
        meta['winlog.event_data.ParentImage'] ||
        ''
      ).trim();
    }

    function objectLabel(e) {
      const meta = e?.metadata && typeof e.metadata === 'object' ? e.metadata : {};
      const normObj = String(meta?.['norm.object'] || '').trim();
      if (normObj) return normObj;
      const filePath = String(e?.file?.path || '').trim();
      if (filePath) return filePath;
      const regPath = String(e?.registry?.path || '').trim();
      if (regPath) return regPath;
      const cmd = String(e?.process?.command_line || '').trim();
      if (cmd) return cmd;
      const proc = String(e?.process?.name || '').trim();
      if (proc) return proc;
      const winObj = String(
        meta['winlog.event_data.ObjectName'] ||
        meta['winlog.event_data.TargetFilename'] ||
        meta['winlog.event_data.TargetObject'] ||
        meta['winlog.event_data.ImageLoaded'] ||
        meta['winlog.event_data.PipeName'] ||
        meta['winlog.event_data.QueryName'] ||
        meta['winlog.event_data.KeyName'] ||
        meta['winlog.event_data.RelativeTargetName'] ||
        ''
      ).trim();
      if (winObj) return winObj;
      return '';
    }

    function flowLabel(e) {
      const n = e?.network || {};
      const srcIp = String(n?.src_ip || '').trim();
      const dstIp = String(n?.dst_ip || '').trim();
      const srcPort = n?.src_port ? String(n.src_port) : '';
      const dstPort = n?.dst_port ? String(n.dst_port) : '';
      const src = srcIp ? `${srcIp}${srcPort ? ':' + srcPort : ''}` : '';
      const dst = dstIp ? `${dstIp}${dstPort ? ':' + dstPort : ''}` : '';
      if (src && dst) return `${src} → ${dst}`;
      return src || dst || '';
    }

    function honeypotAttackerLabel(e) {
      const n = e?.network || {};
      const srcIp = String(n?.src_ip || '').trim();
      const srcPort = n?.src_port ? String(n.src_port) : '';
      if (!srcIp) return '';
      return `${srcIp}${srcPort ? ':' + srcPort : ''}`;
    }

    function serviceNameForPort(p) {
      const port = Number(p);
      if (!Number.isFinite(port) || port <= 0) return '';
      const map = {
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        5900: 'VNC',
      };
      return map[port] || '';
    }

    function honeypotTargetLabel(e) {
      const n = e?.network || {};
      const proto = String(n?.protocol || '').trim().toLowerCase();
      const dstPort = n?.dst_port ? String(n.dst_port) : '';
      const svc = dstPort ? serviceNameForPort(dstPort) : '';
      const base = `${proto || ''}${dstPort ? '/' + dstPort : ''}`.replace(/^\//, '');
      if (!base && !svc) return '';
      return svc ? `${base} (${svc})` : base;
    }

    function honeypotActivityLabel(e) {
      const m = e?.metadata || {};
      const candidate =
        String(m?.activity || m?.method || m?.command || m?.request || '').trim() ||
        String(e?.event?.original_message || '').trim() ||
        String(e?.event?.summary || '').trim();
      return shortText(candidate.replace(/\s+/g, ' '), 140);
    }

    function idsSignatureLabel(e) {
      const m = e?.metadata || {};
      const sig = String(
        m?.signature ||
        m?.msg ||
        m?.rule ||
        m?.alert ||
        m?.message ||
        m?.['ids.signature'] ||
        m?.['suricata.signature'] ||
        ''
      ).trim();
      const sid = String(
        m?.sid ||
        m?.signature_id ||
        m?.rule_id ||
        m?.['ids.sid'] ||
        m?.['suricata.sid'] ||
        ''
      ).trim();
      if (sig && sid) return `${sig} (sid ${sid})`;
      return sig || sid || displaySummary(e);
    }

    function idsActionLabel(e) {
      const m = e?.metadata || {};
      const action = String(
        m?.action ||
        m?.verdict ||
        m?.decision ||
        m?.['ids.action'] ||
        m?.['suricata.action'] ||
        ''
      ).trim();
      return action || outcomeLabel(e) || '';
    }

    function idsProtoLabel(e) {
      return String(e?.network?.protocol || '').trim().toLowerCase();
    }

    const eventsColumnsRuntime = {
      activeDefs: [],
      defaultOrder: ['time', 'sev', 'user', 'agent', 'host', 'agent_ip', 'src', 'dst', 'process', 'object', 'summary'],
    };

    function eventPathRawValue(e, path) {
      const p = String(path || '').trim();
      if (!p) return '';
      const parts = p.split('.').filter(Boolean);
      if (!parts.length) return '';

      if (parts[0] === 'metadata') {
        const m = e?.metadata || {};
        if (parts.length === 2 && Object.prototype.hasOwnProperty.call(m, parts[1])) return m[parts[1]];
        const dotted = parts.slice(1).join('.');
        if (Object.prototype.hasOwnProperty.call(m, dotted)) return m[dotted];
      }

      let cur = e;
      for (const part of parts) {
        if (cur == null || typeof cur !== 'object') return '';
        cur = cur[part];
      }
      return cur;
    }

    function eventPathTextValue(e, path) {
      const raw = eventPathRawValue(e, path);
      if (raw == null) return '';
      if (typeof raw === 'string') return raw.trim();
      if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
      if (Array.isArray(raw)) return raw.map((v) => String(v ?? '')).filter(Boolean).join(', ');
      if (typeof raw === 'object') {
        try { return JSON.stringify(raw); } catch { return ''; }
      }
      return String(raw);
    }

    function createEventsSummaryCell(e) {
      const sum = document.createElement('td');
      sum.className = 'colSummary';
      const sumMain = document.createElement('div');
      sumMain.style.fontWeight = '900';
      sumMain.textContent = displaySummary(e);
      const sumMeta = document.createElement('div');
      sumMeta.className = 'muted';
      sumMeta.style.fontSize = '11px';
      sumMeta.style.marginTop = '2px';
      const bits = [];
      const ca = categoryActionLabel(e);
      if (ca) bits.push(ca);
      const out = outcomeLabel(e);
      if (out) bits.push(out);
      const eid = getEventIdValue(e);
      if (eid) bits.push(`eid ${eid}`);
      const prov = providerToDisplayName(e?.event?.provider);
      if (prov) bits.push(prov);
      sumMeta.textContent = bits.length ? bits.join(' · ') : '';
      sum.appendChild(sumMain);
      if (sumMeta.textContent) sum.appendChild(sumMeta);
      return sum;
    }

    function getEventsColumnDefinitionMap(customPaths) {
      const defs = [
        { id: 'time', label: t('tbl.time'), key: 'time', width: 120, min: 110, cell: (e) => formatTime(eventPrimaryTime(e)) },
        { id: 'sev', label: t('tbl.sev'), key: 'sev', width: 56, min: 56, pill: true, cell: (e) => severityLabel(e) },
        { id: 'user', label: t('tbl.user'), key: 'user', width: 110, min: 100, cell: (e) => { const v = getBestUser(e); return (v && v !== 'unknown') ? v : ''; } },
        { id: 'agent', label: t('tbl.agent'), key: 'agent', width: 96, min: 90, cell: (e) => agentNumberLabelForEvent(e) || '', title: (e) => String(e?.agent?.id || e?.agent_id || '').trim() },
        { id: 'host', label: t('tbl.host'), key: 'host', width: 140, min: 120, cell: (e) => hostDisplayName(e) || '' },
        { id: 'agent_ip', label: t('tbl.agentIp'), key: 'agent_ip', width: 120, min: 110, className: 'mono', cell: (e) => agentIpForEvent(e) || '' },
        { id: 'src', label: t('tbl.src'), key: 'src', width: 110, min: 100, className: 'mono', cell: (e) => srcLabel(e) || '' },
        { id: 'dst', label: t('tbl.dst'), key: 'dst', width: 110, min: 100, className: 'mono', cell: (e) => dstLabel(e) || '' },
        { id: 'process', label: t('tbl.process'), key: 'process', width: 140, min: 120, className: 'mono', cell: (e) => processLabel(e) || '' },
        { id: 'object', label: t('tbl.object'), key: 'object', width: 160, min: 120, className: 'mono', cell: (e) => objectLabel(e) || '' },
        { id: 'summary', label: t('tbl.summary'), key: 'summary', width: 320, min: 220, summary: true },
        { id: 'event_id', label: 'Event ID', key: 'eid', width: 92, min: 80, className: 'mono', cell: (e) => getEventIdValue(e) || '' },
        { id: 'provider', label: 'Provider', key: 'field:event.provider', width: 160, min: 120, cell: (e) => providerToDisplayName(e?.event?.provider) || '' },
        { id: 'category', label: 'Category', key: 'field:event.category', width: 130, min: 100, cell: (e) => e?.event?.category || '' },
        { id: 'action', label: 'Action', key: 'field:event.action', width: 130, min: 100, cell: (e) => e?.event?.action || '' },
        { id: 'outcome', label: 'Outcome', key: 'outcome', width: 110, min: 90, cell: (e) => outcomeLabel(e) || '' },
        { id: 'protocol', label: 'Proto', key: 'field:network.protocol', width: 88, min: 70, className: 'mono', cell: (e) => String(e?.network?.protocol || '').toLowerCase() },
        { id: 'src_port', label: 'Src Port', key: 'field:network.src_port', width: 90, min: 76, className: 'mono', cell: (e) => String(e?.network?.src_port || '') },
        { id: 'dst_port', label: 'Dst Port', key: 'field:network.dst_port', width: 90, min: 76, className: 'mono', cell: (e) => String(e?.network?.dst_port || '') },
        { id: 'hash', label: 'Hash', key: 'field:event.hash', width: 180, min: 120, className: 'mono', cell: (e) => String(e?.event?.hash || '') },
      ];

      for (const path of (Array.isArray(customPaths) ? customPaths : [])) {
        const p = String(path || '').trim();
        if (!p) continue;
        const id = `custom:${p}`;
        defs.push({ id, label: p, key: `field:${p}`, width: 150, min: 100, className: 'mono', cell: (e) => eventPathTextValue(e, p) });
      }

      const byId = new Map();
      for (const d of defs) byId.set(d.id, d);
      return byId;
    }

    function buildEventsMainRowTr(e, isActive) {
      const tr = document.createElement('tr');
      if (isActive) tr.classList.add('active');
      tr.dataset.key = eventKey(e);
      tr.dataset.type = 'event';

      const defs = Array.isArray(eventsColumnsRuntime.activeDefs) && eventsColumnsRuntime.activeDefs.length
        ? eventsColumnsRuntime.activeDefs
        : eventsColumnsRuntime.defaultOrder.map((id) => getEventsColumnDefinitionMap([]).get(id)).filter(Boolean);

      for (const def of defs) {
        if (def.summary) {
          tr.appendChild(createEventsSummaryCell(e));
          continue;
        }

        const td = document.createElement('td');
        if (def.className) td.className = def.className;
        if (def.pill) {
          const sev = def.cell(e);
          td.appendChild(buildSevPill(sev, sev));
          tr.appendChild(td);
          continue;
        }

        const raw = def.cell(e);
        const text = String(raw ?? '').trim();
        td.textContent = text || '—';
        const titleFn = typeof def.title === 'function' ? def.title : null;
        const ttl = titleFn ? String(titleFn(e) || '').trim() : text;
        if (ttl) td.title = ttl;
        tr.appendChild(td);
      }
      return tr;
    }

    function buildEventRowTr(e, isActive) {
      const tr = document.createElement('tr');
      if (isActive) tr.classList.add('active');
      if (e._burstCount > 1) tr.classList.add('burst-row');
      tr.dataset.key = eventKey(e);
      tr.dataset.type = 'event';

      const dash = (v) => {
        const s = String(v ?? '').trim();
        return s ? s : '—';
      };

      const t = document.createElement('td');
      t.textContent = formatTime(eventPrimaryTime(e));

      const s = document.createElement('td');
      const sev = severityLabel(e);
      s.appendChild(buildSevPill(sev, sev));

      const usr = document.createElement('td');
      const u = getBestUser(e);
      usr.textContent = (u && u !== 'unknown') ? u : '—';

      const ag = document.createElement('td');
      const agLabel = agentNumberLabelForEvent(e);
      ag.textContent = agLabel ? agLabel : '—';
      ag.title = String(e?.agent?.id || e?.agent_id || '').trim();

      const host = document.createElement('td');
      const hn = hostDisplayName(e);
      host.textContent = dash(hn);
      host.title = hn;

      const aip = document.createElement('td');
      aip.className = 'mono';
      const ip = agentIpForEvent(e);
      aip.textContent = dash(ip);
      aip.title = ip;

      const src = document.createElement('td');
      src.className = 'mono';
      const sl = srcLabel(e);
      src.textContent = dash(sl);
      src.title = sl;

      const dst = document.createElement('td');
      dst.className = 'mono';
      const dl = dstLabel(e);
      dst.textContent = dash(dl);
      dst.title = dl;

      const proc = document.createElement('td');
      proc.className = 'mono';
      const pl = processLabel(e);
      proc.textContent = dash(pl);
      proc.title = pl;

      const sum = document.createElement('td');
      sum.className = 'colSummary';
      const sumMain = document.createElement('div');
      sumMain.style.fontWeight = '900';
      sumMain.textContent = displaySummary(e);
      // Show burst count badge when this row represents a collapsed group.
      if (e._burstCount > 1) {
        const badge = document.createElement('span');
        badge.className = 'burst-badge';
        badge.title = `${e._burstCount} similar events collapsed — click to see first occurrence`;
        badge.textContent = `×${e._burstCount}`;
        sumMain.appendChild(badge);
      }
      const sumMeta = document.createElement('div');
      sumMeta.className = 'muted';
      sumMeta.style.fontSize = '11px';
      sumMeta.style.marginTop = '2px';
      const bits = [];
      const ca = categoryActionLabel(e);
      if (ca) bits.push(ca);
      const out = outcomeLabel(e);
      if (out) bits.push(out);
      const eid = getEventIdValue(e);
      if (eid) bits.push(`eid ${eid}`);
      const prov = providerToDisplayName(e?.event?.provider);
      if (prov) bits.push(prov);
      sumMeta.textContent = bits.length ? bits.join(' · ') : '';
      sum.appendChild(sumMain);
      if (sumMeta.textContent) sum.appendChild(sumMeta);

      const obj = document.createElement('td');
      obj.className = 'mono';
      obj.textContent = dash(objectLabel(e));

      tr.appendChild(t);
      tr.appendChild(s);
      tr.appendChild(usr);
      tr.appendChild(ag);
      tr.appendChild(host);
      tr.appendChild(aip);
      tr.appendChild(src);
      tr.appendChild(dst);
      tr.appendChild(proc);
      tr.appendChild(obj);
      tr.appendChild(sum);
      return tr;
    }

    function honeypotTrapLabel(e) {
      const m = e?.metadata || {};
      const trap = String(m?.['honeypot.trap'] || '').trim();
      if (trap) return trap.replace(/_/g, ' ');
      // Fallback: look at tags
      const tags = e?.tags || [];
      if (tags.includes('trap')) return 'trap';
      if (tags.includes('cowrie')) return 'cowrie';
      if (tags.includes('opencanary')) return 'opencanary';
      return '';
    }

    function buildHoneypotRowTr(e, isActive) {
      const tr = document.createElement('tr');
      if (isActive) tr.classList.add('active');
      tr.dataset.key = eventKey(e);
      tr.dataset.type = 'event';

      const t = document.createElement('td');
      t.textContent = formatTime(eventPrimaryTime(e));

      const s = document.createElement('td');
      const sev = severityLabel(e);
      s.appendChild(buildSevPill(sev, sev));

      const attacker = document.createElement('td');
      attacker.className = 'mono';
      attacker.textContent = honeypotAttackerLabel(e);

      const trapTd = document.createElement('td');
      const trapName = honeypotTrapLabel(e);
      if (trapName) {
        const badge = document.createElement('span');
        badge.className = 'chip sm';
        badge.textContent = trapName;
        badge.style.cssText = 'font-size:11px; padding:1px 6px;';
        trapTd.appendChild(badge);
      }

      const target = document.createElement('td');
      target.className = 'mono';
      target.textContent = honeypotTargetLabel(e);

      const activity = document.createElement('td');
      activity.textContent = honeypotActivityLabel(e);

      const outc = document.createElement('td');
      outc.textContent = outcomeLabel(e) || '';

      const blockTd = document.createElement('td');
      const srcIp = e?.network?.src_ip || '';
      if (srcIp) {
        const btn = document.createElement('button');
        btn.className = 'hp-block-btn';
        btn.textContent = 'Block';
        btn.title = `Block ${srcIp} for 1 hour`;
        btn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          honeypotBlockIp(srcIp);
        });
        blockTd.appendChild(btn);
      }

      tr.appendChild(t);
      tr.appendChild(s);
      tr.appendChild(attacker);
      tr.appendChild(trapTd);
      tr.appendChild(target);
      tr.appendChild(activity);
      tr.appendChild(outc);
      tr.appendChild(blockTd);
      return tr;
    }

    function buildIdsRowTr(e, isActive) {
      const tr = document.createElement('tr');
      if (isActive) tr.classList.add('active');
      tr.dataset.key = eventKey(e);
      tr.dataset.type = 'event';

      const t = document.createElement('td');
      t.textContent = formatTime(eventPrimaryTime(e));

      const s = document.createElement('td');
      const sev = severityLabel(e);
      s.appendChild(buildSevPill(sev, sev));

      const sig = document.createElement('td');
      sig.textContent = idsSignatureLabel(e);
      sig.title = idsSignatureLabel(e);

      const act = document.createElement('td');
      const actionRaw = idsActionLabel(e).toLowerCase();
      const actionBadge = document.createElement('span');
      actionBadge.className = 'ids-action-badge ' + (/drop/.test(actionRaw) ? 'drop' : /reject/.test(actionRaw) ? 'reject' : /pass/.test(actionRaw) ? 'pass' : 'alert');
      actionBadge.textContent = idsActionLabel(e);
      act.appendChild(actionBadge);

      const fl = document.createElement('td');
      fl.className = 'mono';
      const flow = flowLabel(e);
      fl.textContent = flow;
      fl.title = flow;

      const pr = document.createElement('td');
      const protoBadge = document.createElement('span');
      protoBadge.className = 'ids-proto-badge';
      protoBadge.textContent = idsProtoLabel(e);
      pr.appendChild(protoBadge);

      const ag = document.createElement('td');
      const agentId = e?.agent?.id || e?.agent_id || e?.agent?.hostname || '';
      ag.textContent = agentId ? agentLabel(agentId) : '';
      ag.title = agentId;

      tr.appendChild(t);
      tr.appendChild(s);
      tr.appendChild(sig);
      tr.appendChild(act);
      tr.appendChild(fl);
      tr.appendChild(pr);
      tr.appendChild(ag);
      return tr;
    }

    function buildAlertRowTr(a, isActive) {
      const tr = document.createElement('tr');
      if (isActive) tr.classList.add('active');
      const key = alertKey(a);
      tr.dataset.key = key;
      tr.dataset.type = 'alert';

      const t = document.createElement('td');
      const check = document.createElement('input');
      check.type = 'checkbox';
      check.className = 'alert-row-check';
      check.dataset.key = key;
      check.checked = state.selectedAlertKeys instanceof Set && state.selectedAlertKeys.has(key);
      check.setAttribute('aria-label', 'Select alert');
      t.appendChild(check);
      t.appendChild(document.createTextNode(' '));
      const timeTxt = document.createElement('span');
      timeTxt.textContent = formatTime(a?.last_seen || a?.first_seen);
      t.appendChild(timeTxt);
      const s = document.createElement('td');
      const sev = alertSeverityLabel(a);
      s.appendChild(buildSevPill(sev, sev));
      const risk = Number(alertRiskScore(a) || 0);
      const riskBadge = document.createElement('span');
      riskBadge.className = 'badge';
      riskBadge.style.cssText = 'margin-left:6px;font-size:10px;padding:1px 4px;opacity:0.85;';
      riskBadge.textContent = `R${Math.max(0, Math.min(100, Math.round(risk)))}`;
      s.appendChild(riskBadge);
      const msg = document.createElement('td');
      msg.textContent = `${a?.rule_name || a?.rule_id || 'Alert'} — ${a?.message || ''}`;
      // Append small MITRE technique badges
      {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const techs = String(md.mitre_attack || '').split(',').map(x => x.trim()).filter(Boolean);
        for (const tech of techs.slice(0, 3)) {
          const b = document.createElement('span');
          b.className = 'badge';
          b.style.cssText = 'margin-left:4px;font-size:10px;padding:1px 4px;opacity:0.8;';
          b.textContent = tech;
          msg.appendChild(b);
        }
      }
      const ag = document.createElement('td');
      ag.textContent = agentIdentityLabelForAlert(a) || a?.agent_hostname || a?.agent_id || '';
      const st = document.createElement('td');
      st.textContent = a?.status || 'new';

      tr.appendChild(t);
      tr.appendChild(s);
      tr.appendChild(msg);
      tr.appendChild(ag);
      tr.appendChild(st);
      return tr;
    }

    function parseSearchTerms(raw) {
      const q = String(raw || '').trim();
      if (!q) return [];
      return q
        .split(/\s+/g)
        .map((tok) => {
          const t = String(tok || '').trim();
          if (!t) return null;
          const idx = t.indexOf(':');
          if (idx > 0) {
            const field = t.slice(0, idx).trim().toLowerCase();
            const value = t.slice(idx + 1).trim().toLowerCase();
            if (field && value) return { field, value };
          }
          return { field: null, value: t.toLowerCase() };
        })
        .filter(Boolean);
    }


    function eventMatchesTerms(e, terms) {
      if (!terms || !terms.length) return true;
      const hay = eventFilterText(e);
      const hasAny = (v) => hay.includes(String(v || '').toLowerCase());

      const matchField = (field, val) => {
        if (!field) return hasAny(val);
        if (field === 'ip' || field === 'src_ip' || field === 'dst_ip') {
          const src = String(e?.network?.src_ip || '').toLowerCase();
          const dst = String(e?.network?.dst_ip || '').toLowerCase();
          const a = String(e?.agent?.ip || '').toLowerCase();
          const hostIpVal = e?.host?.ip;
          const hostIps = Array.isArray(hostIpVal)
            ? hostIpVal.map((x) => String(x).toLowerCase())
            : (hostIpVal ? [String(hostIpVal).toLowerCase()] : []);
          return src.includes(val) || dst.includes(val) || a.includes(val) || hostIps.some((x) => x.includes(val));
        }
        if (field === 'user') {
          const u = e?.user || {};
          return (
            String(u?.name || '').toLowerCase().includes(val) ||
            String(u?.domain || '').toLowerCase().includes(val) ||
            String(u?.id || '').toLowerCase().includes(val) ||
            (Array.isArray(u?.privileges) && u.privileges.some((p) => String(p).toLowerCase().includes(val)))
          );
        }
        if (field === 'agent') {
          const a = e?.agent || {};
          return (
            String(a?.id || '').toLowerCase().includes(val) ||
            String(a?.hostname || '').toLowerCase().includes(val) ||
            String(a?.ip || '').toLowerCase().includes(val) ||
            String(a?.mac || '').toLowerCase().includes(val)
          );
        }
        if (field === 'hash' || field === 'sha256') {
          const sha = getBestSha256(e);
          if (sha && sha.includes(val)) return true;
          const h = String(e?.hash || e?.event?.hash || e?.correlation_id || '').toLowerCase();
          return h.includes(val) || hasAny(val);
        }
        if (field === 'proc' || field === 'process') {
          const p = e?.process || {};
          return (
            String(p?.name || '').toLowerCase().includes(val) ||
            String(p?.command_line || '').toLowerCase().includes(val)
          );
        }
        if (field === 'file') {
          const f = e?.file || {};
          return (
            String(f?.path || '').toLowerCase().includes(val) ||
            String(f?.name || '').toLowerCase().includes(val) ||
            String(f?.permissions || '').toLowerCase().includes(val)
          );
        }
        if (field === 'reg' || field === 'registry') {
          const r = e?.registry || {};
          return String(r?.path || '').toLowerCase().includes(val) || String(r?.value || '').toLowerCase().includes(val);
        }
        if (field === 'tag') {
          return Array.isArray(e?.tags) && e.tags.some((t) => String(t).toLowerCase().includes(val));
        }
        if (field === 'provider') {
          return String(e?.event?.provider || '').toLowerCase().includes(val);
        }
        if (field === 'eid' || field === 'eventid' || field === 'event_id') {
          return getEventIdValue(e).toLowerCase().includes(val) || String(e?.event?.record_id || '').toLowerCase().includes(val);
        }
        if (field === 'cve') {
          return hasAny(val);
        }
        // Unknown field: treat as generic keyword.
        return hasAny(val);
      };

      return terms.every((t) => matchField(t.field, t.value));
    }

    function filtered(list, type) {
      const terms = parseSearchTerms(state.searchText);
      if (!terms.length) return list;
      if (type === 'alert') {
        return list.filter((a) => {
          const txt = `${a?.rule_name || ''} ${a?.rule_id || ''} ${a?.message || ''} ${a?.agent_hostname || ''} ${a?.agent_id || ''}`.toLowerCase();
          return terms.every((t) => txt.includes(t.value));
        });
      }
      return list.filter((e) => eventMatchesTerms(e, terms));
    }

    function ensureVirtualScrollBindings() {
      if (state.virtualScrollBound) return;
      state.virtualScrollBound = true;

      for (const [tbodyId, cfg] of Object.entries(VIRTUAL_TABLES)) {
        const body = document.getElementById(tbodyId);
        const wrap = body?.closest ? body.closest('.tableWrap') : null;
        if (!body || !wrap) continue;

        let rafPending = false;
        wrap.addEventListener('scroll', () => {
          if (rafPending) return;
          rafPending = true;
          requestAnimationFrame(() => {
            rafPending = false;
            if (state.view !== cfg.view) return;
            state.dirty.tables = true;
            scheduleRender();
          });
        }, { passive: true });
      }
    }

    function virtualWindowForBody(body, totalLen) {
      const cfg = VIRTUAL_TABLES[String(body?.id || '')];
      if (!cfg) return { start: 0, end: totalLen, topPad: 0, bottomPad: 0, virtual: false };

      const wrap = body?.closest ? body.closest('.tableWrap') : null;
      if (!wrap) return { start: 0, end: totalLen, topPad: 0, bottomPad: 0, virtual: false };

      const rowH = Math.max(24, Number(cfg.rowHeight || 34));
      const overscan = Math.max(4, Number(cfg.overscan || 10));
      const viewportH = Math.max(1, Number(wrap.clientHeight || 1));
      const scrollTop = Math.max(0, Number(wrap.scrollTop || 0));

      const visibleRows = Math.ceil(viewportH / rowH);
      const start = Math.max(0, Math.floor(scrollTop / rowH) - overscan);
      const end = Math.min(totalLen, start + visibleRows + (overscan * 2));
      const topPad = start * rowH;
      const bottomPad = Math.max(0, (totalLen - end) * rowH);

      return { start, end, topPad, bottomPad, virtual: true };
    }

    function makeSpacerTr(heightPx, colSpan) {
      const tr = document.createElement('tr');
      tr.dataset.spacer = '1';
      tr.style.pointerEvents = 'none';
      const td = document.createElement('td');
      td.colSpan = Math.max(1, Number(colSpan || 1));
      td.style.height = `${Math.max(0, Math.floor(heightPx))}px`;
      td.style.padding = '0';
      td.style.border = '0';
      tr.appendChild(td);
      return tr;
    }

    function alertRowSig(a) {
      return [
        alertKey(a),
        String(a?.last_seen || a?.first_seen || ''),
        String(a?.status || ''),
        String(a?.rule_name || a?.rule_id || ''),
        String(a?.message || ''),
        String(a?.agent_id || a?.agent_hostname || ''),
      ].join('|');
    }

    function renderRowsSmart(body, list, max, buildRow, rowKeyFn, rowSigFn, activeKey) {
      if (!body) return;

      const all = list.slice(0, max);
      const emptyMessageForTable = (id) => {
        if (id === 'tblAlerts') return 'No alerts in this scope';
        if (id === 'tblEvents' || id === 'tblOverviewEvents') return 'No events in this scope';
        if (id === 'tblHoneypot') return 'No honeypot events in this scope';
        if (id === 'tblIds') return 'No IDS detections in this scope';
        return 'No rows to display';
      };

      if (!all.length) {
        const colSpan = body.closest('table')?.querySelectorAll('thead th')?.length || 1;
        const tr = document.createElement('tr');
        tr.className = 'table-empty-row';
        const td = document.createElement('td');
        td.colSpan = Math.max(1, Number(colSpan || 1));
        td.className = 'muted text-12';
        td.textContent = emptyMessageForTable(String(body.id || ''));
        tr.appendChild(td);
        if (typeof body.replaceChildren === 'function') body.replaceChildren(tr);
        else {
          clearEl(body);
          body.appendChild(tr);
        }
        return;
      }

      const win = virtualWindowForBody(body, all.length);
      const start = win.start;
      const end = win.end;

      const tableId = String(body.id || 'table');
      let cache = state.tableDomCache.get(tableId);
      if (!cache) {
        cache = new Map();
        state.tableDomCache.set(tableId, cache);
      }

      const frag = document.createDocumentFragment();
      const colSpan = body.closest('table')?.querySelectorAll('thead th')?.length || 1;

      if (win.virtual && win.topPad > 0) frag.appendChild(makeSpacerTr(win.topPad, colSpan));

      const keepKeys = new Set();
      for (let i = start; i < end; i++) {
        const item = all[i];
        const key = String(rowKeyFn(item));
        keepKeys.add(key);

        const sig = String(rowSigFn ? rowSigFn(item) : key);
        let rec = cache.get(key);
        let tr = rec?.tr;

        if (!tr || rec?.sig !== sig) {
          tr = buildRow(item, key === activeKey);
          rec = { sig, tr };
          cache.set(key, rec);
        } else {
          tr.classList.toggle('active', key === activeKey);
        }

        frag.appendChild(tr);
      }

      if (win.virtual && win.bottomPad > 0) frag.appendChild(makeSpacerTr(win.bottomPad, colSpan));

      if (typeof body.replaceChildren === 'function') body.replaceChildren(frag);
      else {
        clearEl(body);
        body.appendChild(frag);
      }

      // prune stale cache entries for this table
      if (cache.size > Math.max(keepKeys.size * 2, 300)) {
        for (const k of cache.keys()) {
          if (!keepKeys.has(k)) cache.delete(k);
        }
      }
    }

