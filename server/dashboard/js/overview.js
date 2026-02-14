// Map initialization state machine to prevent race conditions
const MapInitState = {
  UNINITIALIZED: 'uninitialized',
  LOADING: 'loading',
  READY: 'ready',
  ERROR: 'error',
};

// Global map instances with state tracking
let ovMapState = MapInitState.UNINITIALIZED;
let ovMap = null, ovHeatLayer = null, ovTrendChart = null, ovDonutChart = null, ovLanRaf = null, ovLanAgentPositions = [];
let eliteMapState = MapInitState.UNINITIALIZED;
let eliteMap = null, eliteHeatLayer = null, elitePanTimer = null;
let eliteStaticPulseMarkers = [], eliteLivePulseMarkers = [], eliteLiveArcs = [];
let eliteGlobeState = MapInitState.UNINITIALIZED;
let eliteGlobe = null, eliteGlobeEl = null, eliteGlobeLoadPromise = null, eliteGlobeResizeBound = false;
let eliteLastGlobeSig = '';
let eliteLastMapUpdateMs = 0, eliteLastUserInteractMs = 0;
let eliteLastCriticalCount = 0;
let eliteCriticalFxTimer = null;
let eliteCommandViewListenerBound = false;
let overviewAggCache = { key: '', value: null };

// Utility: Check if map is ready before use
function isMapReady(mapRef, state) {
  if (state !== MapInitState.READY) {
    console.warn('[Overview] Map accessed in state:', state, '- skipping operation');
    return false;
  }
  if (!mapRef) {
    console.warn('[Overview] Map is null despite READY state - initialization may have failed');
    return false;
  }
  return true;
}

function loadExternalScript(src, testGlobal) {
  if (testGlobal && window[testGlobal]) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-ext-src="${src}"]`);
    if (existing) {
      existing.addEventListener('load', () => resolve(), { once: true });
      existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
      return;
    }
    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.dataset.extSrc = src;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`Failed to load ${src}`));
    document.head.appendChild(script);
  });
}

async function ensureEliteGlobeRuntime() {
  if (eliteGlobe) return eliteGlobe;
  const host = document.getElementById('ovEliteGlobe');
  if (!host) return null;

  if (!eliteGlobeLoadPromise) {
    eliteGlobeLoadPromise = (async () => {
      // globe.gl bundles its own Three.js — no need to load it separately
      await loadExternalScript('https://unpkg.com/globe.gl@2.45.2/dist/globe.gl.min.js', 'Globe');

      const width = Math.max(320, host.clientWidth || 320);
      const height = Math.max(220, host.clientHeight || 220);
      eliteGlobeEl = host;
      eliteGlobe = window.Globe()(host)
        .backgroundColor('rgba(0,0,0,0)')
        .showAtmosphere(true)
        .atmosphereColor('#00e5ff')
        .atmosphereAltitude(0.17)
        .pointAltitude((d) => Number(d?.alt || 0.03))
        .pointRadius((d) => Number(d?.radius || 0.26))
        .pointColor((d) => d?.color || 'rgba(255,171,0,0.92)')
        .arcColor((d) => d?.color || 'rgba(0,229,255,0.75)')
        .arcAltitude((d) => Number(d?.alt || 0.26))
        .arcStroke((d) => Number(d?.stroke || 0.38))
        .arcDashLength((d) => Number(d?.dash || 0.45))
        .arcDashGap((d) => Number(d?.gap || 0.2))
        .arcDashInitialGap((d) => Number(d?.dashInitial || 0))
        .arcDashAnimateTime((d) => Number(d?.animate || 1600))
        .ringColor((d) => d?.color || 'rgba(0,229,255,0.35)')
        .ringMaxRadius((d) => Number(d?.maxR || 3.7))
        .ringPropagationSpeed((d) => Number(d?.speed || 1.0))
        .ringRepeatPeriod((d) => Number(d?.period || 900))
        .width(width)
        .height(height);

      const controls = eliteGlobe.controls?.();
      if (controls) {
        controls.autoRotate = false;
        controls.autoRotateSpeed = 0;
        controls.enablePan = true;
        controls.enableDamping = true;
        controls.minDistance = 170;
        controls.maxDistance = 310;
      }

      const pointLight = new window.THREE.PointLight(0x00e5ff, 0.55);
      pointLight.position.set(200, 120, 120);
      eliteGlobe.scene?.().add(pointLight);

      const ambient = new window.THREE.AmbientLight(0xffffff, 0.36);
      eliteGlobe.scene?.().add(ambient);

      if (!eliteGlobeResizeBound) {
        eliteGlobeResizeBound = true;
        window.addEventListener('resize', () => {
          if (!eliteGlobe || !eliteGlobeEl) return;
          const w = Math.max(320, eliteGlobeEl.clientWidth || 320);
          const h = Math.max(220, eliteGlobeEl.clientHeight || 220);
          eliteGlobe.width(w).height(h);
        });
      }

      return eliteGlobe;
    })().catch((err) => {
      eliteGlobeLoadPromise = null;
      // Silent failure acceptable - fallback to 2D map will be used
      return null;
    });
  }

  return eliteGlobeLoadPromise;
}

function buildEliteGlobeArcs(originPoints, impactPoints) {
  if (!Array.isArray(originPoints) || !Array.isArray(impactPoints) || !originPoints.length || !impactPoints.length) return [];
  const arcs = [];
  const palette = [
    'rgba(0,229,255,0.78)',
    'rgba(255,171,0,0.72)',
    'rgba(255,23,68,0.74)',
  ];
  const maxArcs = Math.min(40, originPoints.length * impactPoints.length);
  for (let i = 0; i < maxArcs; i += 1) {
    const src = originPoints[i % originPoints.length];
    const dst = impactPoints[(i * 2 + 1) % impactPoints.length];
    if (!src || !dst) continue;
    const weight = Math.max(1, Number(src.weight || 1));
    arcs.push({
      startLat: src.lat,
      startLng: src.lon,
      endLat: dst.lat,
      endLng: dst.lon,
      color: palette[i % palette.length],
      alt: Math.min(0.48, 0.16 + (weight / 80)),
      stroke: Math.min(0.8, 0.26 + (weight / 120)),
      dash: 0.42,
      gap: 0.22,
      dashInitial: (i * 0.07) % 1,
      animate: 1200 + ((i % 5) * 180),
    });
  }
  return arcs;
}

async function updateEliteGlobeVisuals(originPoints, impactPoints, pulsePoints) {
  const globe = await ensureEliteGlobeRuntime();
  if (!globe) return;

  const points = [];
  for (const p of (originPoints || []).slice(0, 36)) {
    points.push({
      lat: p.lat,
      lng: p.lon,
      alt: Math.min(0.11, 0.02 + (Number(p.weight || 1) / 180)),
      radius: Math.min(0.58, 0.18 + (Number(p.weight || 1) / 120)),
      color: 'rgba(255,171,0,0.95)',
    });
  }
  for (const p of (impactPoints || []).slice(0, 36)) {
    points.push({
      lat: p.lat,
      lng: p.lon,
      alt: Math.min(0.1, 0.02 + (Number(p.weight || 1) / 190)),
      radius: Math.min(0.54, 0.16 + (Number(p.weight || 1) / 130)),
      color: 'rgba(0,229,255,0.92)',
    });
  }

  const rings = (pulsePoints || []).slice(0, 18).map((p, idx) => ({
    lat: p.lat,
    lng: p.lon,
    maxR: 2.4 + Math.min(4.8, Number(p.weight || 1) * 0.15),
    speed: 0.72 + ((idx % 4) * 0.16),
    period: 860 + ((idx % 6) * 110),
    color: idx % 2 === 0 ? 'rgba(0,229,255,0.35)' : 'rgba(255,171,0,0.33)',
  }));
  const arcs = buildEliteGlobeArcs(originPoints, impactPoints);

  const signature = JSON.stringify([
    points.slice(0, 10).map((p) => [Math.round(p.lat * 100) / 100, Math.round(p.lng * 100) / 100, Math.round((p.alt || 0) * 100) / 100]),
    arcs.slice(0, 8).map((a) => [Math.round(a.startLat * 10) / 10, Math.round(a.startLng * 10) / 10, Math.round(a.endLat * 10) / 10, Math.round(a.endLng * 10) / 10]),
    rings.length,
  ]);
  if (signature === eliteLastGlobeSig) return;
  eliteLastGlobeSig = signature;

  globe
    .pointsData(points)
    .arcsData(arcs)
    .ringsData(rings);
}

function setEliteMetricText(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  const next = String(value ?? '');
  if (el.textContent === next) return;
  el.textContent = next;
  el.classList.remove('metric-roll');
  void el.offsetWidth;
  el.classList.add('metric-roll');
  setTimeout(() => el.classList.remove('metric-roll'), 360);
}

/**
 * Ensure baseline map visuals (heat layer + initial static markers) are present.
 * Safe to call repeatedly – idempotent.
 */
function ensureEliteBaselineMapVisuals() {
  if (!eliteMap) return;
  // Ensure empty heat layer exists so later updates just call setLatLngs
  if (!eliteHeatLayer) {
    try {
      eliteHeatLayer = L.heatLayer([], {
        radius: 20,
        blur: 15,
        gradient: { 0.4: '#00e5ff', 0.7: '#ffab00', 1.0: '#ff1744' },
      }).addTo(eliteMap);
    } catch (_) { /* Leaflet.heat not loaded yet – harmless */ }
  }
  // Clear stale static pulse markers on theme change / re-init
  clearElitePulseMarkers(eliteStaticPulseMarkers);
}

function triggerEliteCriticalCinematic() {
  const pane = document.getElementById('paneOverview');
  if (!pane || !pane.classList.contains('ov-elite')) return;
  pane.classList.remove('critical-vignette-active');
  void pane.offsetWidth;
  pane.classList.add('critical-vignette-active');
  const criticalPill = document.getElementById('elite-critical-val')?.closest('.hero-pill');
  if (criticalPill) {
    criticalPill.classList.remove('critical-hit');
    void criticalPill.offsetWidth;
    criticalPill.classList.add('critical-hit');
    setTimeout(() => criticalPill.classList.remove('critical-hit'), 1800);
  }
  clearTimeout(eliteCriticalFxTimer);
  eliteCriticalFxTimer = setTimeout(() => pane.classList.remove('critical-vignette-active'), 1250);
}

function clearElitePulseMarkers(list) {
  if (!eliteMap || !Array.isArray(list)) return;
  for (const marker of list) {
    try { eliteMap.removeLayer(marker); } catch (_) { }
  }
  list.length = 0;
}

function clearEliteLiveArcs() {
  if (!eliteMap) return;
  for (const arc of eliteLiveArcs) {
    try { eliteMap.removeLayer(arc); } catch (_) { }
  }
  eliteLiveArcs.length = 0;
}

/**
 * Draw a curved leaflet polyline arc from [lat1,lon1] to [lat2,lon2].
 * Uses an intermediate "hump" point so it looks like a great-circle arc.
 */
function addLeafletArc(map, lat1, lon1, lat2, lon2, color) {
  const steps = 24;
  const pts = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lat = lat1 + (lat2 - lat1) * t;
    const lon = lon1 + (lon2 - lon1) * t;
    // Raise the midpoint to create a visible arc
    const hump = Math.sin(t * Math.PI) * Math.max(4, Math.abs(lat2 - lat1) * 0.5, Math.abs(lon2 - lon1) * 0.18);
    pts.push([lat + hump, lon]);
  }
  const line = L.polyline(pts, {
    color,
    weight: 1.8,
    opacity: 0.65,
    dashArray: '5, 4',
    lineJoin: 'round',
  }).addTo(map);
  eliteLiveArcs.push(line);
  return line;
}

/**
 * Update live blinker markers for attacker origins and impacted hosts.
 * @param {Array<{lat,lon,weight,ip}>} originPts  - attacker/origin points with IPs
 * @param {Array<{lat,lon,weight,ip}>} impactedPts - victim/host points with IPs
 */
function updateEliteLiveBlinkers(originPts, impactedPts) {
  if (!eliteMap) return;
  clearElitePulseMarkers(eliteLivePulseMarkers);
  clearEliteLiveArcs();

  // Top attacker origins (orange pulse)
  const topOrigins = [...(originPts || [])]
    .sort((a, b) => (Number(b.weight) || 0) - (Number(a.weight) || 0))
    .slice(0, 6);

  // Top impacted hosts (red pulse)
  const topImpacted = [...(impactedPts || [])]
    .sort((a, b) => (Number(b.weight) || 0) - (Number(a.weight) || 0))
    .slice(0, 5);

  for (const pt of topOrigins) {
    const ip = String(pt.ip || '');
    const label = ip ? `<span class="pm-ip">${escapeHtml(ip)}</span>` : '';
    const marker = L.marker([pt.lat, pt.lon], {
      icon: L.divIcon({
        className: '',
        html: `<div class="pulse-marker pulse-attacker">${label}</div>`,
        iconSize: [16, 16],
        iconAnchor: [8, 8],
      }),
      zIndexOffset: 500,
    }).addTo(eliteMap);
    eliteLivePulseMarkers.push(marker);
  }

  for (const pt of topImpacted) {
    const ip = String(pt.ip || '');
    const label = ip ? `<span class="pm-ip pm-ip-victim">${escapeHtml(ip)}</span>` : '';
    const marker = L.marker([pt.lat, pt.lon], {
      icon: L.divIcon({
        className: '',
        html: `<div class="pulse-marker pulse-victim">${label}</div>`,
        iconSize: [16, 16],
        iconAnchor: [8, 8],
      }),
      zIndexOffset: 400,
    }).addTo(eliteMap);
    eliteLivePulseMarkers.push(marker);
  }

  // Draw arcs from each top attacker to each top victim (cap at 5 arcs total)
  let arcCount = 0;
  const arcColor = 'rgba(255,80,80,0.55)';
  outer: for (const origin of topOrigins) {
    for (const victim of topImpacted) {
      if (arcCount >= 5) break outer;
      // Skip arc if attacker and victim are in the same area (< 1 degree apart)
      const dist = Math.abs(origin.lat - victim.lat) + Math.abs(origin.lon - victim.lon);
      if (dist < 1) continue;
      addLeafletArc(eliteMap, origin.lat, origin.lon, victim.lat, victim.lon, arcColor);
      arcCount++;
    }
  }
}

function getOverviewAggregationSnapshot(events, alerts, nowSec, buckets) {
  const safeEvents = Array.isArray(events) ? events : [];
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const evTail = safeEvents.length ? eventIngestTimeSeconds(safeEvents[safeEvents.length - 1]) : 0;
  const alTailRaw = safeAlerts.length ? safeAlerts[safeAlerts.length - 1]?.last_seen : null;
  const alTail = alTailRaw ? Math.floor(new Date(alTailRaw).getTime() / 1000) : 0;
  const timeSlice = Math.floor(Date.now() / 5000);
  const cacheKey = `${safeEvents.length}|${safeAlerts.length}|${evTail}|${alTail}|${buckets}|${timeSlice}`;
  if (overviewAggCache.key === cacheKey && overviewAggCache.value) return overviewAggCache.value;

  const start = nowSec - buckets * 60;
  const evSeries = new Array(buckets).fill(0);
  const alSeries = new Array(buckets).fill(0);
  const hiSeries = new Array(buckets).fill(0);
  const hpSeries = new Array(buckets).fill(0);
  const idsSeries = new Array(buckets).fill(0);
  const fimSeries = new Array(buckets).fill(0);

  const classCounts = new Map();
  const srcIpCounts = new Map();
  const agentCounts = new Map();
  const originIps = new Map();
  const impactedIps = new Map();
  const eventIdCounts = new Map();

  const bump = (map, key, n = 1) => {
    if (!key) return;
    const k = String(key);
    map.set(k, (map.get(k) || 0) + n);
  };

  const classifyEvent = (e) => {
    if (isIdsEvent(e)) return 'IDS';
    if (isHoneypotEvent(e)) return 'Honeypot';
    if (isFimEvent(e)) return 'FIM';

    const prov = String(e?.event?.provider || '').toLowerCase();
    const eid = getEventIdValue(e);
    const hasNet = Boolean(e?.network?.src_ip || e?.network?.dst_ip);
    const hasProc = Boolean(e?.process?.name || e?.process?.pid);
    const hasUser = Boolean(e?.user?.name);

    if (prov.includes('security-auditing') || hasUser) return 'Auth';
    if (prov.includes('powershell') || prov.includes('sysmon') || hasProc) return 'Process';
    if (hasNet) return 'Network';
    if (eid) return 'System';
    return 'Other';
  };

  // isPrivateIp inline helper for origin classification
  const _isPrivate = (s) => {
    const v = String(s || '').trim();
    if (!v) return true; // treat empty as private/unknown
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    if (!m) return v === '::1' || /^fe80:/i.test(v) || /^fc|^fd/i.test(v);
    const a = Number(m[1]), b = Number(m[2]);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 169 && b === 254);
  };

  for (const e of safeEvents) {
    const t = eventIngestTimeSeconds(e);
    const inWindow = (typeof t === 'number' && t >= start && t <= nowSec);
    if (!inWindow) continue;

    const idx = Math.min(buckets - 1, Math.max(0, Math.floor((t - start) / 60)));
    evSeries[idx] += 1;
    const sev = severityLabel(e);
    if (sev === 'high' || sev === 'critical') hiSeries[idx] += 1;
    if (isHoneypotEvent(e)) hpSeries[idx] += 1;
    if (isIdsEvent(e)) idsSeries[idx] += 1;
    if (isFimEvent(e)) fimSeries[idx] += 1;

    const cls = classifyEvent(e);
    bump(classCounts, cls, 1);

    // Collect all IP fields for source counts — network, metadata extras
    const md = (e && typeof e.metadata === 'object' && e.metadata) ? e.metadata : {};
    const srcCandidates = [
      e?.network?.src_ip, e?.network?.source_ip, md.src_ip, md.source_ip,
    ].filter(Boolean);
    for (const ip of srcCandidates) bump(srcIpCounts, ip, 1);

    const eid = getEventIdValue(e);
    if (eid) bump(eventIdCounts, eid, 1);

    // Origin IPs: prefer external (non-private) src_ip for attack origin map
    const originCandidates = [
      e?.network?.src_ip, md.src_ip, md.attacker_ip, md.source_ip,
    ].filter(ip => ip && !_isPrivate(ip));
    for (const ip of originCandidates) { bump(originIps, ip, 1); break; } // first match only
    // Fall back to any external src if no external found
    if (!originCandidates.length) {
      const anySrc = e?.network?.src_ip || md.src_ip || '';
      if (anySrc) bump(originIps, anySrc, 1);
    }

    // Impacted hosts: collect ALL host IPs, plus agent IP, to get true scope
    const hostIpVal = e?.host?.ip;
    const hostIps = Array.isArray(hostIpVal) ? hostIpVal : (hostIpVal ? [hostIpVal] : []);
    let hasImpact = false;
    for (const ip of hostIps) { if (ip) { bump(impactedIps, ip, 1); hasImpact = true; } }
    if (!hasImpact) {
      const fallback = e?.agent?.ip || e?.agent?.hostname || e?.host?.name || '';
      if (fallback) bump(impactedIps, fallback, 1);
    }
    // Also track the agent that sent the event (for scope)
    const agId = String(e?.agent?.id || '').trim();
    if (agId) bump(agentCounts, agId, 1);
  }

  for (const a of safeAlerts) {
    // Use first_seen if available for more accurate bucketing; last_seen can be far future
    const tRaw = a?.first_seen || a?.last_seen;
    const sec = (() => {
      if (typeof tRaw === 'number') return tRaw;
      if (typeof tRaw === 'string') {
        const ms = Date.parse(tRaw);
        return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
      }
      return null;
    })();
    if (typeof sec === 'number' && Number.isFinite(sec) && sec >= start && sec <= nowSec) {
      const idx = Math.min(buckets - 1, Math.max(0, Math.floor((sec - start) / 60)));
      alSeries[idx] += 1;

      const aid = a?.agent_id || a?.agent?.id || '';
      const w = Number(a?.count || 1);
      if (aid) bump(agentCounts, aid, (Number.isFinite(w) && w > 0) ? w : 1);
    }
  }

  const snapshot = {
    start,
    evSeries,
    alSeries,
    hiSeries,
    hpSeries,
    idsSeries,
    fimSeries,
    classCounts,
    srcIpCounts,
    agentCounts,
    originIps,
    impactedIps,
    eventIdCounts,
  };
  overviewAggCache = { key: cacheKey, value: snapshot };
  return snapshot;
}

function objectCountsToMap(obj) {
  const out = new Map();
  if (!obj || typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj)) out.set(String(k), Number(v || 0));
  return out;
}

function getServerOverviewAggregationSnapshot(nowSec, buckets) {
  const s = state.dashboardSummary;
  if (!s || typeof s !== 'object') return null;
  const windowMinutes = Number(s.window_minutes || 0);
  if (windowMinutes !== buckets) return null;

  const generatedAt = Number(s.generated_at_unix || 0);
  if (!generatedAt || (nowSec - generatedAt) > 60) return null;

  const toSeries = (value) => {
    if (!Array.isArray(value)) return new Array(buckets).fill(0);
    const out = value.slice(0, buckets).map((n) => Number(n || 0));
    while (out.length < buckets) out.push(0);
    return out;
  };

  return {
    start: Number(s.start_unix || (nowSec - buckets * 60)),
    evSeries: toSeries(s.ev_series),
    alSeries: toSeries(s.al_series),
    hiSeries: toSeries(s.hi_series),
    hpSeries: toSeries(s.hp_series),
    idsSeries: toSeries(s.ids_series),
    fimSeries: toSeries(s.fim_series),
    classCounts: objectCountsToMap(s.class_counts),
    srcIpCounts: objectCountsToMap(s.src_ip_counts),
    agentCounts: objectCountsToMap(s.agent_counts),
    originIps: objectCountsToMap(s.origin_ips),
    impactedIps: objectCountsToMap(s.impacted_ips),
    eventIdCounts: objectCountsToMap(s.event_id_counts),
  };
}

function getActiveAgentCount(windowSec = 300) {
  const connected = new Set(Array.isArray(state.agentIds) ? state.agentIds : []);
  const nowSec = Math.floor(Date.now() / 1000);
  const maxAgeSec = Math.max(60, Number(windowSec) || 300);

  for (const e of (Array.isArray(state.events) ? state.events : [])) {
    const aid = String(e?.agent?.id || e?.agent_id || '').trim();
    if (!aid) continue;
    const t = eventIngestTimeSeconds(e);
    if (!t || (nowSec - t) <= maxAgeSec) connected.add(aid);
  }

  for (const a of (Array.isArray(state.alerts) ? state.alerts : [])) {
    const aid = String(a?.agent_id || a?.agent?.id || '').trim();
    if (!aid) continue;
    const tRaw = a?.last_seen;
    const t = (typeof tRaw === 'string') ? Math.floor(new Date(tRaw).getTime() / 1000) : (typeof tRaw === 'number' ? tRaw : 0);
    if (!t || (nowSec - t) <= maxAgeSec) connected.add(aid);
  }

  const statCount = Number(state.stats?.connected_agents ?? 0);
  return Math.max(connected.size, Number.isFinite(statCount) ? statCount : 0);
}
let eliteTrendChart = null, eliteDonutChart = null;
function paintOverviewDashThrottled() {
  if (state.view !== 'overview') return;
  const paneOverview = document.getElementById('paneOverview');
  if (!paneOverview) return;
  const isEliteOverview = paneOverview.classList.contains('ov-elite');

  if (isEliteOverview) {
    if (!state.mapMode) state.mapMode = 'geoip';
    if (!eliteMap) {
      try {
        initEliteOverview();
      } catch (e) {
        showToast(`Overview map initialization failed: ${e?.message || 'Unknown error'}`, 'warn');
        // Schedule retry after 5 seconds
        if (!window._eliteMapRetryScheduled) {
          window._eliteMapRetryScheduled = true;
          setTimeout(() => {
            try { initEliteOverview(); } catch {}
            window._eliteMapRetryScheduled = false;
          }, 5000);
        }
      }
    }
  }

  const now = Date.now();
  if (now - state.lastOverviewPaint < 700) return;
  state.lastOverviewPaint = now;

  // Dense SIEM-slide Overview. Try elite IDs first, then legacy IDs for backwards compatibility.
  const getElement = (eliteId, legacyId) => {
    const el = document.getElementById(eliteId) || document.getElementById(legacyId);
    if (!el) return null;
    // Quick visibility check — skip expensive getComputedStyle
    if (el.offsetParent === null && el.style.position !== 'fixed') return null;
    return el;
  };
  const trendCanvas = getElement('elite-trendChart', 'ovTrendChart');
  const gaugeCanvas = getElement('ovGaugeMps', 'ovGaugeMps');
  const donutCanvas = getElement('elite-classDonut', 'ovClassDonut');
  const pipelineScoreEl = document.getElementById('elite-pipeline-score') || document.getElementById('ovPipelineScore');
  const pipelineHintEl = document.getElementById('elite-pipeline-hint') || document.getElementById('ovPipelineHint');
  const barsSources = getElement('elite-sources-bars', 'ovTopSourcesBars');
  const barsHosts = getElement('elite-hosts-bars', 'ovTopHostsBars');
  const mapCanvas = getElement('ovThreatMap', 'ovThreatMap');
  const mapNoteEl = document.getElementById('ovMapNote');

  const dense = isEliteOverview || Boolean(trendCanvas || gaugeCanvas || donutCanvas || barsSources || barsHosts || mapCanvas);

  const events = Array.isArray(state.events) ? state.events : [];
  const alerts = Array.isArray(state.alerts) ? state.alerts : [];

  if (dense) {
    const buckets = 60; // last 60 minutes @ 1-min resolution
    const nowSec = Math.floor(Date.now() / 1000);
    const serverAgg = getServerOverviewAggregationSnapshot(nowSec, buckets);
    let agg = serverAgg || getOverviewAggregationSnapshot(events, alerts, nowSec, buckets);
    if (serverAgg) {
      const serverEvTotal = serverAgg.evSeries.reduce((acc, n) => acc + Number(n || 0), 0);
      if (serverEvTotal === 0 && events.length > 0) {
        const localAgg = getOverviewAggregationSnapshot(events, alerts, nowSec, buckets);
        const localEvTotal = localAgg.evSeries.reduce((acc, n) => acc + Number(n || 0), 0);
        if (localEvTotal > 0) agg = localAgg;
      }
    }
    const start = agg.start;
    const evSeries = agg.evSeries;
    const alSeries = agg.alSeries;
    const hiSeries = agg.hiSeries;
    const hpSeries = agg.hpSeries;
    const idsSeries = agg.idsSeries;
    const fimSeries = agg.fimSeries;
    const classCounts = agg.classCounts;
    const srcIpCounts = agg.srcIpCounts;
    const agentCounts = agg.agentCounts;
    const originIps = agg.originIps;
    const impactedIps = agg.impactedIps;
    const eventIdCounts = agg.eventIdCounts;

    // Trend (Detected Events / Critical+High / Alerts)
    if (trendCanvas) {
      drawMultiLine(trendCanvas, [
        { label: 'Events', color: getCssVar('--accent') || '#00d4ff', points: evSeries },
        { label: 'High/Crit', color: getCssVar('--danger') || '#ff4757', points: hiSeries },
        { label: 'Alerts', color: '#ff4081', points: alSeries },
      ]);
    }

    const trendLegend = document.getElementById('ovTrendLegend');
    if (trendLegend) {
      const sum = (arr) => arr.reduce((a, b) => a + Number(b || 0), 0);
      const evT = sum(evSeries);
      const hiT = sum(hiSeries);
      const alT = sum(alSeries);
      trendLegend.innerHTML = `
            <div class="legendDot legendDotAccent"></div><div>Events</div><div class="muted">${evT.toLocaleString()}</div>
            <div class="legendDot legendDotDanger"></div><div>High/Crit</div><div class="muted">${hiT.toLocaleString()}</div>
            <div class="legendDot legendDotWarn"></div><div>Alerts (60m)</div><div class="muted">${alT.toLocaleString()}</div>
          `;
    }

    // Gauge (events/sec) computed from monotonic ingest counter deltas.
    const nowMs = Date.now();
    const ingestTotal = Number(state.stats?.ingest_total_received ?? state.ingestTotalReceived ?? 0);
    let eps = 0;
    let listEps = 0;
    if (Number.isFinite(ingestTotal)) {
      if (typeof state.rate.lastIngestTotal === 'number' && state.rate.lastMs > 0 && nowMs > state.rate.lastMs) {
        const dt = (nowMs - state.rate.lastMs) / 1000;
        const de = ingestTotal - state.rate.lastIngestTotal;
        if (dt > 0 && de >= 0) eps = de / dt;
      }
      state.rate.lastIngestTotal = ingestTotal;
      state.rate.lastMs = nowMs;
    }

    if (typeof state.rate.lastEventListCount === 'number' && state.rate.lastEventListMs > 0 && nowMs > state.rate.lastEventListMs) {
      const dt = (nowMs - state.rate.lastEventListMs) / 1000;
      const de = events.length - state.rate.lastEventListCount;
      if (dt > 0 && de >= 0) listEps = de / dt;
    }
    state.rate.lastEventListCount = events.length;
    state.rate.lastEventListMs = nowMs;

    const alpha = 0.35;
    state.rate.emaEps = (state.rate.emaEps || 0) * (1 - alpha) + Math.max(eps, listEps) * alpha;

    // Seed EMA from server stats on first paint so the gauge isn't stuck at 0.
    const serverEpsHint = Number(state.stats?.ingest_rate_eps ?? state.stats?.eps ?? 0);
    if (state.rate.emaEps < 0.001 && serverEpsHint > 0) {
      state.rate.emaEps = serverEpsHint;
    }

    // Fallback: derive from the 60-minute series (total events / 3600 secs).
    const total60 = evSeries.reduce((a, b) => a + b, 0);
    const seriesEps = total60 > 0 ? total60 / (buckets * 60) : 0;
    const lastMin = evSeries[evSeries.length - 1] || 0;
    const fallbackEps = Math.max(seriesEps, lastMin / 60, listEps, serverEpsHint);
    const mps = (state.rate.emaEps > 0.001) ? state.rate.emaEps : fallbackEps;

    const peakMps = Math.max(...evSeries) / 60;
    const gaugeMax = Math.max(1, Math.ceil(Math.max(peakMps, mps) * 1.6 * 10) / 10);
    if (gaugeCanvas) {
      drawHalfGauge(gaugeCanvas, mps, 0, gaugeMax, getCssVar('--accent') || '#00d4ff');
    }
    setTextIfChanged('ovGaugeValue', (mps >= 10 ? mps.toFixed(1) : mps.toFixed(2)));
    const hi60 = hiSeries.reduce((a, b) => a + b, 0);
    const ingestHint = Number.isFinite(ingestTotal) ? ` • Ingested: ${ingestTotal.toLocaleString()}` : '';
    setTextIfChanged('ovGaugeHint', `Last 60m (ingest): ${total60.toLocaleString()} • High/Crit: ${hi60.toLocaleString()}${ingestHint}`);

    // High-density stream board (aggressive multi-signal surface)
    const al60 = alSeries.reduce((a, b) => a + b, 0);
    // Use 15-minute window for agents; events may batch and arrive late
    const agentsLive = getActiveAgentCount(900);
    const srcUnique = srcIpCounts.size;
    const impactUnique = impactedIps.size;
    const classesActive = classCounts.size;
    const highRatio = total60 ? (hi60 / total60) : 0;

    setTextIfChanged('ovSigAgents', Number(agentsLive || 0).toLocaleString());
    setTextIfChanged('ovSigEps', mps >= 10 ? mps.toFixed(1) : mps.toFixed(2));
    setTextIfChanged('ovSigHigh', hi60.toLocaleString());
    setTextIfChanged('ovSigAlerts', `${al60.toLocaleString()} (60m)`);
    setTextIfChanged('ovSigSources', srcUnique.toLocaleString());
    setTextIfChanged('ovSigImpact', impactUnique.toLocaleString());
    setTextIfChanged('ovSigClass', classesActive.toLocaleString());
    setTextIfChanged('ovSigWs', state.wsOk ? t('ws.ok') : t('ws.connecting'));

    const paintTileTone = (tileId, tone) => {
      const el = document.getElementById(tileId);
      if (!el) return;
      el.classList.remove('t-ok', 't-warn', 't-danger', 't-hot');
      el.classList.add(`t-${tone}`);
    };
    paintTileTone('ovTileAgents', agentsLive >= 3 ? 'ok' : (agentsLive >= 1 ? 'warn' : 'danger'));
    paintTileTone('ovTileEps', mps >= 60 ? 'hot' : (mps >= 20 ? 'danger' : (mps >= 5 ? 'warn' : 'ok')));
    paintTileTone('ovTileHigh', hi60 >= 180 ? 'hot' : (hi60 >= 60 ? 'danger' : (hi60 >= 15 ? 'warn' : 'ok')));
    paintTileTone('ovTileAlerts', al60 >= 120 ? 'hot' : (al60 >= 45 ? 'danger' : (al60 >= 10 ? 'warn' : 'ok')));
    paintTileTone('ovTileSources', srcUnique >= 80 ? 'hot' : (srcUnique >= 35 ? 'danger' : (srcUnique >= 12 ? 'warn' : 'ok')));
    paintTileTone('ovTileImpact', impactUnique >= 60 ? 'hot' : (impactUnique >= 20 ? 'danger' : (impactUnique >= 8 ? 'warn' : 'ok')));
    paintTileTone('ovTileClass', classesActive >= 7 ? 'hot' : (classesActive >= 5 ? 'danger' : (classesActive >= 3 ? 'warn' : 'ok')));
    paintTileTone('ovTileWs', state.wsOk ? 'ok' : 'danger');

    const pulse = document.getElementById('ovPulseMatrix');
    if (pulse) {
      const tail = (arr) => arr.slice(Math.max(0, arr.length - 12));
      const evTail = tail(evSeries);
      const hiTail = tail(hiSeries);
      const alTail = tail(alSeries);
      const rTail = evTail.map((v, i) => {
        const vv = Number(v || 0);
        const hh = Number(hiTail[i] || 0);
        return vv > 0 ? (hh / vv) : 0;
      });
      const maxEv = Math.max(1, ...evTail);
      const maxHi = Math.max(1, ...hiTail);
      const maxAl = Math.max(1, ...alTail);

      const lv = (ratio) => {
        if (ratio >= 0.90) return 'lv5';
        if (ratio >= 0.68) return 'lv4';
        if (ratio >= 0.42) return 'lv3';
        if (ratio >= 0.18) return 'lv2';
        if (ratio > 0) return 'lv1';
        return 'lv0';
      };

      const mk = (row, max, label) => row.map((v, idx) => `<div class="heatCell ${lv(max > 0 ? (Number(v || 0) / max) : 0)}" title="${escapeHtml(label)} T-${11 - idx}m: ${Number(v || 0).toLocaleString()}"></div>`).join('');
      const mkRatio = rTail.map((v, idx) => `<div class="heatCell ${lv(Number(v || 0))}" title="High/Crit ratio T-${11 - idx}m: ${Math.round(Number(v || 0) * 100)}%"></div>`).join('');
      const nextHtml = `${mk(evTail, maxEv, 'Events')}${mk(hiTail, maxHi, 'High/Crit')}${mk(alTail, maxAl, 'Alerts')}${mkRatio}`;
      if (pulse.dataset.sig !== nextHtml) {
        pulse.dataset.sig = nextHtml;
        pulse.innerHTML = nextHtml;
      }
    }
    setTextIfChanged('ovPulseStamp', `${Math.round(highRatio * 100)}% high/crit`);

    const ticker = document.getElementById('ovThreatTicker');
    if (ticker) {
      const recent = events.slice(0, 18);
      const pieces = [];
      for (const e of recent) {
        const sev = String(severityLabel(e) || 'info').toLowerCase();
        const eid = getEventIdValue(e);
        const src = e?.network?.src_ip || e?.agent?.ip || e?.host?.name || e?.agent?.id || 'unknown';
        const msg = shortText(String(e?.event?.summary || e?.message || e?.event?.provider || 'event'), 46);
        const tag = eid ? `ID ${eid}` : shortText(String(e?.event?.provider || 'evt'), 12);
        pieces.push(`<span class="tkItem sev-${escapeHtml(sev)}">${escapeHtml(tag)} • ${escapeHtml(src)} • ${escapeHtml(msg)}</span>`);
      }
      if (!pieces.length) {
        pieces.push('<span class="tkItem sev-info">No fresh events in cache</span>');
      }
      const sig = pieces.join('');
      if (ticker.dataset.sig !== sig) {
        ticker.dataset.sig = sig;
        ticker.innerHTML = `${sig}${sig}`;
      }
    }

    // Pipeline health score (from /api/stats)
    if (pipelineScoreEl || pipelineHintEl) {
      const total = Number(state.stats?.pipeline_quality_total ?? 0);
      const warned = Number(state.stats?.pipeline_quality_warned ?? 0);
      if (!total) {
        setTextIfChanged('ovPipelineScore', '99.9%');
        setTextIfChanged('ovPipelineHint', 'ClickHouse Buffer Status: Healthy');
        if (pipelineScoreEl) pipelineScoreEl.className = 'val t-ok';
      } else {
        const ok = Math.max(0, total - warned);
        const pct = (ok / total) * 100;
        setTextIfChanged('ovPipelineScore', `${pct.toFixed(1)}%`);
        setTextIfChanged('ovPipelineHint', `Total: ${total.toLocaleString()} • Warn: ${warned.toLocaleString()}`);
      }
    }

    // Classification donut
    const palette = [
      { k: 'Auth', c: getCssVar('--warn') || '#ffa502' },
      { k: 'Process', c: getCssVar('--accent') || '#00d4ff' },
      { k: 'Network', c: getCssVar('--ok') || '#26de81' },
      { k: 'IDS', c: getCssVar('--danger') || '#ff4757' },
      { k: 'FIM', c: getCssVar('--muted') || 'rgba(255,255,255,0.65)' },
      { k: 'Honeypot', c: getCssVar('--danger') || '#ff4757' },
      { k: 'System', c: getCssVar('--stroke') || 'rgba(255,255,255,0.35)' },
      { k: 'Other', c: getCssVar('--stroke2') || 'rgba(255,255,255,0.25)' },
    ];
    const allDonutItems = palette
      .map((p) => ({ key: p.k, color: p.c, value: Number(classCounts.get(p.k) || 0) }))
      .filter((x) => x.value > 0)
      .sort((a, b) => b.value - a.value);
    // Show top 5; aggregate the rest as "Other"
    const TOP_N = 5;
    let donutItems;
    if (allDonutItems.length <= TOP_N) {
      donutItems = allDonutItems;
    } else {
      const top = allDonutItems.slice(0, TOP_N);
      const restVal = allDonutItems.slice(TOP_N).reduce((s, x) => s + x.value, 0);
      if (restVal > 0) top.push({ key: 'Other', color: getCssVar('--stroke2') || 'rgba(255,255,255,0.25)', value: restVal });
      donutItems = top;
    }
    const classDonutItems = donutItems;
    if (donutCanvas) {
      drawDonut(donutCanvas, donutItems.length ? donutItems : [{ key: 'Other', color: getCssVar('--stroke') || '#666', value: 1 }]);
    }
    const classLegend = document.getElementById('ovClassLegend');
    if (classLegend) {
      const total = donutItems.reduce((a, b) => a + b.value, 0) || 1;
      classLegend.innerHTML = '';
      for (const it of donutItems) {
        const row = document.createElement('div');
        row.className = 'donutLegendRow';
        row.innerHTML = `
              <div class="legendDot" style="background:${escapeHtml(it.color)}"></div>
              <div>${escapeHtml(it.key)}</div>
              <div class="muted">${Math.round((it.value / total) * 100)}%</div>
            `;
        classLegend.appendChild(row);
      }
      if (!donutItems.length) {
        const row = document.createElement('div');
        row.className = 'donutLegendRow';
        row.innerHTML = '<div class="legendDot legendDotStroke"></div><div>Other</div><div class="muted">100%</div>';
        classLegend.appendChild(row);
      }
    }

    // Top bars
    const topN = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    const topSources = topN(srcIpCounts, 7).map(([k, v]) => ({ label: k, value: v }));
    const topHosts = topN(agentCounts, 7).map(([k, v]) => ({ label: agentLabel(k), value: v }));
    if (barsSources) renderBarBoard(barsSources, topSources, getCssVar('--danger') || '#ff4757');
    if (barsHosts) renderBarBoard(barsHosts, topHosts, getCssVar('--accent') || '#00d4ff');

    // Threat map: GeoIP (optional) + LAN-mode for private networks.
    const mapMode = state.mapMode || 'geoip';
    const mapToggleBtn = document.getElementById('toggleMapMode');
    if (mapToggleBtn) {
      mapToggleBtn.textContent = mapMode === 'lan' ? 'Mode: LAN' : 'Mode: WORLD';
    }
    if (mapMode === 'geoip' && state.geoip.available === null) {
      ensureGeoipAvailability();
    }
    const mapHint = (() => {
      if (mapMode === 'lan') {
        const snap = state.lan?.snapshot;
        const agentsN = Array.isArray(snap?.agents) ? snap.agents.length : 0;
        const devicesN = Array.isArray(snap?.devices) ? snap.devices.length : 0;
        const lanStatus = String(state.lan?.status || 'ok');
        const lanErr = String(state.lan?.error || '').trim();
        if (lanStatus === 'error') {
          return lanErr ? `LAN topology unavailable: ${lanErr}` : 'LAN topology unavailable';
        }
        if (agentsN === 0 && devicesN <= 1) {
          return 'LAN bus topology (limited discovery — install arp-scan w/ CAP_NET_RAW or enable ping sweep on server)';
        }
        return 'LAN bus topology (private network)';
      }
      if (state.geoip.available === false) return 'GeoIP not configured';
      if (state.geoip.available === null) return 'GeoIP status unknown';
      return 'World GeoIP view';
    })();
    if (mapNoteEl) mapNoteEl.textContent = mapHint;

    const isPrivateIp = (s) => {
      const v = String(s || '').trim();
      if (!v) return false;
      if (v.includes(':')) {
        const lv = v.toLowerCase();
        return lv === '::1' || lv.startsWith('fe80:') || lv.startsWith('fc') || lv.startsWith('fd');
      }
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
      if (!m) return false;
      const a = Number(m[1]);
      const b = Number(m[2]);
      if (a === 10) return true;
      if (a === 127) return true;
      if (a === 0) return true;
      if (a === 169 && b === 254) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      return false;
    };

    const drawLocalThreatMap = (canvas, originIpCounts, impactedIpCounts) => {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 600;
      const cssH = canvas.clientHeight || 400;
      const dpr = window.devicePixelRatio || 1;
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const stroke = getCssVar('--stroke2') || 'rgba(255,255,255,0.2)';
      ctx.strokeStyle = stroke;
      ctx.globalAlpha = 0.25;
      const cols = 12;
      const rows = 3;
      for (let i = 1; i < cols; i++) {
        const x = Math.round((w / cols) * i) + 0.5;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let i = 1; i < rows; i++) {
        const y = Math.round((h / rows) * i) + 0.5;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;

      const toSubnet = (ip) => {
        const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || '').trim());
        if (!m) return '';
        return `${m[1]}.${m[2]}.${m[3]}.0/24`;
      };

      const subnetCounts = (countsMap) => {
        const m = new Map();
        for (const [ip, c] of countsMap.entries()) {
          if (!isPrivateIp(ip)) continue;
          const sn = toSubnet(ip);
          if (!sn) continue;
          m.set(sn, (m.get(sn) || 0) + Number(c || 0));
        }
        return m;
      };

      const top = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
      const o = top(subnetCounts(originIpCounts), 10);
      const im = top(subnetCounts(impactedIpCounts), 10);
      const max = Math.max(1, ...o.map((x) => x[1]), ...im.map((x) => x[1]));

      const drawDots = (items, color, rowIndex) => {
        ctx.fillStyle = color;
        const padX = 18;
        const padY = 18;
        const y = padY + rowIndex * ((h - padY * 2) / 2);
        const step = (w - padX * 2) / Math.max(1, items.length - 1);
        for (let i = 0; i < items.length; i++) {
          const [, c] = items[i];
          const x = padX + step * i;
          const r = 4 + Math.min(10, Math.round((Number(c || 0) / max) * 10));
          ctx.globalAlpha = 0.85;
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 0.20;
          ctx.beginPath();
          ctx.arc(x, y, r + 8, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      };

      const toGeoPoints = (countsMap, limit = 80) => {
        const out = [];
        const top = [...countsMap.entries()].sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0)).slice(0, limit);
        for (const [ip, c] of top) {
          const p = state.geoip.cache.get(ip);
          if (!p || !Number.isFinite(p.lat) || !Number.isFinite(p.lon)) continue;
          out.push([p.lat, p.lon, Number(c || 1)]);
        }
        return out;
      };
      const originPts = toGeoPoints(originIps, 80);
      const impactedPts = toGeoPoints(impactedIps, 80);
      const note = (state.geoip.available === false) ? 'GeoIP not configured (set PERCEPTA_GEOIP_DB)' : '';
      if (mapCanvas) drawThreatMap(mapCanvas, originPts, impactedPts, note);
    }

    // ── ELITE UI REDESIGN ──
    if (paneOverview.classList.contains('ov-elite')) {
      paintEliteDash({
        total60, hi60, agentsLive, mps,
        evSeries, alSeries, hpSeries, idsSeries, fimSeries,
        originIps, impactedIps, eventIdCounts,
        classDonutItems,
        alerts
      });
      return; // Skip the legacy paint logic below
    }

    // ── Hero KPI strip (Legacy) ──
    setTextIfChanged('ovHeroEventsVal', total60.toLocaleString());
    setTextIfChanged('ovHeroHighVal', hi60.toLocaleString());
    setTextIfChanged('ovHeroAgentsVal', Number(agentsLive || 0).toLocaleString());
    setTextIfChanged('ovHeroRateVal', mps >= 10 ? mps.toFixed(1) : mps.toFixed(2));

    const _ovBadge = (id, cls, text) => {
      const el = document.getElementById(id);
      if (el && (el.className !== 'ovHeroBadge ' + cls || el.textContent !== text)) {
        el.className = 'ovHeroBadge ' + cls;
        el.textContent = text;
      }
    };
    _ovBadge('ovHeroEventsBadge', total60 === 0 ? 'w' : 'ok', total60 === 0 ? '— No events' : '▲ Nominal');
    _ovBadge('ovHeroHighBadge', hi60 === 0 ? 'ok' : (hi60 < 5 ? 'w' : 'd'), hi60 === 0 ? '— No threats' : (hi60 < 5 ? `▲ ${hi60} threats` : `▲ ${hi60} HIGH/CRIT`));
    _ovBadge('ovHeroAgentsBadge', agentsLive === 0 ? 'd' : (agentsLive < 3 ? 'w' : 'ok'), agentsLive === 0 ? 'No agents connected' : `${agentsLive} active`);
    _ovBadge('ovHeroRateBadge', mps === 0 ? 'w' : (mps >= 60 ? 'd' : 'ok'), mps === 0 ? 'No traffic' : (mps >= 60 ? '▲ High load' : 'Monitoring'));

    // ── Pipeline ring arc ──
    const _pipeRingArc = document.getElementById('ovPipeRingArc');
    if (_pipeRingArc) {
      const _pipeTotal = Number(state.stats?.pipeline_quality_total ?? 0);
      const _pipeWarn = Number(state.stats?.pipeline_quality_warned ?? 0);
      const _pipePct = _pipeTotal > 0 ? ((_pipeTotal - _pipeWarn) / _pipeTotal) : 0;
      const _pipeCirc = 2 * Math.PI * 21;
      _pipeRingArc.style.strokeDashoffset = (_pipeCirc * (1 - _pipePct)).toFixed(1);
      _pipeRingArc.style.stroke = _pipePct >= 0.8 ? (getCssVar('--ok') || '#3ad27a') : (_pipePct >= 0.5 ? (getCssVar('--warn') || '#ffb14a') : (getCssVar('--danger') || '#ff5d7a'));
    }
    // Pipeline check status
    setTextIfChanged('ovPipeWsVal', state.wsOk ? 'Connected' : 'Connecting…');
    setTextIfChanged('ovPipeAgentVal', `${Number(agentsLive || 0)} active`);
    const _wsDot = document.getElementById('ovPipeWsDot');
    if (_wsDot) _wsDot.style.background = state.wsOk ? (getCssVar('--ok') || '#3ad27a') : (getCssVar('--danger') || '#ff5d7a');
    const _agDot = document.getElementById('ovPipeAgDot');
    if (_agDot) _agDot.style.background = agentsLive > 0 ? (getCssVar('--ok') || '#3ad27a') : (getCssVar('--faint') || 'rgba(240,248,255,0.5)');
    // Parser engine status — healthy when overall server health is ok
    const _parserValEl = document.getElementById('ovPipeParserVal');
    const _parserDotEl = _parserValEl ? _parserValEl.closest('.ovPipeCheck')?.querySelector('.ovPipeCheckDot') : null;
    if (_parserValEl) {
      if (state.lastHealthStatus === 'pending') {
        _parserValEl.textContent = 'Initializing…';
        if (_parserDotEl) _parserDotEl.style.background = getCssVar('--faint') || 'rgba(240,248,255,0.5)';
      } else if (state.lastHealthStatus === 'ok') {
        _parserValEl.textContent = 'OK';
        if (_parserDotEl) _parserDotEl.style.background = getCssVar('--ok') || '#3ad27a';
      } else {
        _parserValEl.textContent = 'Degraded';
        if (_parserDotEl) _parserDotEl.style.background = getCssVar('--danger') || '#ff5d7a';
      }
    }

    // ── Map overlay stats ──
    setTextIfChanged('ovMapStatEvents', total60.toLocaleString());
    setTextIfChanged('ovMapStatHigh', hi60.toLocaleString());
    setTextIfChanged('ovMapStatAgents', Number(agentsLive || 0).toLocaleString());

    // ── Rate mini-bars ──
    const _rateBarsEl = document.getElementById('ovRateBarsEl');
    if (_rateBarsEl) {
      const _rSlice = evSeries.slice(-30);
      const _rMax = Math.max(1, ..._rSlice);
      const _rHtml = _rSlice.map((v, i, a) => {
        const pct = Math.max(4, Math.round((v / _rMax) * 100));
        const isCur = i === a.length - 1;
        const cls = 'ovRateBar' + (isCur ? ' cur' : (v > _rMax * 0.5 ? ' active' : ''));
        return `<div class="${cls}" style="height:${pct}%"></div>`;
      }).join('');
      if (_rateBarsEl.dataset.barSig !== _rHtml) {
        _rateBarsEl.dataset.barSig = _rHtml;
        _rateBarsEl.innerHTML = _rHtml;
      }
    }

    // ── Country ranking from origin IPs ──
    const _countryEl = document.getElementById('ovCountryList');
    if (_countryEl && originIps.size > 0) {
      // Prefer country/city grouping from GeoIP cache; fallback to IP when unresolved.
      const _geoGroups = new Map();
      for (const [ip, cnt] of originIps.entries()) {
        const g = state.geoip.cache.get(ip);
        const country = String(g?.country || '').trim();
        const city = String(g?.city || '').trim();
        const key = country ? `${country}|${city || ''}` : `ip:${ip}`;
        const label = country ? (city ? `${country} • ${city}` : country) : ip;
        const obj = _geoGroups.get(key) || { label, count: 0 };
        obj.count += Number(cnt || 0);
        _geoGroups.set(key, obj);
      }
      const _topO = [..._geoGroups.values()].sort((a, b) => b.count - a.count).slice(0, 7);
      const _maxO = Math.max(1, _topO[0]?.count || 1);
      const _rows = _topO.map((item, idx) => {
        const cnt = Number(item.count || 0);
        const pct = Math.round((cnt / _maxO) * 100);
        const sev = cnt >= 20 ? ['h', 'HIGH'] : cnt >= 5 ? ['m', 'MED'] : ['l', 'LOW'];
        const clr = sev[0] === 'h' ? 'var(--danger)' : sev[0] === 'm' ? 'var(--warn)' : 'var(--accent)';
        return `<div class="ovCountryRow"><span class="ovCRank">${idx + 1}</span><span class="ovCFlag">🌐</span><span class="ovCName">${escapeHtml(item.label)}</span><div class="ovCBarW"><div class="ovCBar" style="width:${pct}%;background:${clr}"></div></div><span class="ovCCount">${cnt}</span><span class="ovCSev ${sev[0]}">${sev[1]}</span></div>`;
      });
      const _sig = _rows.join('');
      if (_countryEl.dataset.sig !== _sig) {
        _countryEl.dataset.sig = _sig;
        _countryEl.innerHTML = _sig || '<div class="ovCountryRow ovCountryRowEmpty"><span class="ovCountryEmptyText">No origin data</span></div>';
      }
    }

    // ── Live geo feed from recent events with source IPs ──
    const _geoFeedEl = document.getElementById('ovGeoFeed');
    if (_geoFeedEl) {
      const _nowSc = Math.floor(Date.now() / 1000);
      const _recentIp = events.filter(e => e?.network?.src_ip && !isPrivateIp(e.network.src_ip)).slice(0, 8);
      const _feedRows = _recentIp.map(e => {
        const ip = escapeHtml(e.network.src_ip || '');
        const dst = escapeHtml(e.network.dst_ip || '');
        const host = escapeHtml(e.host?.name || e.agent?.id || '');
        const geo = state.geoip.cache.get(e.network.src_ip || '') || null;
        const place = geo?.country ? `${geo.country}${geo.city ? ` • ${geo.city}` : ''}` : '';
        const sev = String(severityLabel(e) || 'info').toLowerCase();
        const t = eventIngestTimeSeconds(e);
        const age = (typeof t === 'number') ? (() => { const s = Math.max(0, Math.round(_nowSc - t)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${s % 60}s`; })() : '–';
        return `<div class="ovGeoRow ${(sev === 'high' || sev === 'critical') ? 'new-entry' : ''}"><div class="ovGeoIp">${ip}</div><div class="ovGeoMeta"><span>${escapeHtml(place || host || dst)}</span><span class="ovGeoTime">${escapeHtml(age)}</span></div></div>`;
      });
      if (!_feedRows.length) _feedRows.push('<div class="ovGeoRow ovGeoRowEmpty"><div class="ovGeoIp ovGeoIpEmpty">No external IP events</div></div>');
      const _feedSig = _feedRows.join('');
      if (_geoFeedEl.dataset.sig !== _feedSig) {
        _geoFeedEl.dataset.sig = _feedSig;
        _geoFeedEl.innerHTML = _feedSig;
      }
    }

    // ── Scope insight panels ──
    {
      const scope = currentScopeForView('overview');
      document.querySelectorAll('#ovScopeInsights .ovInsightPanel').forEach(p => {
        p.style.display = p.getAttribute('data-scope-vis') === scope ? '' : 'none';
      });

      const openAlerts = alerts.filter(a => (a?.status || 'new') === 'new' || a?.status === 'investigating');
      const resolvedAlerts = alerts.filter(a => a?.status === 'resolved' || a?.status === 'false_positive');
      const fpAlerts = alerts.filter(a => a?.status === 'false_positive');

      // Collect MITRE data from alerts
      const tacticSet = new Set();
      const techSet = new Set();
      const tacticCounts = new Map();
      for (const a of alerts) {
        const md = (a && a.metadata && typeof a.metadata === 'object') ? a.metadata : {};
        const tactics = String(md.mitre_tactics || '').split(',').map(s => s.trim()).filter(Boolean);
        const techs = String(md.mitre_attack || '').split(',').map(s => s.trim()).filter(Boolean);
        for (const t of tactics) { tacticSet.add(t); tacticCounts.set(t, (tacticCounts.get(t) || 0) + 1); }
        for (const t of techs) techSet.add(t);
      }

      if (scope === 'executive') {
        // Risk score: weighted by open alert severity
        let riskScore = 0;
        for (const a of openAlerts) {
          const sev = String(a?.severity || '').toLowerCase();
          if (sev === 'critical') riskScore += 10;
          else if (sev === 'high') riskScore += 5;
          else if (sev === 'medium') riskScore += 2;
          else riskScore += 1;
        }
        riskScore = Math.min(100, riskScore);
        setTextIfChanged('ovExecRiskScore', String(riskScore));
        const riskEl = document.getElementById('ovExecRiskScore');
        if (riskEl) riskEl.style.color = riskScore >= 60 ? 'var(--danger)' : riskScore >= 30 ? 'var(--warn)' : 'var(--ok, #3ad27a)';
        setTextIfChanged('ovExecRiskHint', riskScore >= 60 ? 'Critical' : riskScore >= 30 ? 'Elevated' : 'Nominal');
        setTextIfChanged('ovExecOpenAlerts', String(openAlerts.length));
        setTextIfChanged('ovExecAlertTrend', openAlerts.length === 0 ? 'All clear' : openAlerts.length < 5 ? 'Low volume' : 'Needs attention');
        setTextIfChanged('ovExecMitreTactics', String(tacticSet.size));
      } else if (scope === 'stream') {
        const density = events.length > 0 ? ((alerts.length / events.length) * 100).toFixed(1) : '0.0';
        setTextIfChanged('ovStreamDensity', density);
        const topTactic = [...tacticCounts.entries()].sort((a, b) => b[1] - a[1])[0];
        setTextIfChanged('ovStreamTopTactic', topTactic ? topTactic[0] : '—');
        setTextIfChanged('ovStreamTopTacticCount', topTactic ? `${topTactic[1]} alerts` : '—');
        setTextIfChanged('ovStreamTechniques', String(techSet.size));
        const fpRate = resolvedAlerts.length > 0 ? ((fpAlerts.length / resolvedAlerts.length) * 100).toFixed(0) + '%' : '—';
        setTextIfChanged('ovStreamFpRate', fpRate);
      } else if (scope === 'ops') {
        const totalAgents = Number(state.stats?.agent_count ?? state.stats?.known_agents?.length ?? state.knownAgents?.length ?? 0);
        const liveAgents = Number(agentsLive || 0);
        const degradedAgents = Number(state.stats?.degraded_agents ?? 0);
        const offlineAgents = Number(state.stats?.offline_agents ?? 0);
        const presenceP95Sec = Number(state.stats?.presence_age_p95_sec ?? 0);
        const presenceTrend = Array.isArray(state.stats?.presence_trend) ? state.stats.presence_trend.slice(-10) : [];
        setTextIfChanged('ovOpsAgentUptime', totalAgents > 0 ? Math.round((liveAgents / totalAgents) * 100) + '%' : '—');
        const p95DriftText = Number.isFinite(presenceP95Sec) && presenceP95Sec > 0
          ? `${presenceP95Sec}s p95 drift`
          : 'no drift samples yet';
        const sparkline = (series) => {
          const blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
          if (!Array.isArray(series) || !series.length) return 'n/a';
          const values = series.map((v) => Number(v || 0));
          const max = Math.max(...values, 1);
          return values
            .map((v) => blocks[Math.max(0, Math.min(7, Math.round((v / max) * 7)))])
            .join('');
        };
        const connTrend = sparkline(presenceTrend.map((p) => p?.connected_agents));
        const degrTrend = sparkline(presenceTrend.map((p) => p?.degraded_agents));
        const offTrend = sparkline(presenceTrend.map((p) => p?.offline_agents));
        setTextIfChanged(
          'ovOpsAgentUptimeHint',
          `${liveAgents} / ${totalAgents} connected • ${degradedAgents} degraded • ${offlineAgents} offline • ${p95DriftText} • Trend C:${connTrend} D:${degrTrend} O:${offTrend}`
        );
        setTextIfChanged('ovOpsParseErrors', String(Number(state.stats?.parse_errors_24h ?? 0)));
        const avgLat = state.stats?.avg_latency_ms;
        setTextIfChanged('ovOpsAvgLatency', avgLat != null ? Number(avgLat).toFixed(0) + 'ms' : '—');
        const storageBytes = Number(state.stats?.storage_bytes ?? 0);
        const persist = state.stats?.presence_persistence || null;
        const lastWrite = Number(persist?.last_persist_unix || 0);
        const lastRestore = Number(persist?.last_restore_unix || 0);
        const persistHint = persist?.enabled
          ? `Presence snapshot: ${lastWrite > 0 ? `write ${new Date(lastWrite * 1000).toLocaleTimeString()}` : 'write pending'}${lastRestore > 0 ? ` • restore ${new Date(lastRestore * 1000).toLocaleTimeString()}` : ''}`
          : 'Presence snapshot: disabled';
        setTextIfChanged('ovOpsStorageHint', `ClickHouse • ${persistHint}`);
        if (storageBytes > 0) {
          const gb = (storageBytes / (1024 * 1024 * 1024)).toFixed(2);
          setTextIfChanged('ovOpsStorage', gb + ' GB');
        }
      }
    }

    return;
  }

  // 10 minute buckets (1-min resolution)
  const buckets = 10;
  const evSeries = new Array(buckets).fill(0);
  const alSeries = new Array(buckets).fill(0);
  const hpSeries = new Array(buckets).fill(0);
  const idsSeries = new Array(buckets).fill(0);
  const fimSeries = new Array(buckets).fill(0);
  const nowSec = Math.floor(Date.now() / 1000);
  const start = nowSec - buckets * 60;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  // Legacy overview: keep event-volume counts for diagnostics, but compute "top impacted"
  // agents from alerts so a noisy agent doesn't dominate this widget.
  const agentEventCounts = new Map();
  const agentAlertCounts = new Map();
  const eventIdCounts = new Map();
  const srcIpCounts = new Map();

  const hpIpCounts = new Map();
  const idsSigCounts = new Map();
  const fimPathCounts = new Map();

  for (const e of events) {
    const sev = severityLabel(e);
    if (sevCounts[sev] !== undefined) sevCounts[sev] += 1;

    const t = eventTimeSeconds(e);
    if (typeof t === 'number' && t >= start && t <= nowSec) {
      const idx = Math.min(buckets - 1, Math.max(0, Math.floor((t - start) / 60)));
      evSeries[idx] += 1;

      if (isHoneypotEvent(e)) hpSeries[idx] += 1;
      if (isIdsEvent(e)) idsSeries[idx] += 1;
      if (isFimEvent(e)) fimSeries[idx] += 1;
    }

    const aid = e?.agent?.id || e?.agent_id || '';
    if (aid) agentEventCounts.set(aid, (agentEventCounts.get(aid) || 0) + 1);

    const eid = getEventIdValue(e);
    if (eid) eventIdCounts.set(eid, (eventIdCounts.get(eid) || 0) + 1);

    const ip = getBestIp(e);
    if (ip) srcIpCounts.set(ip, (srcIpCounts.get(ip) || 0) + 1);

    if (isHoneypotEvent(e) && ip) hpIpCounts.set(ip, (hpIpCounts.get(ip) || 0) + 1);

    if (isIdsEvent(e)) {
      const sig = e?.event?.summary || e?.event?.event_id || e?.event?.provider || e?.message || 'ids';
      const s = shortText(String(sig), 64);
      idsSigCounts.set(s, (idsSigCounts.get(s) || 0) + 1);
    }

    if (isFimEvent(e)) {
      const p = e?.file?.path || e?.registry?.path || e?.event?.summary || e?.message || 'fim';
      const s = shortText(String(p), 64);
      fimPathCounts.set(s, (fimPathCounts.get(s) || 0) + 1);
    }
  }

  for (const a of alerts) {
    const t = a?.last_seen;
    const sec = (typeof t === 'string') ? Math.floor(new Date(t).getTime() / 1000) : (typeof t === 'number' ? t : null);
    if (typeof sec === 'number' && sec >= start && sec <= nowSec) {
      const idx = Math.min(buckets - 1, Math.max(0, Math.floor((sec - start) / 60)));
      alSeries[idx] += 1;

      const aid = a?.agent_id || a?.agent?.id || '';
      const w = Number(a?.count || 1);
      if (aid) agentAlertCounts.set(aid, (agentAlertCounts.get(aid) || 0) + ((Number.isFinite(w) && w > 0) ? w : 1));
    }
  }

  const evTotal10 = evSeries.reduce((a, b) => a + b, 0);
  const alTotal10 = alSeries.reduce((a, b) => a + b, 0);
  const evPerMin = Math.round(evTotal10 / Math.max(1, buckets));
  const alPerMin = Math.round(alTotal10 / Math.max(1, buckets));

  setTextIfChanged('ovEventsMin', evPerMin.toLocaleString());
  setTextIfChanged('ovAlertsMin', alPerMin.toLocaleString());

  const hpTotal10 = hpSeries.reduce((a, b) => a + b, 0);
  const idsTotal10 = idsSeries.reduce((a, b) => a + b, 0);
  const fimTotal10 = fimSeries.reduce((a, b) => a + b, 0);
  setTextIfChanged('ovHpMin', Math.round(hpTotal10 / Math.max(1, buckets)).toLocaleString());
  setTextIfChanged('ovIdsMinMod', Math.round(idsTotal10 / Math.max(1, buckets)).toLocaleString());
  setTextIfChanged('ovFimMin', Math.round(fimTotal10 / Math.max(1, buckets)).toLocaleString());

  const highCrit = sevCounts.high + sevCounts.critical;
  const highCritPct = events.length ? Math.round((highCrit / events.length) * 100) : 0;
  setTextIfChanged('ovHighCrit', `${highCritPct}%`);

  const agentsLive = getActiveAgentCount(300);
  const agentsEl = document.getElementById('ovAgentsLive');
  if (agentsEl) agentsEl.textContent = `Agents live: ${agentsLive}`;

  // Deltas vs last paint snapshot (simple, punchy)
  const snap = {
    ev: Number(state.stats?.ingest_total_received ?? state.ingestTotalReceived ?? 0),
    al: Number(state.stats?.total_alerts ?? state.alerts.length ?? 0),
  };
  const prev = state.lastOverviewSnapshot;
  state.lastOverviewSnapshot = snap;

  const formatDelta = (n) => (n > 0 ? `+${n}` : (n < 0 ? `${n}` : '0'));
  const setDelta = (id, delta) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = `Δ ${formatDelta(delta)}`;
    el.classList.toggle('pos', delta > 0);
    el.classList.toggle('neg', delta < 0);
  };
  if (prev) {
    setDelta('ovEventsDelta', snap.ev - prev.ev);
    setDelta('ovAlertsDelta', snap.al - prev.al);
  } else {
    setDelta('ovEventsDelta', 0);
    setDelta('ovAlertsDelta', 0);
  }

  drawLine(document.getElementById('ovChartEvents'), evSeries, getCssVar('--accent') || '#00d4ff');
  drawLine(document.getElementById('ovChartAlerts'), alSeries, getCssVar('--warn') || '#ffa502');
  drawSeverityBars(document.getElementById('ovChartSeverity'), sevCounts);

  drawLine(document.getElementById('ovChartHoneypot'), hpSeries, getCssVar('--danger') || '#ff4757');
  drawLine(document.getElementById('ovChartIdsMod'), idsSeries, getCssVar('--warn') || '#ffa502');
  drawLine(document.getElementById('ovChartFim'), fimSeries, getCssVar('--ok') || '#26de81');

  // Hotspots board
  const boards = document.getElementById('ovBoards');
  if (boards) {
    const topN = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    const topAgents = topN(agentAlertCounts, 3).map(([id, c]) => ({ label: agentLabel(id), count: c }));
    const topEventIds = topN(eventIdCounts, 3).map(([id, c]) => ({ label: id, count: c }));
    const topIps = topN(srcIpCounts, 3).map(([ip, c]) => ({ label: ip, count: c }));

    boards.innerHTML = '';
    const mkSection = (title, rows) => {
      const wrap = document.createElement('div');
      wrap.style.display = 'flex';
      wrap.style.flexDirection = 'column';
      wrap.style.gap = '6px';
      const t = document.createElement('div');
      t.className = 'muted';
      t.style.fontSize = '12px';
      t.style.letterSpacing = '0.6px';
      t.style.textTransform = 'uppercase';
      t.textContent = title;
      wrap.appendChild(t);
      for (const r of rows) {
        const row = document.createElement('div');
        row.className = 'boardRow';
        row.innerHTML = `<span>${escapeHtml(r.label)}</span><strong>${Number(r.count).toLocaleString()}</strong>`;
        wrap.appendChild(row);
      }
      return wrap;
    };

    boards.appendChild(mkSection('Top impacted agents', topAgents.length ? topAgents : [{ label: '–', count: 0 }]));
    boards.appendChild(mkSection('Top event IDs', topEventIds.length ? topEventIds : [{ label: '–', count: 0 }]));
    boards.appendChild(mkSection('Top IPs', topIps.length ? topIps : [{ label: '–', count: 0 }]));
  }

  // Module boards + hints
  const topN = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  const setHint = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };

  setHint('ovHpHint', hpTotal10 ? `Last 10m: ${hpTotal10}` : 'Quiet');
  setHint('ovIdsHint', idsTotal10 ? `Last 10m: ${idsTotal10}` : 'Quiet');
  setHint('ovFimHint', fimTotal10 ? `Last 10m: ${fimTotal10}` : 'Quiet');

  const hpBoards = document.getElementById('ovHpBoards');
  if (hpBoards) {
    const topHpIps = topN(hpIpCounts, 3).map(([k, v]) => ({ label: k, count: v }));
    hpBoards.innerHTML = '';
    for (const r of (topHpIps.length ? topHpIps : [{ label: 'Top attacker IP: none', count: 0 }])) {
      const row = document.createElement('div');
      row.className = 'boardRow';
      row.innerHTML = `<span>${escapeHtml(r.label)}</span><strong>${Number(r.count).toLocaleString()}</strong>`;
      hpBoards.appendChild(row);
    }
  }

  const idsBoards = document.getElementById('ovIdsBoards');
  if (idsBoards) {
    const topIds = topN(idsSigCounts, 3).map(([k, v]) => ({ label: k, count: v }));
    idsBoards.innerHTML = '';
    for (const r of (topIds.length ? topIds : [{ label: t('overview.topSignatureFallback'), count: 0 }])) {
      const row = document.createElement('div');
      row.className = 'boardRow';
      row.innerHTML = `<span>${escapeHtml(r.label)}</span><strong>${Number(r.count).toLocaleString()}</strong>`;
      idsBoards.appendChild(row);
    }
  }

  const fimBoards = document.getElementById('ovFimBoards');
  if (fimBoards) {
    const topFim = topN(fimPathCounts, 3).map(([k, v]) => ({ label: k, count: v }));
    fimBoards.innerHTML = '';
    for (const r of (topFim.length ? topFim : [{ label: t('overview.topPathFallback'), count: 0 }])) {
      const row = document.createElement('div');
      row.className = 'boardRow';
      row.innerHTML = `<span>${escapeHtml(r.label)}</span><strong>${Number(r.count).toLocaleString()}</strong>`;
      fimBoards.appendChild(row);
    }
  }
}

let lanAnimRaf = null;
let lanLastPacketTime = 0;

function fetchLanTopology() {
  const container = document.getElementById('lanTopology');
  if (!container) return;

  const agents = Array.isArray(state.stats?.known_agents) ? state.stats.known_agents : [];
  const activeAgents = Array.isArray(state.agentIds) ? state.agentIds : [];

  let html = `<div class="lan-node core" style="top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 10;">SERVER</div>`;
  html += `<div class="lan-node crit" style="top: 20%; left: 65%; z-index: 10;">DB-01</div>`;

  let svgLines = `
            <line x1="50%" y1="50%" x2="65%" y2="20%" stroke="var(--danger)" stroke-width="3" opacity="0.8"/>
        `;

  const R = 35;
  const agentNodes = [];
  const displayAgents = agents.length > 0 ? agents : [{ id: 'WAIT', hostname: 'Awaiting...' }];

  displayAgents.forEach((ag, i) => {
    const isOffline = agents.length > 0 && !activeAgents.includes(ag.id);
    const angle = (i / displayAgents.length) * Math.PI * 2;
    const adjustedAngle = angle + Math.PI * 0.8;

    const top = 50 + R * Math.sin(adjustedAngle);
    const left = 50 + R * Math.cos(adjustedAngle);

    const cls = isOffline ? 'lan-node offline' : 'lan-node';
    const label = ag.hostname ? String(ag.hostname).substring(0, 8) : String(ag.id).substring(0, 8);

    html += `<div class="${cls}" style="top: ${top}%; left: ${left}%; z-index: 10;">${escapeHtml(label)}</div>`;

    const stroke = isOffline ? 'var(--muted)' : 'var(--accent)';
    const dash = isOffline ? 'stroke-dasharray="5,5"' : '';
    svgLines += `<line x1="50%" y1="50%" x2="${left}%" y2="${top}%" stroke="${stroke}" stroke-width="2" ${dash} opacity="0.4"/>`;

    if (!isOffline && agents.length > 0) {
      agentNodes.push({ top, left });
    }
  });

  html += `<svg id="lanSvg" style="position:absolute; top:0; left:0; width:100%; height:100%; z-index:1; pointer-events:none;">${svgLines}</svg>`;
  html += `<div id="lanPackets" style="position:absolute; top:0; left:0; width:100%; height:100%; z-index:15; pointer-events:none;"></div>`;

  const sig = String(agents.length) + "-" + String(activeAgents.length);
  if (container.dataset.sig !== sig) {
    container.innerHTML = html;
    container.dataset.sig = sig;
  }

  window._lanAgentPositions = agentNodes;
}

function ensureLanAnimLoop() {
  if (lanAnimRaf) return;

  const loop = () => {
    if (state.mapMode !== 'lan' || state.view !== 'overview') {
      lanAnimRaf = null;
      lanLastPacketTime = 0;
      return;
    }

    const now = Date.now();
    if (now - lanLastPacketTime > 600) {
      lanLastPacketTime = now;
      spawnPacket();
    }

    // Frame rate throttling: 30fps target (33ms per frame) instead of 60fps.
    const nextFrame = (window._lanLastFrameTime || 0) + 33;
    if (now >= nextFrame) {
      window._lanLastFrameTime = now;
      lanAnimRaf = requestAnimationFrame(loop);
    } else {
      lanAnimRaf = requestAnimationFrame(loop);
    }
  };
  lanAnimRaf = requestAnimationFrame(loop);
}

function spawnPacket() {
  const container = document.getElementById('lanPackets');
  if (!container || !window._lanAgentPositions || window._lanAgentPositions.length === 0) return;

  const agents = window._lanAgentPositions;
  const from = agents[Math.floor(Math.random() * agents.length)];

  const pkt = document.createElement('div');
  pkt.className = 'lan-packet';
  if (Math.random() < 0.1) pkt.classList.add('crit');
  container.appendChild(pkt);

  const anim = pkt.animate([
    { top: (String(from.top) + '%'), left: (String(from.left) + '%'), opacity: 1 },
    { top: '50%', left: '50%', opacity: 0 }
  ], {
    duration: 800 + Math.random() * 400,
    easing: 'ease-in'
  });

  anim.onfinish = () => pkt.remove();
}


/**
 * Premium LAN Topology Visualization (Star/Bus Hybrid)
 */
function fetchPremiumLanTopology() {
  const container = document.getElementById('lanTopology');
  if (!container) return Promise.resolve();

  return fetch('/api/lan/topology')
    .then(res => res.json())
    .then(data => {
      const nodes = data.nodes || [];
      if (nodes.length === 0) {
        container.innerHTML = `
          <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:12px;color:var(--muted);text-align:center;padding:28px;user-select:none">
            <svg width="46" height="46" viewBox="0 0 46 46" fill="none" xmlns="http://www.w3.org/2000/svg" opacity="0.38">
              <circle cx="23" cy="23" r="19" stroke="currentColor" stroke-width="1.4" stroke-dasharray="4 3"/>
              <circle cx="23" cy="23" r="4" fill="currentColor" opacity="0.35"/>
              <line x1="23" y1="4" x2="23" y2="42" stroke="currentColor" stroke-width="1" opacity="0.22"/>
              <line x1="4" y1="23" x2="42" y2="23" stroke="currentColor" stroke-width="1" opacity="0.22"/>
              <line x1="9" y1="9" x2="37" y2="37" stroke="currentColor" stroke-width="1" opacity="0.18"/>
            </svg>
            <span style="font-size:11px;font-weight:700;letter-spacing:1.8px;text-transform:uppercase;opacity:0.52">LAN Topology Unavailable</span>
            <span style="font-size:10px;opacity:0.36;max-width:210px;line-height:1.6">No agents are reporting network topology data in this environment. Deploy agents on target LAN segments to enable this view.</span>
          </div>`;
        return;
      }
      renderPremiumTopology(data, container);
    })
    .catch(() => {
      if (container) container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);font-size:11px;opacity:0.42;letter-spacing:0.5px">Topology data unavailable</div>';
    });
}

function renderPremiumTopology(data, container) {
  container.innerHTML = '';
  const nodes = data.nodes || [];
  const connections = data.connections || [];

  // Core Switch (Central Hub)
  const coreNode = { id: 'CORE_GATEWAY', type: 'switch', label: 'CORE GW', x: 50, y: 50 };
  const allNodes = [coreNode, ...nodes.filter(n => n.id !== 'CORE_GATEWAY')];

  const radius = 35;
  allNodes.forEach((node, i) => {
    if (node.id === 'CORE_GATEWAY') {
      node.x = 50; node.y = 50;
    } else {
      const angle = (i / (allNodes.length - 1)) * 2 * Math.PI;
      node.x = 50 + radius * Math.cos(angle);
      node.y = 50 + radius * Math.sin(angle);
    }

    const el = document.createElement('div');
    el.className = 'lan-node-ov ' + (node.type || 'agent');
    el.style.left = node.x + '%';
    el.style.top = node.y + '%';
    el.innerHTML = '<div class="node-icon">' + (node.type === 'switch' ? '󱘖' : '󰈙') + '</div><div class="node-label">' + escapeHtml(node.label || node.id) + '</div>';
    container.appendChild(el);
  });

  // Draw SVG Links
  let svg = container.querySelector('.lan-svg-layer');
  if (!svg) {
    svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'lan-svg-layer');
    container.prepend(svg);
  }
  svg.innerHTML = '';
  allNodes.forEach(node => {
    if (node.id === 'CORE_GATEWAY') return;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', '50%'); line.setAttribute('y1', '50%');
    line.setAttribute('x2', node.x + '%'); line.setAttribute('y2', node.y + '%');
    line.setAttribute('class', 'lan-link-ov');
    svg.appendChild(line);
  });

  startLanSimulation(container, allNodes);
}

let lanAnimInterval = null;
let lanSimLastPacketTime = 0;
let lanSimNodes = null;
let lanSimContainer = null;

function startLanSimulation(container, nodes) {
  // Kill any existing RAF-based premium animation
  if (lanAnimInterval !== null) {
    cancelAnimationFrame(lanAnimInterval);
    lanAnimInterval = null;
  }
  
  lanSimContainer = container;
  lanSimNodes = nodes;
  lanSimLastPacketTime = Date.now();

  const premiumLoop = () => {
    if (state.mapMode !== 'lan' || state.view !== 'overview' || !lanSimContainer || !lanSimNodes) {
      lanAnimInterval = null;
      lanSimContainer = null;
      lanSimNodes = null;
      return;
    }

    const now = Date.now();
    if (now - lanSimLastPacketTime > 400) {
      lanSimLastPacketTime = now;
      const src = lanSimNodes[Math.floor(Math.random() * lanSimNodes.length)];
      if (src && src.id !== 'CORE_GATEWAY') {
        spawnLanPacket(lanSimContainer, src, { x: 50, y: 50 });
      }
    }

    lanAnimInterval = requestAnimationFrame(premiumLoop);
  };
  lanAnimInterval = requestAnimationFrame(premiumLoop);
}

function spawnLanPacket(container, from, to) {
  const pkt = document.createElement('div');
  pkt.className = 'lan-packet-ov';
  if (Math.random() < 0.1) pkt.classList.add('crit');
  container.appendChild(pkt);

  pkt.animate([
    { left: from.x + '%', top: from.y + '%', opacity: 1 },
    { left: to.x + '%', top: to.y + '%', opacity: 0 }
  ], {
    duration: 800 + Math.random() * 400,
    easing: 'ease-in-out'
  }).onfinish = () => pkt.remove();
}

function initPremiumOverview() {
  const wrapper = document.getElementById('ovThreatMapWrapper');
  if (!wrapper || (typeof ovMap !== 'undefined' && ovMap)) return;
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  ovMap = L.map('ovThreatMapWrapper', { zoomControl: false, attributionControl: false, worldCopyJump: true, minZoom: 2 }).setView([20, 0], 2);
  L.tileLayer(isLight ? 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png' : 'https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', { subdomains: 'abcd', maxZoom: 19, crossOrigin: 'anonymous' }).addTo(ovMap);

  const spotlight = document.getElementById('map-spotlight-ov');
  if (spotlight) {
    document.addEventListener('mousemove', (e) => {
      if (state.view !== 'overview') return;
      const pane = document.getElementById('paneOverview');
      const color = (pane ? getComputedStyle(pane).getPropertyValue('--ov-accent').trim() : '') || '#00d4ff';
      spotlight.style.background = `radial-gradient(circle 450px at ${e.clientX}px ${e.clientY}px, ${color}1f, transparent 80%)`;
    });
  }

  // Geo/Lan button delegation
  document.addEventListener('click', (e) => {
    if (e.target?.id === 'btn-geo-ov' || e.target?.closest('#btn-geo-ov')) {
      state.mapMode = 'geoip';
      document.getElementById('btn-geo-ov')?.classList.add('active');
      document.getElementById('btn-lan-ov')?.classList.remove('active');
      document.getElementById('view-geo-ov')?.classList.add('active');
      document.getElementById('view-lan-ov')?.classList.remove('active');
      ovMap?.invalidateSize?.();
    }
    if (e.target?.id === 'btn-lan-ov' || e.target?.closest('#btn-lan-ov')) {
      state.mapMode = 'lan';
      document.getElementById('btn-geo-ov')?.classList.remove('active');
      document.getElementById('btn-lan-ov')?.classList.add('active');
      document.getElementById('view-geo-ov')?.classList.remove('active');
      document.getElementById('view-lan-ov')?.classList.add('active');
      fetchPremiumLanTopology();
    }
  });
}

function updateThreatMap(events) {
  if (typeof ovMap === 'undefined' || !ovMap) return;
  const geoPoints = [];
  events.forEach(e => {
    const lat = Number(e?.network?.geo?.lat);
    const lon = Number(e?.network?.geo?.lon);
    if (Number.isFinite(lat) && Number.isFinite(lon)) geoPoints.push([lat, lon, 1]);
  });
  if (geoPoints.length > 0) {
    try {
      if (typeof ovHeatLayer !== 'undefined' && ovHeatLayer) {
        ovHeatLayer.setLatLngs(geoPoints);
      } else {
        ovHeatLayer = L.heatLayer(geoPoints, { radius: 25, blur: 15, gradient: { 0.4: '#00e5ff', 0.7: '#ffab00', 1.0: '#ff1744' } }).addTo(ovMap);
      }
    } catch (_) { /* leaflet-heat canvas size error — non-fatal */ }
  }
}

function fetchLanTopology() {
  return fetchPremiumLanTopology();
}

function ensureLanAnimLoop() {
  // Already handled by startLanSimulation in overview.js
}

function ensureGeoipAvailability() {
  if (typeof ovMap !== 'undefined' && ovMap) ovMap.invalidateSize();
}
/**
 * ELITE DASHBOARD LOGIC
 */
function initEliteOverview() {
  const mapEl = document.getElementById('ovEliteMap');
  const globeEl = document.getElementById('ovEliteGlobe');
  if (!mapEl) return;

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const tileUrl = isLight
    ? 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png'
    : 'https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png';

  if (eliteMap) {
    if (eliteMap._lastTheme !== (isLight ? 'light' : 'dark')) {
      eliteMap.eachLayer(l => { if (l instanceof L.TileLayer) eliteMap.removeLayer(l); });
      L.tileLayer(tileUrl, { subdomains: 'abcd', maxZoom: 19, crossOrigin: 'anonymous' }).addTo(eliteMap);
      eliteMap._lastTheme = isLight ? 'light' : 'dark';
    }
    ensureEliteBaselineMapVisuals();
    return;
  }

  eliteMap = L.map('ovEliteMap', {
    zoomControl: false,
    attributionControl: false,
    worldCopyJump: true,
    minZoom: 2,
    crs: L.CRS.EPSG3857,
    preferCanvas: true,
    zoomAnimation: false,
    fadeAnimation: false,
    markerZoomAnimation: false
  }).setView([20, 0], 2);
  eliteMap._lastTheme = isLight ? 'light' : 'dark';

  L.tileLayer(tileUrl, { subdomains: 'abcd', maxZoom: 19, crossOrigin: 'anonymous' }).addTo(eliteMap);
  ensureEliteBaselineMapVisuals();

  const markMapInteraction = () => { eliteLastUserInteractMs = Date.now(); };
  eliteMap.on('dragstart', markMapInteraction);
  eliteMap.on('movestart', markMapInteraction);
  eliteMap.on('zoomstart', markMapInteraction);
  eliteMap.on('click', markMapInteraction);

  if (!elitePanTimer) {
    // Map only moves on user interaction — no auto-panning
    elitePanTimer = true;
  }

  // Toggle
  const btnMapMode = document.getElementById('elite-btn-mapmode');
  const btnExecutive = document.getElementById('elite-btn-executive');
  const btnCommand = document.getElementById('elite-btn-command');
  const lanEl = document.getElementById('lanTopology');
  const paneOverview = document.getElementById('paneOverview');

  if (typeof state.elite3dMode !== 'boolean') state.elite3dMode = false;
  if (typeof state.eliteExecutiveMode !== 'boolean') state.eliteExecutiveMode = false;
  if (typeof state.eliteCommandMode !== 'boolean') state.eliteCommandMode = false;

  function sync3dModeButton() {
    paneOverview?.classList.toggle('map-3d', Boolean(state.elite3dMode));
    if (state.elite3dMode) {
      ensureEliteGlobeRuntime();
    }
  }

  function syncExecutiveButton() {
    if (!btnExecutive) return;
    btnExecutive.textContent = state.eliteExecutiveMode ? 'Analyst View' : 'Executive View';
    btnExecutive.classList.toggle('active', state.eliteExecutiveMode);
    paneOverview?.classList.toggle('executive-mode', Boolean(state.eliteExecutiveMode));
  }

  function syncCommandButton() {
    if (btnCommand) {
      btnCommand.textContent = state.eliteCommandMode ? 'Exit Command' : 'Command Center';
      btnCommand.classList.toggle('active', Boolean(state.eliteCommandMode));
    }
    document.body.classList.toggle('soc-command-mode', Boolean(state.eliteCommandMode));
  }

  async function setCommandMode(enabled) {
    state.eliteCommandMode = Boolean(enabled);
    if (state.eliteCommandMode) {
      state.mapMode = 'geoip';
      state.elite3dMode = true;
      sync3dModeButton();
    }
    syncCommandButton();
    setEliteMapMode(state.mapMode || 'geoip');

    const fsEnabled = Boolean(document.fullscreenEnabled);
    if (!fsEnabled) return;
    try {
      if (state.eliteCommandMode) {
        if (!document.fullscreenElement) {
          await document.documentElement.requestFullscreen();
        }
      } else if (document.fullscreenElement) {
        await document.exitFullscreen();
      }
    } catch (_) { }
  }

  function syncEliteMapModeButton() {
    if (!btnMapMode) return;
    if (state.elite3dMode && state.mapMode === 'geoip') {
      btnMapMode.textContent = '3D Globe';
      btnMapMode.classList.remove('mode-geo', 'mode-lan');
      btnMapMode.classList.add('mode-3d');
    } else if (state.mapMode === 'geoip') {
      btnMapMode.textContent = 'GEO View';
      btnMapMode.classList.remove('mode-3d', 'mode-lan');
      btnMapMode.classList.add('mode-geo');
    } else {
      btnMapMode.textContent = 'LAN Topology';
      btnMapMode.classList.remove('mode-geo', 'mode-3d');
      btnMapMode.classList.add('mode-lan');
    }
    btnMapMode.classList.add('active');
  }

  function setEliteMapMode(mode) {
    state.mapMode = mode;
    const isGeo = mode === 'geoip';
    const showGlobe = isGeo && Boolean(state.elite3dMode);
    const showLeaflet = isGeo && !showGlobe;

    mapEl.style.display = showLeaflet ? 'block' : 'none';
    if (globeEl) globeEl.style.display = showGlobe ? 'block' : 'none';
    if (lanEl) {
      if (isGeo) {
        lanEl.style.display = 'none';
      } else {
        lanEl.style.display = 'flex';
        lanEl.style.position = 'absolute';
        lanEl.style.inset = '0';
        lanEl.style.zIndex = '5';
        lanEl.style.background = 'var(--bg-base)';
        fetchLanTopology();
        ensureLanAnimLoop();
      }
    }

    if (showLeaflet && eliteMap) eliteMap.invalidateSize();
    if (showGlobe) {
      ensureEliteGlobeRuntime().then(() => {
        if (!eliteGlobe || !globeEl) {
          state.elite3dMode = false;
          sync3dModeButton();
          mapEl.style.display = 'block';
          if (globeEl) globeEl.style.display = 'none';
          if (eliteMap) eliteMap.invalidateSize();
          return;
        }
        requestAnimationFrame(() => {
          const w = Math.max(320, globeEl.clientWidth || 320);
          const h = Math.max(220, globeEl.clientHeight || 220);
          eliteGlobe.width(w).height(h);
        });
      });
    }
    syncEliteMapModeButton();
  }

  syncEliteMapModeButton();
  sync3dModeButton();
  syncExecutiveButton();
  syncCommandButton();

  // Elite buttons - delegated event listeners
  document.addEventListener('click', async (e) => {
    // Map mode button
    if (e.target?.id === 'elite-btn-mapmode' || e.target?.closest('#elite-btn-mapmode')) {
      // Cycle: GEO → 3D Globe → LAN → GEO
      if (state.mapMode === 'geoip' && !state.elite3dMode) {
        state.elite3dMode = true;
        sync3dModeButton();
        setEliteMapMode('geoip');
      } else if (state.mapMode === 'geoip' && state.elite3dMode) {
        state.elite3dMode = false;
        sync3dModeButton();
        setEliteMapMode('lan');
      } else {
        state.elite3dMode = false;
        sync3dModeButton();
        setEliteMapMode('geoip');
      }
    }
    // Executive button
    if (e.target?.id === 'elite-btn-executive' || e.target?.closest('#elite-btn-executive')) {
      state.eliteExecutiveMode = !state.eliteExecutiveMode;
      syncExecutiveButton();
    }
    // Command button
    if (e.target?.id === 'elite-btn-command' || e.target?.closest('#elite-btn-command')) {
      await setCommandMode(!state.eliteCommandMode);
    }
  });

  if (!eliteCommandViewListenerBound) {
    eliteCommandViewListenerBound = true;
    document.addEventListener('percepta:view-change', async (ev) => {
      const nextView = String(ev?.detail?.view || state.view || '').toLowerCase();
      if (nextView !== 'overview' && state.eliteCommandMode) {
        await setCommandMode(false);
      }
    });
  }

  // Map cursor glow — tracks mouse in dark theme
  const mapCont = mapEl?.closest('.map-container') || document.querySelector('#paneOverview .map-container');
  if (mapCont && !mapCont._eliteGlowBound) {
    mapCont._eliteGlowBound = true;
    mapCont.addEventListener('mousemove', (e) => {
      if (document.documentElement.getAttribute('data-theme') === 'light') return;
      const r = mapCont.getBoundingClientRect();
      const x = ((e.clientX - r.left) / r.width * 100).toFixed(1) + '%';
      const y = ((e.clientY - r.top) / r.height * 100).toFixed(1) + '%';
      mapCont.style.setProperty('--mgx', x);
      mapCont.style.setProperty('--mgy', y);
      mapCont.style.setProperty('--mglow', '1');
    });
    mapCont.addEventListener('mouseleave', () => {
      mapCont.style.setProperty('--mglow', '0');
    });
  }
}

function paintEliteDash(d) {
  initEliteOverview();

  const derivePipelineHealth = () => {
    const wsOk = Boolean(state.wsOk);
    const hs = state.lastHealthStatus || 'pending';
    const bufferUsage = Number(state.stats?.clickhouse_buffer_usage ?? 0);
    const connectedAgents = Number(d?.agentsLive || 0);
    const knownAgents = Array.isArray(state.knownAgents) ? state.knownAgents.length : 0;

    let score = 100;
    if (!wsOk) score -= 25;
    if (hs === 'offline') score -= 25;
    else if (hs === 'degraded') score -= 10;
    if (Number.isFinite(bufferUsage) && bufferUsage >= 90) score -= 20;
    else if (Number.isFinite(bufferUsage) && bufferUsage >= 75) score -= 10;
    if (knownAgents > 0 && connectedAgents === 0) score -= 10;

    score = Math.max(0, Math.min(100, score));
    const status = score >= 85 ? 'Nominal' : (score >= 65 ? 'Warning' : 'Degraded');
    const cls = score >= 90 ? 'c-ok' : (score >= 70 ? 'c-warn' : 'c-danger');
    const pipelineCls = score >= 90 ? 'ok' : (score >= 70 ? 'warn' : 'danger');
    return { score, status, cls, pipelineCls };
  };

  const health = derivePipelineHealth();

  // Hero KPIs
  setEliteMetricText('elite-ingest-val', d.mps >= 10 ? d.mps.toFixed(1) : d.mps.toFixed(2));
  setEliteMetricText('elite-critical-val', d.hi60.toLocaleString());
  setEliteMetricText('elite-agents-val', d.agentsLive.toLocaleString());

  setEliteMetricText('elite-health-val', `${health.score}%`);
  const healthEl = document.getElementById('elite-health-val');
  if (healthEl) {
    healthEl.className = 'hero-val ' + health.cls;
  }

  const stanceValueEl = document.getElementById('eliteExecutiveStanceValue');
  if (stanceValueEl) {
    let stance = 'SECURE';
    if (d.hi60 >= 120 || health.score < 55) stance = 'CRITICAL';
    else if (d.hi60 >= 45 || health.score < 70) stance = 'ELEVATED';
    else if (d.hi60 >= 12 || health.score < 85) stance = 'GUARDED';
    stanceValueEl.textContent = stance;
    stanceValueEl.style.color = stance === 'CRITICAL'
      ? (getCssVar('--danger') || '#ff1744')
      : stance === 'ELEVATED'
        ? (getCssVar('--warn') || '#ffab00')
        : (getCssVar('--ok') || '#00fa9a');
  }

  if (d.hi60 > eliteLastCriticalCount && d.hi60 > 0) {
    triggerEliteCriticalCinematic();
  }
  eliteLastCriticalCount = d.hi60;

  // Pipeline Info
  const statusEl = document.getElementById('elite-pipeline-status');
  if (statusEl) {
    statusEl.textContent = health.status;
    statusEl.className = 'w-sub ' + health.pipelineCls;
  }
  setTextIfChanged('elite-ws-status', state.wsOk ? 'Connected' : 'Connecting…');
  setTextIfChanged('elite-parser-lag',
    state.lastHealthStatus === 'ok' ? '< 1ms' :
    state.lastHealthStatus === 'pending' ? 'Init…' :
    state.lastHealthStatus === 'offline' ? 'Offline' : 'Degraded');
  const rawBufferUsage = Number(state.stats?.clickhouse_buffer_usage);
  const pipelineWarned = Number(state.stats?.pipeline_quality_warned ?? 0);
  const pipelineTotal = Number(state.stats?.pipeline_quality_total ?? 0);
  const fallbackBufferUsage = pipelineTotal > 0
    ? Math.max(0, Math.min(100, Math.round((pipelineWarned / pipelineTotal) * 100)))
    : null;
  const effectiveBufferUsage = Number.isFinite(rawBufferUsage)
    ? rawBufferUsage
    : (Number.isFinite(fallbackBufferUsage) ? fallbackBufferUsage : null);
  setTextIfChanged('elite-ch-buffer', effectiveBufferUsage == null ? '--%' : `${effectiveBufferUsage}%`);

  // Charts
  const donutCanvas = document.getElementById('elite-classDonut');
  if (donutCanvas) drawDonut(donutCanvas, d.classDonutItems);

  // Classification legend
  const eliteLegend = document.getElementById('elite-classLegend');
  if (eliteLegend) {
    const items = Array.isArray(d.classDonutItems) ? d.classDonutItems : [];
    const total = items.reduce((s, x) => s + Number(x.value || 0), 0) || 1;
    const sig = items.map(x => `${x.key}:${x.value}`).join(',');
    if (eliteLegend.dataset.sig !== sig) {
      eliteLegend.dataset.sig = sig;
      eliteLegend.innerHTML = items.map(it => {
        const pct = Math.round((Number(it.value || 0) / total) * 100);
        return `<span class="elite-legend-item"><span class="elite-legend-dot" style="background:${escapeHtml(it.color)}"></span>${escapeHtml(it.key)} <span class="elite-legend-pct">${pct}%</span></span>`;
      }).join('') || '<span class="elite-legend-item" style="color:var(--muted)">No data</span>';
    }
  }

  const trendCanvas = document.getElementById('elite-trendChart');
  if (trendCanvas) {
    const series = [
      { points: d.evSeries, color: getCssVar('--accent') || '#00d4ff' },
      { points: d.alSeries, color: '#ff4081' },
      { points: d.hpSeries, color: getCssVar('--danger') || '#ff1744' }
    ];
    drawMultiLine(trendCanvas, series);
  }

  // Top Sources & Hosts
  renderEliteBars('elite-sources-bars', d.originIps, getCssVar('--danger') || '#ff1744');
  renderEliteBars('elite-hosts-bars', d.impactedIps, getCssVar('--accent') || '#00e5ff');

  // Map Update
  if (state.mapMode === 'geoip' && eliteMap) {
    const now = Date.now();
    if (now - eliteLastMapUpdateMs < 1200) return;
    eliteLastMapUpdateMs = now;

    // ── Context-aware private IP visibility ──
    // On public internet (non-private hostname), hide RFC-1918 IPs from the map.
    // On private networks (localhost, .local, RFC-1918), show private IPs.
    const _hostname = window.location.hostname || '';
    const _isPrivateNetwork = (() => {
      if (!_hostname || _hostname === 'localhost' || _hostname === '127.0.0.1' || _hostname === '::1') return true;
      if (_hostname.endsWith('.local') || _hostname.endsWith('.lan') || _hostname.endsWith('.internal')) return true;
      const hm = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(_hostname);
      if (!hm) return false;
      const a = Number(hm[1]), b = Number(hm[2]);
      return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
    })();
    const _isRfc1918 = (ip) => {
      const v = String(ip || '').trim();
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
      if (!m) return v === '::1' || /^fe80:/i.test(v) || /^fc|^fd/i.test(v);
      const a = Number(m[1]), b = Number(m[2]);
      return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) || (a === 169 && b === 254);
    };
    const shouldShowIp = (ip) => _isPrivateNetwork || !_isRfc1918(ip);

    const bump = (map, key, n = 1) => {
      const k = String(key || '').trim();
      if (!k || !shouldShowIp(k)) return;
      map.set(k, (map.get(k) || 0) + Number(n || 1));
    };

    // ── 10-minute map filter ──
    // Only show IPs from events/alerts within the last 10 minutes on the map.
    const tenMinAgoSec = Math.floor(now / 1000) - 600;
    const mergedOrigins = new Map();
    const mergedImpacted = new Map();

    // Re-scan recent events (last 10 min only) for origin/impacted IPs
    const recentEvents = (Array.isArray(state.events) ? state.events : []).filter(e => {
      const t = eventIngestTimeSeconds(e);
      return typeof t === 'number' && t >= tenMinAgoSec;
    });
    for (const e of recentEvents) {
      const md = (e && typeof e.metadata === 'object' && e.metadata) ? e.metadata : {};
      const srcCandidates = [e?.network?.src_ip, md.src_ip, md.attacker_ip, md.source_ip].filter(Boolean);
      for (const ip of srcCandidates) { bump(mergedOrigins, ip, 1); break; }
      const hostIpVal = e?.host?.ip;
      const hostIps = Array.isArray(hostIpVal) ? hostIpVal : (hostIpVal ? [hostIpVal] : []);
      for (const ip of hostIps) bump(mergedImpacted, ip, 1);
      if (!hostIps.length) {
        const fallback = e?.agent?.ip || e?.agent?.hostname || e?.host?.name || '';
        if (fallback) bump(mergedImpacted, fallback, 1);
      }
    }

    const ipKeys = ['src_ip', 'source_ip', 'attacker_ip', 'ip', 'norm.host_ip'];
    const recentAlerts = (Array.isArray(d.alerts) ? d.alerts.slice(0, 500) : []).filter(a => {
      const tRaw = a?.first_seen || a?.last_seen;
      const sec = typeof tRaw === 'number' ? tRaw : (typeof tRaw === 'string' ? Math.floor(Date.parse(tRaw) / 1000) : 0);
      return sec >= tenMinAgoSec;
    });
    for (const a of recentAlerts) {
      const md = (a && typeof a.metadata === 'object' && a.metadata) ? a.metadata : {};
      const w = Number(a?.count || 1);
      for (const key of ipKeys) {
        if (md[key]) bump(mergedOrigins, md[key], (Number.isFinite(w) && w > 0) ? w : 1);
      }
      if (a?.agent_hostname && /^\d+\.\d+\.\d+\.\d+$/.test(String(a.agent_hostname))) {
        bump(mergedOrigins, a.agent_hostname, 1);
      }
      if (a?.agent_ip && /^\d+\.\d+\.\d+\.\d+$/.test(String(a.agent_ip))) {
        bump(mergedImpacted, a.agent_ip, 1);
      }
    }

    const topO = [...mergedOrigins.entries()].sort((a, b) => b[1] - a[1]).slice(0, 80);
    const topImpacted = [...mergedImpacted.entries()].sort((a, b) => b[1] - a[1]).slice(0, 80);
    const ips = [...new Set([...topO.map((x) => x[0]), ...topImpacted.map((x) => x[0])])];
    kickGeoipBatch(ips);

    const pts = [];
    const originPts = [];
    const impactedPts = [];
    for (const [ip, count] of topO) {
      const p = state.geoip.cache.get(ip);
      if (p) {
        const intensity = Math.min(1, 0.25 + (Number(count || 1) / 10));
        pts.push([p.lat, p.lon, intensity]);
        // Include ip for label rendering on blinkers
        originPts.push({ lat: p.lat, lon: p.lon, weight: Number(count || 1), ip });
      }
    }

    for (const [ip, count] of topImpacted) {
      const p = state.geoip.cache.get(ip);
      if (p) impactedPts.push({ lat: p.lat, lon: p.lon, weight: Number(count || 1), ip });
    }

    if (state.elite3dMode) {
      try { if (eliteHeatLayer) eliteHeatLayer.setLatLngs([]); } catch (_) {}
      clearElitePulseMarkers(eliteLivePulseMarkers);
      clearEliteLiveArcs();
      updateEliteGlobeVisuals(originPts, impactedPts, originPts.slice(0, 18));
      return;
    }

    try {
      if (eliteHeatLayer) {
        eliteHeatLayer.setLatLngs(pts);
      } else {
        eliteHeatLayer = L.heatLayer(pts, {
          radius: 20,
          blur: 15,
          gradient: { 0.4: '#00e5ff', 0.7: '#ffab00', 1.0: '#ff1744' },
        }).addTo(eliteMap);
      }
    } catch (_) { /* leaflet-heat canvas size error — non-fatal */ }

    // Pass attacker & victim point sets with IPs for separate blinkers + arcs
    updateEliteLiveBlinkers(originPts, impactedPts);
  }
}

(function bootEliteOverviewOnceReady() {
  const ensureBoot = () => {
    const pane = document.getElementById('paneOverview');
    if (!pane || !pane.classList.contains('ov-elite')) return;
    if (!state.mapMode) state.mapMode = 'geoip';
    if (!eliteMap) {
      try { initEliteOverview(); } catch (_) { }
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(ensureBoot, 0), { once: true });
  } else {
    setTimeout(ensureBoot, 0);
  }

  let retries = 0;
  const retryTimer = setInterval(() => {
    if (eliteMap || retries >= 5) {
      clearInterval(retryTimer);
      return;
    }
    if (state.view === 'overview') ensureBoot();
    retries += 1;
  }, 1000);
})();

document.addEventListener('themeChanged', () => {
  try {
    if (state.view !== 'overview') return;
    state.lastOverviewPaint = 0;
    if (eliteMap) {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const tileUrl = isLight
        ? 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png';
      if (eliteMap._lastTheme !== (isLight ? 'light' : 'dark')) {
        eliteMap.eachLayer((layer) => { if (layer instanceof L.TileLayer) eliteMap.removeLayer(layer); });
        L.tileLayer(tileUrl, { subdomains: 'abcd', maxZoom: 19, crossOrigin: 'anonymous' }).addTo(eliteMap);
        eliteMap._lastTheme = isLight ? 'light' : 'dark';
      }
      eliteMap.invalidateSize();
    }
    paintOverviewDashThrottled();
  } catch { }
});

function renderEliteBars(containerId, dataMap, color) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const safeMap = (dataMap instanceof Map) ? dataMap : new Map();
  let top = [...safeMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);

  if (top.length === 0) {
    const fallback = new Map();
    const bump = (k) => {
      const key = String(k || '').trim();
      if (!key) return;
      fallback.set(key, (fallback.get(key) || 0) + 1);
    };
    const events = Array.isArray(state.events) ? state.events : [];
    const isSources = String(containerId || '').includes('sources');
    const isHosts = String(containerId || '').includes('hosts');
    for (const e of events.slice(0, 1000)) {
      if (isSources) {
        bump(e?.network?.src_ip || e?.network?.dst_ip || e?.agent?.hostname || e?.agent?.id || e?.event?.provider);
      } else if (isHosts) {
        const hostIpVal = e?.host?.ip;
        const hostIps = Array.isArray(hostIpVal) ? hostIpVal : (hostIpVal ? [hostIpVal] : []);
        bump(hostIps[0] || e?.host?.name || e?.agent?.hostname || e?.agent?.id || e?.agent_id);
      }
    }
    top = [...fallback.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }

  const max = Math.max(1, ...top.map(x => x[1]));

  const html = top.map(it => {
    const pct = Math.round((it[1] / max) * 100);
    const pivot = String(it[0] || '').trim();
    return `
        <div class="m-bar-wrap" data-pivot-q="${escapeHtml(pivot)}" role="button" tabindex="0" title="Pivot to Investigation: ${escapeHtml(pivot)}">
                <div class="m-bar-info">
                    <span class="m-bar-lbl">${escapeHtml(it[0])}</span>
                    <span class="m-bar-val">${it[1].toLocaleString()}</span>
                </div>
                <div class="m-bar-track">
                    <div class="m-bar-fill" style="width:${pct}%; background:${color}; box-shadow: 0 0 10px ${color}"></div>
                </div>
            </div>
        `;
  }).join('');

  if (container.dataset.sig !== html) {
    container.dataset.sig = html;
    container.innerHTML = html || '<div class="muted" style="font-size:12px; padding:10px">No activity tracked</div>';

    const pivotToEvents = (q) => {
      const query = String(q || '').trim();
      if (!query) return;
      if (typeof pivotSearch === 'function') {
        try {
          pivotSearch(query, 'events');
          return;
        } catch (_) { }
      }
      const searchBox = document.getElementById('globalSearch');
      if (searchBox) {
        searchBox.value = query;
        searchBox.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (typeof setView === 'function') {
        try { setView('events'); } catch (_) { }
      }
    };

    container.querySelectorAll('[data-pivot-q]').forEach((el) => {
      const query = String(el.getAttribute('data-pivot-q') || '').trim();
      el.addEventListener('click', () => pivotToEvents(query));
      el.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          pivotToEvents(query);
        }
      });
    });
  }
}
