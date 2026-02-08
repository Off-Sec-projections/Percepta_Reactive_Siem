    let _cachedCssVars = {};
    
    function getCssVar(name) {
      if (!_cachedCssVars[name]) {
        _cachedCssVars[name] = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      }
      return _cachedCssVars[name];
    }

    function requestThemeCanvasRepaint() {
      _cachedCssVars = {}; // Clear cache on theme change
      try {
        state.lastOverviewPaint = 0;
      } catch {}

      try {
        if (typeof paintOverviewDashThrottled === 'function') paintOverviewDashThrottled();
      } catch {}
      try {
        if (typeof paintWs === 'function') paintWs();
      } catch {}
      try {
        if (typeof paintHealth === 'function') paintHealth();
      } catch {}
      try {
        if (typeof scheduleRender === 'function') scheduleRender();
      } catch {}
    }

    document.addEventListener('themeChanged', requestThemeCanvasRepaint);

    // Also watch direct data-theme attribute changes as a safety net.
    try {
      const themeRoot = document.documentElement;
      let lastTheme = String(themeRoot.getAttribute('data-theme') || 'dark');
      const obs = new MutationObserver(() => {
        const nextTheme = String(themeRoot.getAttribute('data-theme') || 'dark');
        if (nextTheme === lastTheme) return;
        lastTheme = nextTheme;
        requestThemeCanvasRepaint();
      });
      obs.observe(themeRoot, { attributes: true, attributeFilter: ['data-theme'] });
    } catch {}

    function drawLine(canvas, points, color) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 600;
      const cssH = canvas.clientHeight || 300;
      const dpr = Math.max(2, window.devicePixelRatio || 1);
      
      // Validate dimensions - skip rendering if too small
      if (cssW < 50 || cssH < 30) return;
      
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      try {
        ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);
      } catch (e) { return; }

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const stroke = getCssVar('--stroke2') || 'rgba(255,255,255,0.2)';
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, h - 0.5);
      ctx.lineTo(w, h - 0.5);
      ctx.stroke();

      if (!Array.isArray(points) || points.length < 2) return;
      const max = Math.max(1, ...points);

      // Glow effect
      ctx.save();
      ctx.shadowColor = color;
      ctx.shadowBlur = 8;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let i = 0; i < points.length; i++) {
        const x = (i / (points.length - 1)) * (w - 2) + 1;
        const y = h - 2 - (points[i] / max) * (h - 6);
        if (i === 0) {
          ctx.moveTo(x, y);
        } else {
          const px = ((i - 1) / (points.length - 1)) * (w - 2) + 1;
          const py = h - 2 - (points[i - 1] / max) * (h - 6);
          const cpx = (px + x) / 2;
          ctx.bezierCurveTo(cpx, py, cpx, y, x, y);
        }
      }
      ctx.stroke();
      ctx.restore();
    }

    function drawSeverityBars(canvas, counts) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 600;
      const cssH = canvas.clientHeight || 300;
      const dpr = window.devicePixelRatio || 1;
      
      // Validate dimensions - skip rendering if too small
      if (cssW < 50 || cssH < 30) return;
      
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      try {
        ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);
      } catch (e) { return; }

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const keys = ['critical', 'high', 'medium', 'low', 'info'];
      const cols = {
        critical: getCssVar('--danger') || '#ff4757',
        high: getCssVar('--warn') || '#ffa502',
        medium: getCssVar('--warn') || '#ffa502',
        low: getCssVar('--ok') || '#26de81',
        info: getCssVar('--accent') || '#00d4ff',
      };

      const vals = keys.map((k) => Number(counts?.[k] || 0));
      const max = Math.max(1, ...vals);
      const gap = 8;
      const barW = Math.max(10, Math.floor((w - gap * (keys.length - 1)) / keys.length));
      for (let i = 0; i < keys.length; i++) {
        const v = vals[i];
        const bh = Math.max(2, (v / max) * (h - 12));
        const x = i * (barW + gap);
        const y = h - bh;
        ctx.fillStyle = cols[keys[i]];
        ctx.globalAlpha = 0.35;
        ctx.fillRect(x, y, barW, bh);
        ctx.globalAlpha = 1;
      }
    }

    function drawMultiLine(canvas, seriesList) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 600;
      const cssH = canvas.clientHeight || 300;
      const dpr = Math.max(2, window.devicePixelRatio || 1);
      
      // Validate dimensions
      if (cssW < 50 || cssH < 30) return;
      
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      try {
        ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);
      } catch (e) {
        // Canvas still too large – bail out gracefully
        return;
      }

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const stroke = getCssVar('--stroke2') || 'rgba(255,255,255,0.2)';
      ctx.strokeStyle = stroke;
      ctx.globalAlpha = 0.35;
      for (let i = 1; i <= 4; i++) {
        const y = Math.round((h / 5) * i) + 0.5;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;

      const allVals = [];
      for (const s of seriesList) for (const v of (s?.points || [])) allVals.push(Number(v || 0));
      const max = Math.max(1, ...allVals);

      for (let si = 0; si < seriesList.length; si++) {
        const s = seriesList[si];
        const pts = Array.isArray(s?.points) ? s.points : [];
        if (!pts.length) continue;

        // Build point coordinates
        const coords = [];
        for (let i = 0; i < pts.length; i++) {
          coords.push({
            x: (i / Math.max(1, pts.length - 1)) * (w - 8) + 4,
            y: h - (Number(pts[i] || 0) / max) * (h - 12) - 6,
          });
        }

        // Draw the line stroke with glow
        ctx.save();
        ctx.shadowColor = s.color;
        ctx.shadowBlur = 8;
        ctx.strokeStyle = s.color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        for (let i = 0; i < coords.length; i++) {
          if (i === 0) {
            ctx.moveTo(coords[i].x, coords[i].y);
          } else {
            const cpx = (coords[i - 1].x + coords[i].x) / 2;
            ctx.bezierCurveTo(cpx, coords[i - 1].y, cpx, coords[i].y, coords[i].x, coords[i].y);
          }
        }
        ctx.stroke();
        ctx.restore();

        // Gradient fill under first series (Events)
        if (si === 0 && coords.length > 1) {
          ctx.save();
          ctx.beginPath();
          ctx.moveTo(coords[0].x, coords[0].y);
          for (let i = 1; i < coords.length; i++) {
            const cpx = (coords[i - 1].x + coords[i].x) / 2;
            ctx.bezierCurveTo(cpx, coords[i - 1].y, cpx, coords[i].y, coords[i].x, coords[i].y);
          }
          ctx.lineTo(coords[coords.length - 1].x, h);
          ctx.lineTo(coords[0].x, h);
          ctx.closePath();
          const grad = ctx.createLinearGradient(0, 0, 0, h);
          grad.addColorStop(0, s.color.replace(')', ',0.35)').replace('rgb(', 'rgba(').replace('#', '#') || 'rgba(0,212,255,0.35)');
          grad.addColorStop(1, 'rgba(0,212,255,0)');
          // Use a simpler approach for hex colors
          try {
            const gf = ctx.createLinearGradient(0, 0, 0, h);
            gf.addColorStop(0, 'rgba(0,212,255,0.32)');
            gf.addColorStop(0.7, 'rgba(0,212,255,0.06)');
            gf.addColorStop(1, 'rgba(0,212,255,0)');
            ctx.fillStyle = gf;
          } catch (_) {
            ctx.fillStyle = 'rgba(0,212,255,0.15)';
          }
          ctx.fill();
          ctx.restore();
        }

        // Dot markers on non-first series (Alerts, High/Crit)
        if (si > 0) {
          ctx.save();
          for (const c of coords) {
            if (Number(pts[coords.indexOf(c)] || 0) > 0) {
              ctx.beginPath();
              ctx.arc(c.x, c.y, 3, 0, Math.PI * 2);
              ctx.fillStyle = s.color;
              ctx.fill();
            }
          }
          ctx.restore();
        }
      }
    }

    function drawHalfGauge(canvas, value, min, max, color) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 200;
      const cssH = canvas.clientHeight || 150;
      const dpr = window.devicePixelRatio || 1;
      
      // Validate dimensions
      if (cssW < 50 || cssH < 30) return;
      
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const bg = getCssVar('--stroke2') || 'rgba(255,255,255,0.2)';
      const cx = w / 2;
      const cy = h - 6;
      const r = Math.min(w * 0.45, h * 0.95);

      const start = Math.PI;
      const end = 2 * Math.PI;
      const t = Math.max(0, Math.min(1, (value - min) / Math.max(1e-9, (max - min))));
      const mid = start + t * (end - start);

      ctx.lineWidth = 12;
      ctx.lineCap = 'round';

      ctx.strokeStyle = bg;
      ctx.globalAlpha = 0.35;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, end);
      ctx.stroke();
      ctx.globalAlpha = 1;

      ctx.strokeStyle = color;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, mid);
      ctx.stroke();

      // Ticks
      ctx.strokeStyle = bg;
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.45;
      for (let i = 0; i <= 6; i++) {
        const a = start + (i / 6) * (end - start);
        const x1 = cx + Math.cos(a) * (r - 16);
        const y1 = cy + Math.sin(a) * (r - 16);
        const x2 = cx + Math.cos(a) * (r - 4);
        const y2 = cy + Math.sin(a) * (r - 4);
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    function drawDonut(canvas, items) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 200;
      const cssH = canvas.clientHeight || 200;
      const dpr = window.devicePixelRatio || 1;
      
      // Validate dimensions — skip if canvas is not visible or too small
      if (cssW < 50 || cssH < 30) return;

      // Clamp to prevent "Canvas exceeds max size" errors
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      
      canvas.width = pw;
      canvas.height = ph;
      ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const total = items.reduce((a, b) => a + Number(b.value || 0), 0) || 1;
      const cx = w / 2;
      const cy = h / 2;
      const r = Math.min(w, h) * 0.45;
      const inner = r * 0.62;
      let a0 = -Math.PI / 2;

      for (const it of items) {
        const v = Number(it.value || 0);
        if (v <= 0) continue;
        const a1 = a0 + (v / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, a0, a1);
        ctx.closePath();
        ctx.fillStyle = it.color;
        ctx.globalAlpha = 0.85;
        ctx.fill();
        ctx.globalAlpha = 1;
        a0 = a1;
      }

      // Cutout
      ctx.beginPath();
      ctx.arc(cx, cy, inner, 0, Math.PI * 2);
      ctx.fillStyle = getCssVar('--bg2') || '#111';
      ctx.globalAlpha = 1;
      ctx.fill();
    }

    function renderBarBoard(container, rows, color) {
      if (!container) return;
      container.innerHTML = '';
      const max = Math.max(1, ...rows.map((r) => Number(r.value || 0)));
      for (const r of rows) {
        const wrap = document.createElement('div');
        wrap.className = 'barRow2';
        const left = document.createElement('div');
        const label = document.createElement('div');
        label.className = 'barLabel';
        label.textContent = r.label;
        const bar = document.createElement('div');
        bar.className = 'bar';
        const fill = document.createElement('div');
        fill.className = 'barFill';
        fill.style.background = color;
        fill.style.width = `${Math.round((Number(r.value || 0) / max) * 100)}%`;
        bar.appendChild(fill);
        left.appendChild(label);
        left.appendChild(bar);
        const val = document.createElement('div');
        val.className = 'barVal';
        val.textContent = Number(r.value || 0).toLocaleString();
        wrap.appendChild(left);
        wrap.appendChild(val);
        container.appendChild(wrap);
      }
      if (!rows.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.style.fontSize = '12px';
        empty.textContent = '(none)';
        container.appendChild(empty);
      }
    }

    function toMapXY(lat, lon, w, h) {
      // Equirectangular projection.
      const x = ((lon + 180) / 360) * w;
      const y = ((90 - lat) / 180) * h;
      return [x, y];
    }

    // Lightweight built-in world backdrop so GeoIP points are readable without extra assets.
    // Coordinates are normalized [0..1] and intentionally approximate for fast rendering.
    const WORLD_LANDMASSES = [
      // North America
      [[0.06,0.26],[0.10,0.20],[0.15,0.18],[0.21,0.21],[0.25,0.27],[0.25,0.34],[0.21,0.40],[0.17,0.45],[0.12,0.45],[0.08,0.39]],
      // South America
      [[0.24,0.45],[0.28,0.50],[0.30,0.56],[0.29,0.65],[0.27,0.74],[0.24,0.81],[0.20,0.76],[0.19,0.67],[0.20,0.58],[0.22,0.51]],
      // Greenland
      [[0.28,0.11],[0.31,0.08],[0.35,0.09],[0.36,0.13],[0.34,0.17],[0.30,0.16]],
      // Europe + Asia
      [[0.39,0.21],[0.44,0.18],[0.53,0.20],[0.61,0.24],[0.70,0.26],[0.80,0.29],[0.88,0.35],[0.90,0.41],[0.86,0.46],[0.79,0.47],[0.72,0.44],[0.67,0.46],[0.58,0.48],[0.50,0.45],[0.44,0.39],[0.40,0.32]],
      // Africa
      [[0.48,0.42],[0.53,0.43],[0.57,0.49],[0.58,0.57],[0.56,0.67],[0.52,0.73],[0.47,0.67],[0.45,0.58],[0.46,0.50]],
      // Australia
      [[0.79,0.67],[0.84,0.66],[0.88,0.69],[0.87,0.75],[0.82,0.77],[0.78,0.73]],
      // Japan-ish
      [[0.83,0.38],[0.84,0.36],[0.85,0.38],[0.84,0.41]],
    ];

    function drawWorldBackdrop(ctx, w, h) {
      const stroke = getCssVar('--stroke2') || 'rgba(255,255,255,0.2)';
      const panelBg = getCssVar('--panel2') || '#111';

      // Ocean wash.
      ctx.fillStyle = panelBg;
      ctx.globalAlpha = 0.25;
      ctx.fillRect(0, 0, w, h);

      // Subtle lat/lon graticule.
      ctx.strokeStyle = stroke;
      ctx.globalAlpha = 0.16;
      for (let i = 1; i <= 7; i++) {
        const x = Math.round((w / 8) * i) + 0.5;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let i = 1; i <= 3; i++) {
        const y = Math.round((h / 4) * i) + 0.5;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      // Land masses.
      const land = getCssVar('--accent') || '#00d4ff';
      ctx.fillStyle = land;
      ctx.strokeStyle = stroke;
      ctx.globalAlpha = 0.13;
      for (const poly of WORLD_LANDMASSES) {
        if (!poly.length) continue;
        ctx.beginPath();
        ctx.moveTo(poly[0][0] * w, poly[0][1] * h);
        for (let i = 1; i < poly.length; i++) {
          ctx.lineTo(poly[i][0] * w, poly[i][1] * h);
        }
        ctx.closePath();
        ctx.fill();
      }

      ctx.globalAlpha = 0.3;
      for (const poly of WORLD_LANDMASSES) {
        if (!poly.length) continue;
        ctx.beginPath();
        ctx.moveTo(poly[0][0] * w, poly[0][1] * h);
        for (let i = 1; i < poly.length; i++) {
          ctx.lineTo(poly[i][0] * w, poly[i][1] * h);
        }
        ctx.closePath();
        ctx.stroke();
      }

      ctx.globalAlpha = 1;
    }

    function drawThreatMap(canvas, originPts, impactedPts, note) {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 800;
      const cssH = canvas.clientHeight || 400;
      const dpr = window.devicePixelRatio || 1;
      
      // Validate dimensions
      if (cssW < 50 || cssH < 30) return;
      
      const MAX_PX = 4096;
      const pw = Math.min(Math.floor(cssW * dpr), MAX_PX);
      const ph = Math.min(Math.floor(cssH * dpr), MAX_PX);
      canvas.width = pw;
      canvas.height = ph;
      ctx.setTransform(pw / cssW, 0, 0, ph / cssH, 0, 0);

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      drawWorldBackdrop(ctx, w, h);

      // Points.
      const drawPts = (pts, color) => {
        ctx.fillStyle = color;
        for (const p of pts) {
          const [x, y] = toMapXY(p.lat, p.lon, w, h);
          ctx.globalAlpha = 0.85;
          ctx.beginPath();
          ctx.arc(x, y, 5, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 0.25;
          ctx.beginPath();
          ctx.arc(x, y, 12, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
      };

      drawPts(originPts, getCssVar('--danger') || '#ff4757');
      drawPts(impactedPts, getCssVar('--accent') || '#00d4ff');

      if (note) {
        ctx.fillStyle = getCssVar('--muted') || 'rgba(255,255,255,0.7)';
        ctx.font = '12px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial';
        ctx.fillText(note, 10, h - 10);
      }
    }

    async function kickGeoipBatch(ips) {
      const now = Date.now();
      if (state.geoip.inflight) return;
      if (now - state.geoip.lastFetchMs < 3500) return;

      const uniq = [...new Set((ips || []).map((s) => String(s || '').trim()).filter(Boolean))];
      const missing = uniq.filter((ip) => !state.geoip.cache.has(ip)).slice(0, 80);
      if (!missing.length) return;

      state.geoip.inflight = true;
      state.geoip.lastFetchMs = now;
      try {
        const resp = await apiPostJson(API.geoipBatch || '/api/geoip/batch', { ips: missing }, { timeoutMs: 5200 });
        if (resp && typeof resp.available === 'boolean') {
          state.geoip.available = resp.available;
        }
        const results = resp?.results && typeof resp.results === 'object' ? resp.results : {};
        for (const [ip, point] of Object.entries(results)) {
          if (point && typeof point.lat === 'number' && typeof point.lon === 'number') {
            state.geoip.cache.set(ip, { lat: point.lat, lon: point.lon, city: point.city || '', country: point.country || '' });
          }
        }
      } catch {
        // Non-fatal; keep previous availability state to avoid false negatives on transient failures.
      } finally {
        state.geoip.inflight = false;
        state.dirty.counters = true;
        scheduleRender();
      }
    }

    async function ensureGeoipAvailability() {
      const now = Date.now();
      if (state.geoip.inflight) return;
      if (state.geoip.available !== null) return;
      if (now - state.geoip.lastFetchMs < 10_000) return;
      state.geoip.inflight = true;
      state.geoip.lastFetchMs = now;
      try {
        const resp = await apiPostJson(API.geoipBatch || '/api/geoip/batch', { ips: [] }, { timeoutMs: 3000 });
        if (resp && typeof resp.available === 'boolean') {
          state.geoip.available = resp.available;
        }
      } catch {
        // Keep unknown state on transient failures.
      } finally {
        state.geoip.inflight = false;
        state.dirty.counters = true;
        scheduleRender();
      }
    }

    async function fetchLanTopology() {
      const now = Date.now();
      if (state.lan.inflight) return;
      if (now - (state.lan.lastFetchMs || 0) < 1800) return;
      state.lan.inflight = true;
      state.lan.lastFetchMs = now;
      try {
        const snap = await apiFetchJson(API.lanTopology, { timeoutMs: 1800, headers: { 'Accept': 'application/json' } });
        if (snap && typeof snap === 'object') {
          state.lan.status = String(snap.status || 'ok');
          state.lan.error = String(snap.error || '');
          state.lan.snapshot = snap;
          // Prime device name cache for LAN nodes too.
          const macs = [];
          const agents = Array.isArray(snap?.agents) ? snap.agents : [];
          const devices = Array.isArray(snap?.devices) ? snap.devices : [];
          for (const a of agents) {
            const m = normalizeMac(a?.mac || '');
            if (m) macs.push(m);
          }
          for (const d of devices) {
            const m = normalizeMac(d?.mac || '');
            if (m) macs.push(m);
          }
          if (macs.length) enqueueDeviceNameLookup(macs);
        }
      } catch {
        // Non-fatal; keep last snapshot.
        state.lan.status = 'error';
        state.lan.error = 'LAN topology request failed';
      } finally {
        state.lan.inflight = false;
      }
    }

    function decayLanRates(nowMs) {
      // Decay EMA towards 0 when no events arrive.
      const tauMs = 4500;
      for (const [aid, r] of state.lanRates.entries()) {
        const lastMs = Number(r?.lastMs || nowMs);
        const dt = Math.max(0, nowMs - lastMs);
        if (dt <= 0) continue;
        const decay = Math.exp(-dt / tauMs);
        const ema = Number(r?.ema || 0) * decay;
        // If very low and stale, drop to keep map small.
        if (ema < 0.02 && dt > 20_000) state.lanRates.delete(aid);
        else state.lanRates.set(aid, { ema, lastMs });
      }
    }

    function ensureLanAnimLoop() {
      if (state.lanAnim.running) return;
      state.lanAnim.running = true;

      const tick = () => {
        if (state.view !== 'overview' || state.mapMode !== 'lan') {
          state.lanAnim.running = false;
          if (state.lanAnim.rafId) cancelAnimationFrame(state.lanAnim.rafId);
          state.lanAnim.rafId = 0;
          return;
        }

        const now = performance.now();
        const perfLite = document.documentElement.classList.contains('perf-lite');
        const minFrameMs = perfLite ? 1000 / 12 : 1000 / 24;
        if ((now - Number(state.lanAnim.lastFrameMs || 0)) < minFrameMs) {
          state.lanAnim.rafId = requestAnimationFrame(tick);
          return;
        }
        state.lanAnim.lastFrameMs = now;

        const canvas = document.getElementById('ovThreatMap');
        if (canvas) drawLanBusTopology(canvas);
        state.lanAnim.rafId = requestAnimationFrame(tick);
      };

      state.lanAnim.rafId = requestAnimationFrame(tick);
    }

    function drawLanBusTopology(canvas) {
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const cssW = canvas.clientWidth || 600;
      const cssH = canvas.clientHeight || 400;
      const dpr = window.devicePixelRatio || 1;
      
      // Validate dimensions
      if (cssW < 50 || cssH < 30) return;

      const MAX_PX = 4096;
      // Resize only when needed.
      if (state.lanAnim.w !== cssW || state.lanAnim.h !== cssH || state.lanAnim.dpr !== dpr) {
        canvas.width = Math.min(Math.floor(cssW * dpr), MAX_PX);
        canvas.height = Math.min(Math.floor(cssH * dpr), MAX_PX);
        state.lanAnim.w = cssW;
        state.lanAnim.h = cssH;
        state.lanAnim.dpr = dpr;
      }
      ctx.setTransform(canvas.width / cssW, 0, 0, canvas.height / cssH, 0, 0);

      const w = cssW;
      const h = cssH;
      ctx.clearRect(0, 0, w, h);

      const snap = state.lan.snapshot;
      const nowMs = Date.now();
      decayLanRates(nowMs);

      const stroke = getCssVar('--stroke2') || 'rgba(255,255,255,0.20)';
      const muted = getCssVar('--muted') || 'rgba(255,255,255,0.70)';
      const text = getCssVar('--text') || 'rgba(255,255,255,0.92)';
      const ok = getCssVar('--ok') || '#26de81';
      const accent = getCssVar('--accent') || '#00d4ff';

      const roundRectPath = (x, y, ww, hh, rr) => {
        const r = Math.max(0, Math.min(rr, Math.min(ww, hh) / 2));
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + ww, y, x + ww, y + hh, r);
        ctx.arcTo(x + ww, y + hh, x, y + hh, r);
        ctx.arcTo(x, y + hh, x, y, r);
        ctx.arcTo(x, y, x + ww, y, r);
        ctx.closePath();
      };

      const drawIcon = (kind, x, y, size, color, alpha) => {
        const s = size;
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.strokeStyle = color;
        ctx.fillStyle = color;
        ctx.lineWidth = 1.5;

        if (kind === 'server') {
          // Simple rack: 3 stacked rounded boxes.
          const w0 = s * 1.2;
          const h0 = s * 0.38;
          for (let i = 0; i < 3; i++) {
            const yy = y - s * 0.7 + i * (h0 + 2);
            roundRectPath(x - w0 / 2, yy, w0, h0, 4);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(x + w0 * 0.35, yy + h0 / 2, 1.4, 0, Math.PI * 2);
            ctx.fill();
          }
        } else if (kind === 'router') {
          // Router: box + two antennas.
          const w0 = s * 1.1;
          const h0 = s * 0.45;
          roundRectPath(x - w0 / 2, y - h0 / 2, w0, h0, 6);
          ctx.stroke();
          ctx.beginPath();
          ctx.moveTo(x - w0 * 0.25, y - h0 / 2);
          ctx.lineTo(x - w0 * 0.35, y - h0);
          ctx.moveTo(x + w0 * 0.25, y - h0 / 2);
          ctx.lineTo(x + w0 * 0.35, y - h0);
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(x, y, 2.2, 0, Math.PI * 2);
          ctx.fill();
        } else if (kind === 'phone') {
          // Phone: tall rounded rect + small speaker dot.
          const w0 = s * 0.62;
          const h0 = s * 1.05;
          roundRectPath(x - w0 / 2, y - h0 / 2, w0, h0, 10);
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(x, y - h0 * 0.36, 1.2, 0, Math.PI * 2);
          ctx.fill();
        } else {
          // computer/laptop default
          const screenW = s * 1.15;
          const screenH = s * 0.7;
          roundRectPath(x - screenW / 2, y - screenH / 2, screenW, screenH, 8);
          ctx.stroke();
          // stand/base
          ctx.beginPath();
          ctx.moveTo(x - s * 0.22, y + screenH / 2 + 2);
          ctx.lineTo(x + s * 0.22, y + screenH / 2 + 2);
          ctx.stroke();
          ctx.beginPath();
          ctx.moveTo(x - s * 0.45, y + screenH / 2 + 5);
          ctx.lineTo(x + s * 0.45, y + screenH / 2 + 5);
          ctx.stroke();
        }

        ctx.restore();
      };

      // Backdrop grid (subtle).
      ctx.strokeStyle = stroke;
      ctx.globalAlpha = 0.18;
      const cols = 14;
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

      const busY = Math.round(h * 0.58) + 0.5;
      const busLeft = 90;
      const busRight = w - 22;
      const serverX = 24;

      // Server node.
      const serverLabel = (snap && (snap.server_ip || snap.server_host)) ? (snap.server_ip || snap.server_host) : 'server';
      drawIcon('server', serverX, busY, 16, accent, 0.95);

      // Backbone bus.
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.75;
      ctx.beginPath();
      ctx.moveTo(busLeft, busY);
      ctx.lineTo(busRight, busY);
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Server-to-bus connector.
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.8;
      ctx.beginPath();
      ctx.moveTo(serverX + 10, busY);
      ctx.lineTo(busLeft, busY);
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Extract and de-duplicate nodes.
      const agentsRaw = Array.isArray(snap?.agents) ? snap.agents : [];
      const devicesRaw = Array.isArray(snap?.devices) ? snap.devices : [];

      const gatewayIp = String(snap?.gateway_ip || '').trim();

      const maxAgeMs = 24 * 60 * 60 * 1000;

      const connected = new Set(Array.isArray(state.stats?.connected_agent_ids) ? state.stats.connected_agent_ids : []);

      const agentIps = new Set();
      const agentMacs = new Set();
      const agents = [];
      for (const a of agentsRaw) {
        const aid = String(a?.agent_id || '').trim();
        if (!aid) continue;
        const ip = String(a?.ip || '').trim();
        const mac = normalizeMac(a?.mac || '');
        if (ip) agentIps.add(ip);
        if (mac) agentMacs.add(mac);
        const lastSeen = Number(a?.last_seen_unix || 0) * 1000;
        if (lastSeen && (nowMs - lastSeen) > maxAgeMs) continue;
        agents.push({ aid, ip, mac, connected: connected.has(aid), lastSeen });
      }

      const devices = [];
      for (const d of devicesRaw) {
        const ip = String(d?.ip || '').trim();
        const mac = normalizeMac(d?.mac || '');
        if (!ip) continue;
        if (agentIps.has(ip)) continue;
        if (mac && agentMacs.has(mac)) continue;
        const lastSeen = Number(d?.last_seen_unix || 0) * 1000;
        if (lastSeen && (nowMs - lastSeen) > maxAgeMs) continue;
        devices.push({ ip, mac, lastSeen });
      }

      // Cap to keep rendering predictable.
      if (agents.length > 80) agents.length = 80;
      if (devices.length > 140) devices.length = 140;

      agents.sort((a, b) => (a.ip || a.aid).localeCompare(b.ip || b.aid));
      devices.sort((a, b) => a.ip.localeCompare(b.ip));

      const slots = Math.max(1, agents.length + devices.length);
      const step = (busRight - busLeft) / (slots + 1);
      let slotIndex = 0;

      const agentNodes = [];
      const deviceNodes = [];

      const mkX = () => {
        slotIndex += 1;
        return Math.round(busLeft + step * slotIndex) + 0.5;
      };

      for (const a of agents) {
        agentNodes.push({ ...a, x: mkX(), y: Math.round(h * 0.25) + 0.5 });
      }
      for (const d of devices) {
        deviceNodes.push({ ...d, x: mkX(), y: Math.round(h * 0.82) + 0.5 });
      }

      // Draw device nodes (white).
      ctx.font = '12px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.textBaseline = 'middle';
      for (const n of deviceNodes) {
        const alpha = n.lastSeen ? Math.max(0.18, 1 - ((nowMs - n.lastSeen) / maxAgeMs)) : 0.9;
        const name = n.mac ? getDeviceNameForMac(n.mac) : '';
        const label = name || n.ip;
        const kind = (gatewayIp && n.ip === gatewayIp) ? 'router' : ((name && /phone|mobile|iphone|android/i.test(name)) ? 'phone' : 'computer');
        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.55 * alpha;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y);
        ctx.lineTo(n.x, busY);
        ctx.stroke();

        drawIcon(kind, n.x, n.y, 12, text, 0.95 * alpha);

        ctx.globalAlpha = 0.75 * alpha;
        ctx.fillStyle = muted;
        ctx.fillText(label, Math.min(w - 160, n.x + 12), n.y);
        ctx.globalAlpha = 1;
      }

      // Draw agent nodes (connected green; disconnected muted).
      for (const n of agentNodes) {
        const alpha = n.lastSeen ? Math.max(0.18, 1 - ((nowMs - n.lastSeen) / maxAgeMs)) : 0.9;
        const nodeColor = n.connected ? ok : stroke;

        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.7 * alpha;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y);
        ctx.lineTo(n.x, busY);
        ctx.stroke();

        drawIcon('computer', n.x, n.y, 14, nodeColor, 0.95 * alpha);

        ctx.globalAlpha = 0.75 * alpha;
        ctx.fillStyle = muted;
        ctx.fillText(n.ip || n.aid, Math.min(w - 190, n.x + 14), n.y);
        ctx.globalAlpha = 1;
      }

      // Labels.
      ctx.fillStyle = muted;
      ctx.globalAlpha = 0.9;
      ctx.fillText(`Server: ${serverLabel}`, 10, 14);
      ctx.fillText(`Agents: ${agentNodes.length} • Devices: ${deviceNodes.length}`, 10, 30);
      ctx.globalAlpha = 1;

      // Animated bidirectional flows between each agent and server (volume-weighted).
      const particlesByAgent = state.lanAnim.particlesByAgent;
      for (const n of agentNodes) {
        const aid = n.aid;
        const r = state.lanRates.get(aid);
        const eps = Math.max(0, Number(r?.ema || 0));

        // Thickness and particle count based on eps.
        const thick = 1 + Math.min(7, Math.log1p(eps) * 2.2);
        const targetParticles = Math.max(1, Math.min(10, Math.round(1 + Math.log1p(eps) * 3)));
        const speed = 0.18 + Math.min(1.1, Math.log1p(eps) * 0.22);

        // Base link (heavier with more volume).
        ctx.strokeStyle = stroke;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = thick;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y);
        ctx.lineTo(n.x, busY);
        ctx.lineTo(serverX, busY);
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Maintain per-agent particle arrays.
        let parts = particlesByAgent.get(aid);
        if (!parts) {
          parts = [];
          particlesByAgent.set(aid, parts);
        }

        while (parts.length < targetParticles) {
          parts.push({ t: Math.random(), dir: Math.random() < 0.5 ? 1 : -1 });
        }
        if (parts.length > targetParticles) parts.length = targetParticles;

        const totalLen = Math.abs(n.y - busY) + Math.abs(n.x - serverX);
        const dt = 1 / 60;

        for (const p of parts) {
          p.t = (p.t + (p.dir * speed * dt)) % 1;
          if (p.t < 0) p.t += 1;

          // Position along polyline: agent->bus->server.
          let dist = p.t * totalLen;
          let x = n.x;
          let y = n.y;
          const seg1 = Math.abs(n.y - busY);
          if (dist <= seg1) {
            y = n.y + (busY - n.y) * (dist / seg1);
          } else {
            dist -= seg1;
            x = n.x + (serverX - n.x) * (dist / Math.max(1, Math.abs(n.x - serverX)));
            y = busY;
          }

          const col = (p.dir > 0) ? ok : accent;
          ctx.fillStyle = col;
          ctx.globalAlpha = 0.85;
          const pr = 2 + Math.min(4, thick / 2);
          ctx.beginPath();
          ctx.arc(x, y, pr, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      }
    }

