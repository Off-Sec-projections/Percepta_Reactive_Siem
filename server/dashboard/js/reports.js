// ═══════════════════════════════════════════════════════════════
//  Reports — Report generation & history pane controller
// ═══════════════════════════════════════════════════════════════

const reportsCache = [];

/** Sanitize a cell value for CSV: escape quotes, prevent formula injection. */
function csvSafe(val) {
  let s = String(val == null ? '' : val).replace(/"/g, '""');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s + '"';
}

function parseJsonLikeString(value) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  if (!((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']')))) {
    return value;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function formatReportCellValue(value) {
  const normalized = parseJsonLikeString(value);
  if (normalized == null) return '—';
  if (typeof normalized === 'string' || typeof normalized === 'number' || typeof normalized === 'boolean') {
    return String(normalized);
  }
  if (Array.isArray(normalized)) {
    if (normalized.length === 0) return '[]';
    const preview = normalized.slice(0, 3).map((item) => {
      const itemNorm = parseJsonLikeString(item);
      if (itemNorm == null) return 'null';
      if (typeof itemNorm === 'string' || typeof itemNorm === 'number' || typeof itemNorm === 'boolean') return String(itemNorm);
      if (Array.isArray(itemNorm)) return `[${itemNorm.length} items]`;
      if (typeof itemNorm === 'object') {
        const entries = Object.entries(itemNorm).slice(0, 2).map(([k, v]) => `${k}: ${formatReportCellValue(v)}`);
        return `{ ${entries.join(', ')}${Object.keys(itemNorm).length > 2 ? ', …' : ''} }`;
      }
      return String(itemNorm);
    }).join(', ');
    return normalized.length > 3 ? `${preview} … (+${normalized.length - 3})` : preview;
  }
  if (typeof normalized === 'object') {
    const entries = Object.entries(normalized).slice(0, 4).map(([k, v]) => `${k}: ${formatReportCellValue(v)}`);
    return entries.length ? `${entries.join(' • ')}${Object.keys(normalized).length > 4 ? ' • …' : ''}` : '{}';
  }

  if (value == null) return '—';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const preview = value.slice(0, 3).map((item) => {
      if (item == null) return 'null';
      if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') return String(item);
      try { return JSON.stringify(item); } catch { return '[complex]'; }
    }).join(', ');
    return value.length > 3 ? `${preview} … (+${value.length - 3})` : preview;
  }
  try { return JSON.stringify(value); } catch { return '[object]'; }
}

function initReportsPane() {
  loadReportList();
  const genBtn = document.getElementById('reportsGenerateBtn');
  if (genBtn) genBtn.addEventListener('click', generateReport);
  const refreshBtn = document.getElementById('reportsRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadReportList);
}

async function generateReport() {
  const typeEl = document.getElementById('reportsType');
  const periodEl = document.getElementById('reportsRange');
  const formatEl = document.getElementById('reportsFormat');
  if (!typeEl || !periodEl) return;

  const format = formatEl ? formatEl.value : 'json';
  const body = {
    type: typeEl.value,
    period: periodEl.value,
    format: 'json', // always fetch JSON; convert client-side
  };

  const statusEl = document.getElementById('reportsStatus');
  if (statusEl) { statusEl.textContent = 'Generating…'; statusEl.style.color = 'var(--accent)'; }

  try {
    const result = await apiPostJson('/api/reports/generate', body);
    if (statusEl) { statusEl.textContent = 'Report generated'; statusEl.style.color = 'var(--ok, #2ed573)'; }
    showToast(`Report generated: ${result.type || body.type}`, 'ok');
    loadReportList();

    if (format === 'pdf') {
      exportReportPdf(result);
    } else if (format === 'docx') {
      exportReportDocx(result);
    } else if (format === 'csv') {
      exportReportCsv(result);
    } else {
      showReportPreview(result);
    }
  } catch {
    if (statusEl) { statusEl.textContent = 'Failed'; statusEl.style.color = 'var(--danger)'; }
    showToast('Failed to generate report', 'error');
  }
}

// ── Report enrichment helpers ──
function buildExecutiveSummary(summary, period) {
  const total = summary.total_alerts || 0;
  const critical = summary.critical_alerts || 0;
  const high = summary.high_alerts || 0;
  const medium = summary.medium_alerts || 0;
  const events = summary.total_events || 0;
  const hosts = summary.unique_hosts || 0;

  // Risk posture
  let riskLevel = 'Low';
  let riskColor = '#2ed573';
  if (critical > 5 || (critical > 0 && high > 10)) { riskLevel = 'Critical'; riskColor = '#ff3333'; }
  else if (critical > 0 || high > 5) { riskLevel = 'High'; riskColor = '#e05252'; }
  else if (high > 0 || medium > 10) { riskLevel = 'Elevated'; riskColor = '#e08c36'; }
  else if (total > 0) { riskLevel = 'Guarded'; riskColor = '#4a9c5d'; }

  const periodLabel = {'1h':'the last hour','6h':'the last 6 hours','12h':'the last 12 hours','24h':'the last 24 hours','7d':'the last 7 days','30d':'the last 30 days'}[period] || period;

  let narrative = `During ${periodLabel}, Percepta SIEM processed <strong>${Number(events).toLocaleString()}</strong> events across <strong>${hosts}</strong> monitored host${hosts !== 1 ? 's' : ''}.`;
  if (total > 0) {
    narrative += ` A total of <strong>${total}</strong> alert${total !== 1 ? 's were' : ' was'} generated`;
    const parts = [];
    if (critical > 0) parts.push(`<strong style="color:#ff3333">${critical} critical</strong>`);
    if (high > 0) parts.push(`<strong style="color:#e05252">${high} high</strong>`);
    if (medium > 0) parts.push(`<strong style="color:#e08c36">${medium} medium</strong>`);
    if (parts.length) narrative += `, including ${parts.join(', ')}`;
    narrative += '.';
  } else {
    narrative += ' No alerts were triggered during this period.';
  }

  const enabledRatio = (summary.enabled_rules || 0) + '/' + (summary.total_rules || 0);
  narrative += ` Detection coverage: <strong>${enabledRatio}</strong> rules active.`;

  return { riskLevel, riskColor, narrative };
}

function buildRecommendations(summary, sections) {
  const recs = [];
  const critical = summary.critical_alerts || 0;
  const high = summary.high_alerts || 0;
  if (critical > 0) recs.push('Immediate investigation required for critical alerts. Escalate to SOC Tier 2/3 and initiate incident response procedures.');
  if (high > 3) recs.push('Multiple high-severity alerts detected. Review Top Triggered Rules to identify attack patterns and prioritize triage.');
  const compliance = sections?.['Compliance Framework Coverage'];
  if (Array.isArray(compliance) && compliance.length > 0) recs.push('Review compliance framework alignment. Ensure findings are mapped to organizational control requirements.');
  const mitre = sections?.['MITRE ATT&CK Tactics'];
  if (Array.isArray(mitre) && mitre.length > 3) recs.push('Multiple MITRE ATT&CK tactics observed. Correlate with kill-chain analysis to determine adversary progression stage.');
  const hosts = sections?.['Most Impacted Hosts'];
  if (Array.isArray(hosts) && hosts.length > 0) recs.push('Prioritize forensic review of top impacted hosts. Consider network isolation for hosts with repeated critical alerts.');
  if ((summary.enabled_rules || 0) < (summary.total_rules || 0)) recs.push('Not all detection rules are enabled. Review disabled rules and enable those relevant to your threat landscape.');
  if (recs.length === 0) recs.push('No critical findings. Continue routine monitoring and periodic rule tuning.');
  return recs;
}

// ── PDF Export (built-in, no external library) ──
function exportReportPdf(report) {
  const type = report.report_type || report.type || 'Report';
  const gen = report.generated_at || report.timestamp;
  const genStr = gen ? new Date(gen).toLocaleString() : '—';
  const range = report.range || report.period || '—';
  const summary = report.summary || {};
  const exec = buildExecutiveSummary(summary, report.period || range);
  const recs = buildRecommendations(summary, report.sections);

  // Build structured HTML for printing
  const sections = buildReportSections(report);
  const recsHtml = recs.map((r, i) => `<tr><td style="width:30px;color:#3b9cc2;font-weight:700;">${i + 1}.</td><td>${esc(r)}</td></tr>`).join('');
  const printHtml = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Percepta SIEM — ${esc(type)}</title>
<style>
  @page { margin: 18mm; size: A4; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1a1a2e; line-height: 1.55; margin: 0; padding: 0; font-size: 12px; }
  .header { background: linear-gradient(135deg, #0a0e1a 0%, #131a2e 100%); color: #e4ecf7; padding: 28px 32px; margin-bottom: 0; }
  .header h1 { margin: 0 0 6px; font-size: 22px; font-weight: 700; letter-spacing: 0.5px; }
  .header .sub { font-size: 12px; color: #a0b4d2; }
  .header .brand { font-size: 10px; color: #5a7a9c; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 10px; }
  .risk-bar { display: flex; align-items: center; gap: 16px; padding: 10px 32px; background: #f8f9fb; border-bottom: 2px solid #e2e5eb; font-size: 13px; }
  .risk-badge { display: inline-block; padding: 4px 14px; border-radius: 4px; font-weight: 700; font-size: 13px; color: #fff; letter-spacing: 0.5px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 12px; margin: 16px 0 20px; padding: 0 4px; }
  .metric { text-align: center; padding: 10px 6px; background: #f4f6fa; border-radius: 6px; border: 1px solid #e2e5eb; }
  .metric .val { font-size: 20px; font-weight: 700; color: #0d1526; display: block; }
  .metric .lbl { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .metric.crit .val { color: #ff3333; } .metric.high .val { color: #e05252; } .metric.med .val { color: #e08c36; }
  .exec-summary { margin: 16px 0 20px; padding: 14px 18px; background: #f8fafc; border-left: 4px solid #3b9cc2; border-radius: 0 6px 6px 0; font-size: 13px; color: #344054; line-height: 1.7; }
  .section { margin-bottom: 18px; page-break-inside: avoid; }
  .section h2 { font-size: 14px; font-weight: 700; color: #0d1526; border-bottom: 2px solid #3b9cc2; padding-bottom: 5px; margin: 0 0 10px; text-transform: uppercase; letter-spacing: 0.5px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 11.5px; }
  th { background: #e8ecf2; padding: 7px 10px; text-align: left; font-weight: 600; color: #1a1a2e; border: 1px solid #d0d5dd; }
  td { padding: 6px 10px; border: 1px solid #e2e5eb; color: #344054; }
  tr:nth-child(even) td { background: #f8f9fb; }
  .kv { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px; font-size: 13px; }
  .kv dt { color: #475569; font-weight: 600; }
  .kv dd { color: #1a1a2e; margin: 0; }
  .badge { display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;margin-right:3px;color:#fff; }
  .sev-critical{background:#ff3333;} .sev-high{background:#e05252;} .sev-medium{background:#e08c36;} .sev-low{background:#4a9c5d;} .sev-info{background:#4f8cff;}
  .recs-table { margin: 8px 0; } .recs-table td { border: none; padding: 4px 8px; vertical-align: top; font-size: 12px; }
  .footer { margin-top: 30px; padding-top: 12px; border-top: 1px solid #e2e5eb; font-size: 10px; color: #a0aab8; text-align: center; }
  .toc { margin: 16px 0; padding: 12px 18px; background: #f8f9fb; border-radius: 6px; font-size: 12px; }
  .toc-title { font-weight: 700; font-size: 13px; margin-bottom: 6px; color: #0d1526; }
  .toc-item { color: #3b9cc2; margin: 2px 0; }
  pre { font-size: 10px; background: #f4f5f7; padding: 8px; border-radius: 4px; overflow-wrap: break-word; white-space: pre-wrap; }
</style></head><body>
<div class="header">
  <h1>Percepta SIEM Report — ${esc(type.replace(/_/g, ' '))}</h1>
  <div class="sub">Generated: ${esc(genStr)} · Range: ${esc(range)}</div>
  <div class="brand">PERCEPTA by OFF-Sec Projections · Confidential</div>
</div>
<div class="risk-bar">
  <span style="color:#64748b;">Security Posture:</span>
  <span class="risk-badge" style="background:${exec.riskColor}">${esc(exec.riskLevel)}</span>
  <span style="color:#64748b;font-size:11px;margin-left:auto;">Report ID: ${esc(String(report.id || '').substring(0, 8))}</span>
</div>
<div class="metrics">
  <div class="metric"><span class="val">${esc(String(Number(summary.total_events || 0).toLocaleString()))}</span><span class="lbl">Events</span></div>
  <div class="metric"><span class="val">${esc(String(summary.total_alerts || 0))}</span><span class="lbl">Alerts</span></div>
  <div class="metric crit"><span class="val">${esc(String(summary.critical_alerts || 0))}</span><span class="lbl">Critical</span></div>
  <div class="metric high"><span class="val">${esc(String(summary.high_alerts || 0))}</span><span class="lbl">High</span></div>
  <div class="metric med"><span class="val">${esc(String(summary.medium_alerts || 0))}</span><span class="lbl">Medium</span></div>
  <div class="metric"><span class="val">${esc(String(summary.unique_hosts || 0))}</span><span class="lbl">Hosts</span></div>
  <div class="metric"><span class="val">${esc(String(summary.enabled_rules || 0))}/${esc(String(summary.total_rules || 0))}</span><span class="lbl">Rules Active</span></div>
</div>
<div class="section"><h2>Executive Summary</h2>
  <div class="exec-summary">${exec.narrative}</div>
</div>
${sections}
<div class="section" style="page-break-before:auto;"><h2>Recommendations</h2>
  <table class="recs-table">${recsHtml}</table>
</div>
<div class="footer">Percepta SIEM · Confidential · ${esc(genStr)} · Report ${esc(String(report.id || '').substring(0, 8))}</div>
</body></html>`;

  const w = window.open('', '_blank', 'width=800,height=1000');
  if (!w) { showToast('Please allow popups for PDF export', 'error'); return; }
  w.document.write(printHtml);
  w.document.close();
  setTimeout(() => { w.print(); }, 400);
}

// ── DOCX Export (HTML-based Office XML) ──
function exportReportDocx(report) {
  const type = report.report_type || report.type || 'Report';
  const gen = report.generated_at || report.timestamp;
  const genStr = gen ? new Date(gen).toLocaleString() : '—';
  const range = report.range || report.period || '—';
  const summary = report.summary || {};
  const sections = buildReportSections(report);
  const exec = buildExecutiveSummary(summary, report.period || range);
  const recs = buildRecommendations(summary, report.sections);
  const recsHtml = recs.map((r, i) => `<p>${i + 1}. ${esc(r)}</p>`).join('');

  const docHtml = `<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8">
<style>
  body { font-family: Calibri, sans-serif; color: #1a1a2e; font-size: 11pt; }
  h1 { font-size: 18pt; color: #0a0e1a; border-bottom: 3px solid #3b9cc2; padding-bottom: 6pt; }
  h2 { font-size: 13pt; color: #1a1a2e; border-bottom: 1pt solid #3b9cc2; padding-bottom: 4pt; margin-top: 16pt; }
  table { border-collapse: collapse; width: 100%; }
  th { background: #e8ecf2; padding: 5pt 8pt; border: 1pt solid #c0c5cd; font-weight: bold; }
  td { padding: 4pt 8pt; border: 1pt solid #e0e3e8; }
  .meta { color: #475569; font-size: 10pt; margin-bottom: 12pt; }
  .footer { color: #a0aab8; font-size: 9pt; margin-top: 24pt; border-top: 1pt solid #e0e3e8; padding-top: 6pt; }
  pre { font-family: Consolas, monospace; font-size: 9pt; background: #f4f5f7; padding: 8pt; }
  dt { font-weight: bold; color: #475569; }
  .exec-box { background: #f0f4fa; padding: 10pt 14pt; border-left: 4pt solid #3b9cc2; margin: 10pt 0; font-size: 11pt; line-height: 1.6; }
  .risk-badge { display: inline; padding: 3pt 10pt; font-weight: bold; color: white; font-size: 11pt; }
  .metric-row td { border: none; text-align: center; padding: 6pt 10pt; }
  .metric-val { font-size: 16pt; font-weight: bold; color: #0d1526; }
  .metric-lbl { font-size: 8pt; color: #64748b; text-transform: uppercase; }
</style></head><body>
<h1>Percepta SIEM Report — ${esc(type.replace(/_/g, ' '))}</h1>
<p class="meta">Generated: ${esc(genStr)} · Range: ${esc(range)} · Security Posture: <span class="risk-badge" style="background:${exec.riskColor}">${esc(exec.riskLevel)}</span></p>
<table style="margin-bottom:14pt;"><tr class="metric-row">
  <td><span class="metric-val">${esc(String(Number(summary.total_events || 0).toLocaleString()))}</span><br/><span class="metric-lbl">Events</span></td>
  <td><span class="metric-val">${esc(String(summary.total_alerts || 0))}</span><br/><span class="metric-lbl">Alerts</span></td>
  <td><span class="metric-val" style="color:#ff3333">${esc(String(summary.critical_alerts || 0))}</span><br/><span class="metric-lbl">Critical</span></td>
  <td><span class="metric-val" style="color:#e05252">${esc(String(summary.high_alerts || 0))}</span><br/><span class="metric-lbl">High</span></td>
  <td><span class="metric-val">${esc(String(summary.unique_hosts || 0))}</span><br/><span class="metric-lbl">Hosts</span></td>
  <td><span class="metric-val">${esc(String(summary.enabled_rules || 0))}/${esc(String(summary.total_rules || 0))}</span><br/><span class="metric-lbl">Rules</span></td>
</tr></table>
<h2>Executive Summary</h2>
<div class="exec-box">${exec.narrative}</div>
${sections}
<h2>Recommendations</h2>
${recsHtml}
<p class="footer">Percepta SIEM · Confidential · ${esc(genStr)} · Report ${esc(String(report.id || '').substring(0, 8))}</p>
</body></html>`;

  const blob = new Blob(['\ufeff' + docHtml], { type: 'application/msword' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `percepta_report_${type}_${Date.now()}.doc`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  showToast('DOCX report downloaded', 'ok');
}

// ── CSV Export ──
function exportReportCsv(report) {
  const summary = report.summary || {};
  const exec = buildExecutiveSummary(summary, report.period || '');
  const recs = buildRecommendations(summary, report.sections);
  const rows = [['Field', 'Value']];
  rows.push(['Report Type', report.report_type || report.type || '']);
  rows.push(['Generated', report.generated_at || '']);
  rows.push(['Period', report.period || '']);
  rows.push(['Security Posture', exec.riskLevel]);
  for (const [k, v] of Object.entries(summary)) {
    if (Array.isArray(v)) {
      rows.push([k, v.map(i => typeof i === 'object' ? JSON.stringify(i) : String(i)).join('; ')]);
    } else {
      rows.push([k, String(v ?? '')]);
    }
  }
  // Section data
  if (report.sections) {
    for (const [sectionName, sectionData] of Object.entries(report.sections)) {
      rows.push(['', '']);
      rows.push([`=== ${sectionName} ===`, '']);
      if (Array.isArray(sectionData) && sectionData.length > 0 && typeof sectionData[0] === 'object') {
        const keys = Object.keys(sectionData[0]);
        rows.push(keys);
        for (const row of sectionData.slice(0, 50)) {
          rows.push(keys.map(k => String(row[k] ?? '')));
        }
      }
    }
  }
  rows.push(['', '']);
  rows.push(['=== Recommendations ===', '']);
  recs.forEach((r, i) => rows.push([`${i + 1}`, r]));

  const csvContent = '\uFEFF' + rows.map(r => r.map(csvSafe).join(',')).join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `percepta_report_${report.type || 'report'}_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  showToast('CSV report downloaded', 'ok');
}

// ── Alert Evidence PDF Export ──────────────────────────────────────────────
function exportAlertEvidencePdf(alertObj) {
  if (!alertObj) { showToast('No alert selected', 'warn'); return; }
  const esc2 = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const id = alertObj.id || '';
  const ruleName = alertObj.rule_name || alertObj.rule_id || '—';
  const severity = alertObj.severity || '—';
  const status = alertObj.status || '—';
  const agent = alertObj.agent_hostname || alertObj.agent_id || '—';
  const msg = alertObj.message || '—';
  const firstSeen = alertObj.first_seen ? new Date(alertObj.first_seen).toLocaleString() : '—';
  const lastSeen = alertObj.last_seen ? new Date(alertObj.last_seen).toLocaleString() : '—';
  const count = alertObj.count || 1;
  const md = alertObj.metadata || {};
  const compliance = Array.isArray(alertObj.compliance) ? alertObj.compliance.join(', ') : (alertObj.compliance || '—');

  // MITRE
  const tactics = String(md.mitre_tactics || '').split(',').map(s => s.trim()).filter(Boolean);
  const techniques = String(md.mitre_attack || '').split(',').map(s => s.trim()).filter(Boolean);

  // Evidence conditions
  let evidenceHtml = '<p class="muted">No structured evidence conditions.</p>';
  const evRaw = md.evidence_json || md.evidenceJson;
  if (evRaw) {
    try {
      const ev = JSON.parse(String(evRaw));
      const conds = Array.isArray(ev.conditions) ? ev.conditions : [];
      if (conds.length) {
        evidenceHtml = '<table><thead><tr><th>Field</th><th>Operator</th><th>Expected</th><th>Actual</th></tr></thead><tbody>';
        for (const c of conds.slice(0, 50)) {
          evidenceHtml += `<tr><td class="mono">${esc2(c.field || '')}</td><td>${esc2(c.operator || '')}</td><td class="mono">${esc2(c.expected ?? '')}</td><td class="mono">${esc2(c.actual ?? '')}</td></tr>`;
        }
        evidenceHtml += '</tbody></table>';
        if (ev.threshold) {
          evidenceHtml = `<p>Threshold: ${esc2(ev.threshold.count ?? '')} events in ${esc2(ev.threshold.window_seconds ?? '')}s${ev.group_key ? ' · Group: ' + esc2(ev.group_key) : ''}</p>` + evidenceHtml;
        }
      }
    } catch {}
  }

  // Source events
  const srcEvts = Array.isArray(alertObj.source_events) ? alertObj.source_events : [];
  let eventsHtml = '';
  if (srcEvts.length) {
    eventsHtml = '<div class="section"><h2>Source Events</h2><table><thead><tr><th>Time</th><th>Type</th><th>Message</th></tr></thead><tbody>';
    for (const ev of srcEvts.slice(0, 30)) {
      const evTs = ev.ts_unix ? new Date(ev.ts_unix * 1000).toLocaleString() : (ev.ts ? new Date(ev.ts).toLocaleString() : '—');
      const evKind = ev.kind || ev.type || ev.category || '—';
      const evMsg = ev.message || ev.msg || JSON.stringify(ev).substring(0, 200);
      eventsHtml += `<tr><td class="mono">${esc2(evTs)}</td><td>${esc2(evKind)}</td><td>${esc2(evMsg.substring(0, 200))}</td></tr>`;
    }
    eventsHtml += '</tbody></table></div>';
  }

  // Metadata KV
  const mdEntries = Object.entries(md).filter(([k]) => !['evidence_json','evidenceJson'].includes(k)).slice(0, 40);
  let mdHtml = '';
  if (mdEntries.length) {
    mdHtml = '<div class="section"><h2>Alert Metadata</h2><dl class="kv">';
    for (const [k, v] of mdEntries) {
      mdHtml += `<dt>${esc2(k)}</dt><dd class="mono">${esc2(String(v ?? ''))}</dd>`;
    }
    mdHtml += '</dl></div>';
  }

  const now = new Date().toLocaleString();
  const printHtml = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Percepta SIEM — Alert Evidence: ${esc2(id)}</title>
<style>
  @page { margin: 18mm; size: A4; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1a1a2e; line-height: 1.5; margin: 0; font-size: 12px; }
  .header { background: #0a0e1a; color: #e4ecf7; padding: 22px 28px; margin-bottom: 20px; }
  .header h1 { margin: 0 0 4px; font-size: 18px; font-weight: 700; }
  .header .sub { font-size: 11px; color: #a0b4d2; }
  .header .brand { font-size: 9px; color: #5a7a9c; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 8px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; margin-right: 4px; }
  .sev-critical { background:#ff3333;color:#fff; } .sev-high { background:#e05252;color:#fff; }
  .sev-medium { background:#e08c36;color:#fff; } .sev-low { background:#4a9c5d;color:#fff; } .sev-info { background:#4f8cff;color:#fff; }
  .section { margin-bottom: 18px; page-break-inside: avoid; }
  .section h2 { font-size: 13px; font-weight: 700; color: #0d1526; border-bottom: 2px solid #3b9cc2; padding-bottom: 4px; margin: 0 0 10px; text-transform: uppercase; letter-spacing: 0.5px; }
  .kv { display: grid; grid-template-columns: 160px 1fr; gap: 3px 10px; }
  .kv dt { color: #475569; font-weight: 600; }
  .kv dd { color: #1a1a2e; margin: 0; }
  table { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 11px; }
  th { background: #e8ecf2; padding: 6px 8px; text-align: left; font-weight: 600; border: 1px solid #d0d5dd; }
  td { padding: 5px 8px; border: 1px solid #e2e5eb; }
  tr:nth-child(even) td { background: #f8f9fb; }
  .mono { font-family: Consolas, monospace; font-size: 10px; }
  .mitre-wrap { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  .mitre-tac { background:#4f8cff;color:#fff;padding:2px 8px;border-radius:3px;font-size:10px; }
  .mitre-tech { background:#333;color:#eee;padding:2px 8px;border-radius:3px;font-size:10px; }
  .footer { margin-top: 24px; padding-top: 10px; border-top: 1px solid #e2e5eb; font-size: 9px; color: #a0aab8; text-align: center; }
  .muted { color: #888; font-style: italic; }
</style></head><body>
<div class="header">
  <h1>Alert Evidence Report</h1>
  <div class="sub">Alert ID: ${esc2(id)} · Generated: ${esc2(now)}</div>
  <div class="brand">PERCEPTA SIEM by OFF-Sec Projections · Confidential</div>
</div>

<div class="section"><h2>Alert Summary</h2>
<dl class="kv">
  <dt>Rule</dt><dd>${esc2(ruleName)}</dd>
  <dt>Severity</dt><dd><span class="badge sev-${esc2(severity.toLowerCase())}">${esc2(severity)}</span></dd>
  <dt>Status</dt><dd>${esc2(status)}</dd>
  <dt>Agent / Host</dt><dd class="mono">${esc2(agent)}</dd>
  <dt>Message</dt><dd>${esc2(msg)}</dd>
  <dt>First Seen</dt><dd>${esc2(firstSeen)}</dd>
  <dt>Last Seen</dt><dd>${esc2(lastSeen)}</dd>
  <dt>Event Count</dt><dd>${esc2(String(count))}</dd>
  <dt>Compliance</dt><dd>${esc2(compliance)}</dd>
</dl>
${(tactics.length || techniques.length) ? `<div class="mitre-wrap">${tactics.map(t=>`<span class="mitre-tac">${esc2(t)}</span>`).join('')}${techniques.map(t=>`<span class="mitre-tech">${esc2(t)}</span>`).join('')}</div>` : ''}
</div>

<div class="section"><h2>Evidence Conditions (Why Alert Fired)</h2>${evidenceHtml}</div>

${eventsHtml}
${mdHtml}

<div class="footer">Percepta SIEM · Alert ${esc2(id)} · Confidential · ${esc2(now)}</div>
</body></html>`;

  const w = window.open('', '_blank', 'width=820,height=1060');
  if (!w) { showToast('Please allow popups for PDF export', 'error'); return; }
  w.document.write(printHtml);
  w.document.close();
  setTimeout(() => w.print(), 400);
  showToast('Evidence PDF ready — use browser print to save as PDF', 'ok');
}

// ── Alert Evidence CSV Export ──────────────────────────────────────────────
function exportAlertEvidenceCsv(alertObj) {
  if (!alertObj) { showToast('No alert selected', 'warn'); return; }
  const rows = [['Field', 'Value']];
  rows.push(['Alert ID', alertObj.id || '']);
  rows.push(['Rule', alertObj.rule_name || alertObj.rule_id || '']);
  rows.push(['Severity', alertObj.severity || '']);
  rows.push(['Status', alertObj.status || '']);
  rows.push(['Agent', alertObj.agent_hostname || alertObj.agent_id || '']);
  rows.push(['Message', alertObj.message || '']);
  rows.push(['First Seen', alertObj.first_seen || '']);
  rows.push(['Last Seen', alertObj.last_seen || '']);
  rows.push(['Count', String(alertObj.count || 1)]);
  const md = alertObj.metadata || {};
  for (const [k, v] of Object.entries(md)) {
    if (k === 'evidence_json' || k === 'evidenceJson') continue;
    rows.push([k, String(v ?? '')]);
  }
  // Evidence conditions
  const evRaw = md.evidence_json || md.evidenceJson;
  if (evRaw) {
    try {
      const ev = JSON.parse(String(evRaw));
      const conds = Array.isArray(ev.conditions) ? ev.conditions : [];
      if (conds.length) {
        rows.push(['', '']);
        rows.push(['===Evidence Conditions===', '']);
        rows.push(['Field', 'Operator', 'Expected', 'Actual']);
        for (const c of conds.slice(0, 50)) {
          rows.push([c.field || '', c.operator || '', String(c.expected ?? ''), String(c.actual ?? '')]);
        }
      }
    } catch {}
  }
  const csvContent = '\uFEFF' + rows.map(r => r.map(csvSafe).join(',')).join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `percepta_alert_${(alertObj.id || 'evidence').substring(0, 20)}_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  showToast('Evidence CSV downloaded', 'ok');
}

// ── Shared: build formatted report sections ──
function buildReportSections(report) {
  const summary = report.summary || {};
  let html = '';

  // Summary statistics section
  html += '<div class="section"><h2>Summary Statistics</h2><dl class="kv">';
  for (const [k, v] of Object.entries(summary)) {
    if (Array.isArray(v)) continue;
    html += `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd>${esc(String(v ?? '—'))}</dd>`;
  }
  html += '</dl></div>';

  // Top agents
  if (Array.isArray(summary.top_agents) && summary.top_agents.length > 0) {
    html += '<div class="section"><h2>Top Agents</h2><table><tr><th>Agent</th><th>Events</th></tr>';
    for (const item of summary.top_agents) {
      const name = typeof item === 'object' ? (item.key || item.name || item.agent_id || JSON.stringify(item)) : String(item);
      const count = typeof item === 'object' ? (item.count || item.value || '') : '';
      html += `<tr><td>${esc(String(name))}</td><td>${esc(String(count))}</td></tr>`;
    }
    html += '</table></div>';
  }

  // Top sources
  if (Array.isArray(summary.top_sources) && summary.top_sources.length > 0) {
    html += '<div class="section"><h2>Top Sources</h2><table><tr><th>Source</th><th>Events</th></tr>';
    for (const item of summary.top_sources) {
      const name = typeof item === 'object' ? (item.key || item.name || JSON.stringify(item)) : String(item);
      const count = typeof item === 'object' ? (item.count || item.value || '') : '';
      html += `<tr><td>${esc(String(name))}</td><td>${esc(String(count))}</td></tr>`;
    }
    html += '</table></div>';
  }

  // Report-specific sections
  if (report.sections && typeof report.sections === 'object') {
    for (const [key, val] of Object.entries(report.sections)) {
      html += `<div class="section"><h2>${esc(key.replace(/_/g, ' '))}</h2>`;
      if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
        const keys = Object.keys(val[0]);
        html += `<table><tr>${keys.map(k => `<th>${esc(k)}</th>`).join('')}</tr>`;
        for (const row of val.slice(0, 50)) {
          html += `<tr>${keys.map(k => `<td>${esc(formatReportCellValue(row[k]))}</td>`).join('')}</tr>`;
        }
        html += '</table>';
      } else if (typeof val === 'object' && !Array.isArray(val)) {
        html += '<dl class="kv">';
        for (const [sk, sv] of Object.entries(val)) {
          html += `<dt>${esc(sk)}</dt><dd>${esc(formatReportCellValue(sv))}</dd>`;
        }
        html += '</dl>';
      } else {
        html += `<pre>${esc(typeof val === 'string' ? val : JSON.stringify(val, null, 2))}</pre>`;
      }
      html += '</div>';
    }
  }

  return html;
}

function esc(s) { return escapeHtml(String(s)); }

async function loadReportList() {
  const container = document.getElementById('reportsListContent');
  if (!container) return;
  container.innerHTML = '<div class="loading-state p-24">Loading reports…</div>';
  try {
    const resp = await apiFetchJson('/api/reports/list');
    const reports = Array.isArray(resp) ? resp : (resp?.reports || []);
    if (!Array.isArray(reports) || reports.length === 0) {
      container.innerHTML = '<div class="empty-state p-24">No reports generated yet. Use the controls above to generate one.</div>';
      return;
    }
    const rows = reports.map((r, idx) => {
      const type = r.report_type || r.type || '—';
      const range = r.range || r.period || '—';
      const gen = r.generated_at || r.timestamp;
      const genStr = gen ? new Date(gen).toLocaleString() : '—';
      const summary = formatReportCellValue(r.summary || '');
      return `<tr class="report-row-click" data-report-idx="${idx}">
        <td class="report-gen-cell">${escapeHtml(genStr)}</td>
        <td>${escapeHtml(type)}</td>
        <td class="report-meta-cell">${escapeHtml(range)}</td>
        <td class="report-meta-cell">${escapeHtml(summary)}</td>
        <td><button class="btnSm" data-view-report="${idx}">View</button></td>
      </tr>`;
    }).join('');
    container.innerHTML = `<div class="tableWrap maxh-400">
      <table class="tbl"><thead><tr><th>Generated</th><th>Type</th><th>Range</th><th>Summary</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;

    reportsCache.length = 0;
    reportsCache.push(...reports);
    container.querySelectorAll('[data-view-report]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.dataset.viewReport, 10);
        if (reportsCache[idx]) showReportPreview(reportsCache[idx]);
      });
    });
  } catch {
    container.innerHTML = '<div class="error-state p-24">Error loading reports.</div>';
  }
}

function showReportPreview(report) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  const panel = document.createElement('div');
  panel.className = 'modal-content';
  panel.style.maxWidth = '760px';
  panel.style.width = '95%';
  panel.style.maxHeight = '85vh';
  panel.style.overflowY = 'auto';

  const type = report.report_type || report.type || 'Report';
  const gen = report.generated_at || report.timestamp;
  const genStr = gen ? new Date(gen).toLocaleString() : '—';
  const range = report.range || report.period || '—';
  const summary = report.summary || {};
  const exec = buildExecutiveSummary(summary, report.period || range);
  const recs = buildRecommendations(summary, report.sections);

  // Build a richer summary bar with risk badge
  const summaryBar = `
    <div style="display:flex;align-items:center;gap:10px;margin:8px 0 4px;">
      <span style="font-size:12px;color:var(--dim)">Security Posture:</span>
      <span style="display:inline-block;padding:3px 12px;border-radius:4px;font-weight:700;font-size:12px;color:#fff;background:${exec.riskColor}">${escapeHtml(exec.riskLevel)}</span>
    </div>
    <div class="report-kpi-bar">
      <div class="report-kpi"><span class="report-kpi-val">${escapeHtml(String(Number(summary.total_events ?? 0).toLocaleString()))}</span><span class="report-kpi-lbl">Events</span></div>
      <div class="report-kpi"><span class="report-kpi-val">${escapeHtml(String(summary.total_alerts ?? 0))}</span><span class="report-kpi-lbl">Alerts</span></div>
      <div class="report-kpi report-kpi--critical"><span class="report-kpi-val">${escapeHtml(String(summary.critical_alerts ?? 0))}</span><span class="report-kpi-lbl">Critical</span></div>
      <div class="report-kpi report-kpi--warn"><span class="report-kpi-val">${escapeHtml(String(summary.high_alerts ?? 0))}</span><span class="report-kpi-lbl">High</span></div>
      <div class="report-kpi"><span class="report-kpi-val">${escapeHtml(String(summary.medium_alerts ?? 0))}</span><span class="report-kpi-lbl">Medium</span></div>
      <div class="report-kpi"><span class="report-kpi-val">${escapeHtml(String(summary.enabled_rules ?? 0))}/${escapeHtml(String(summary.total_rules ?? 0))}</span><span class="report-kpi-lbl">Rules active</span></div>
      <div class="report-kpi"><span class="report-kpi-val">${escapeHtml(String(summary.unique_hosts ?? 0))}</span><span class="report-kpi-lbl">Hosts</span></div>
    </div>`;

  // Executive summary block
  const execHtml = `<div class="report-section">
    <strong class="report-section-title">Executive Summary</strong>
    <div style="padding:10px 14px;background:var(--bg-secondary, #0d1320);border-left:3px solid var(--accent, #3b9cc2);border-radius:0 6px 6px 0;font-size:13px;line-height:1.7;color:var(--text, #c8d6e5);">${exec.narrative}</div>
  </div>`;

  // Build sections from report data
  let richSections = '';
  if (report.sections && typeof report.sections === 'object') {
    for (const [key, val] of Object.entries(report.sections)) {
      if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
        const keys = Object.keys(val[0]);
        richSections += `<div class="report-section">
          <strong class="report-section-title">${escapeHtml(key)}</strong>
          <div class="tableWrap"><table class="tbl tbl-compact"><thead><tr>${keys.map(k => `<th>${escapeHtml(k)}</th>`).join('')}</tr></thead><tbody>
          ${val.slice(0, 30).map(row => `<tr>${keys.map(k => `<td>${escapeHtml(String(row[k] ?? ''))}</td>`).join('')}</tr>`).join('')}
          </tbody></table></div>
        </div>`;
      } else if (Array.isArray(val) && val.length === 0) {
        richSections += `<div class="report-section"><strong class="report-section-title">${escapeHtml(key)}</strong><div class="muted p-8">No data for this period</div></div>`;
      } else if (typeof val === 'object' && !Array.isArray(val)) {
        richSections += `<div class="report-section"><strong class="report-section-title">${escapeHtml(key)}</strong><pre class="code report-pre">${escapeHtml(JSON.stringify(val, null, 2))}</pre></div>`;
      }
    }
  } else if (report.sections) {
    for (const [key, val] of Object.entries(report.sections)) {
      richSections += `<div class="report-section">
        <strong class="report-section-title">${escapeHtml(key)}</strong>
        <pre class="code report-pre">${escapeHtml(typeof val === 'string' ? val : JSON.stringify(val, null, 2))}</pre>
      </div>`;
    }
  } else {
    richSections = `<pre class="code report-pre-full">${escapeHtml(JSON.stringify(report, null, 2))}</pre>`;
  }

  // Recommendations
  const recsHtml = `<div class="report-section">
    <strong class="report-section-title">Recommendations</strong>
    <div style="padding:6px 0;">${recs.map((r, i) => `<div style="padding:4px 0;font-size:13px;"><span style="color:var(--accent);font-weight:700;margin-right:6px;">${i + 1}.</span>${escapeHtml(r)}</div>`).join('')}</div>
  </div>`;

  panel.innerHTML = `
    <div class="report-preview-head">
      <h3 class="report-preview-title">${escapeHtml(type.replace(/_/g,' '))}</h3>
      <button class="btnSm" id="reportPreviewClose">✕</button>
    </div>
    <div class="muted report-preview-meta">Generated: ${escapeHtml(genStr)} · Range: ${escapeHtml(range)}</div>
    ${summaryBar}
    ${execHtml}
    ${richSections}
    ${recsHtml}
    <div class="report-preview-actions">
      <button class="btn" id="reportPreviewCopy">Copy JSON</button>
      <button class="btn" id="reportPreviewPdf">Export PDF</button>
      <button class="btn" id="reportPreviewDocx">Export DOCX</button>
      <button class="btn" id="reportPreviewDone">Close</button>
    </div>`;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  const cleanup = () => { try { overlay.remove(); } catch {} };
  overlay.addEventListener('click', e => { if (e.target === overlay) cleanup(); });
  panel.querySelector('#reportPreviewClose').addEventListener('click', cleanup);
  panel.querySelector('#reportPreviewDone').addEventListener('click', cleanup);
  panel.querySelector('#reportPreviewCopy').addEventListener('click', () => {
    try {
      navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      showToast('Report JSON copied', 'ok');
    } catch { showToast('Copy failed', 'error'); }
  });
  panel.querySelector('#reportPreviewPdf').addEventListener('click', () => exportReportPdf(report));
  panel.querySelector('#reportPreviewDocx').addEventListener('click', () => exportReportDocx(report));
}
