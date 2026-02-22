use anyhow::{Context, Result};
use percepta_server::percepta::event::{EventCategory, EventOutcome, NetworkDirection};
use percepta_server::percepta::{event::EventDetails, Event};
use regex::{Captures, Regex, RegexSet};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct ParsersFile {
    #[serde(default)]
    parsers: Vec<ParserDef>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct ParserDef {
    id: String,

    #[serde(default)]
    name: String,

    #[serde(default)]
    enabled: bool,

    #[serde(default)]
    parent: Option<String>,

    // High-level source type (syslog/file/auditd/windows_event_log/etc.).
    #[serde(default)]
    source: Option<String>,

    // Windows/syslog channel selector (best-effort; depends on what agents provide).
    #[serde(default)]
    channel: Option<String>,

    // Optional event ID gate (primarily for Windows channels like Sysmon/Defender).
    #[serde(default)]
    event_ids: Vec<u64>,

    // syslog-ish selectors (best-effort; depends on what agents provide).
    #[serde(default)]
    program: Option<String>,

    #[serde(default)]
    facility: Option<String>,

    // file-ish selector (agents might not send this).
    #[serde(default)]
    file_path: Option<String>,

    // Single pattern form (apache/nginx).
    #[serde(default)]
    pattern: Option<String>,

    // Multi-pattern form.
    #[serde(default)]
    patterns: Vec<PatternDef>,

    // Fields associated with the single-pattern form.
    #[serde(default)]
    fields: HashMap<String, String>,

    // Windows-specific mapping block (handled elsewhere).
    #[serde(default)]
    field_mappings: HashMap<u64, HashMap<String, String>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PatternDef {
    regex: String,
    #[serde(default)]
    fields: HashMap<String, String>,
}

fn merge_parent_parser(child: &ParserDef, parent: &ParserDef) -> ParserDef {
    let mut fields = parent.fields.clone();
    fields.extend(child.fields.clone());

    let mut field_mappings = parent.field_mappings.clone();
    for (event_id, mapping) in &child.field_mappings {
        field_mappings
            .entry(*event_id)
            .and_modify(|existing| existing.extend(mapping.clone()))
            .or_insert_with(|| mapping.clone());
    }

    ParserDef {
        id: child.id.clone(),
        name: if child.name.trim().is_empty() {
            parent.name.clone()
        } else {
            child.name.clone()
        },
        enabled: child.enabled,
        parent: child.parent.clone(),
        source: child.source.clone().or_else(|| parent.source.clone()),
        channel: child.channel.clone().or_else(|| parent.channel.clone()),
        event_ids: if child.event_ids.is_empty() {
            parent.event_ids.clone()
        } else {
            child.event_ids.clone()
        },
        program: child.program.clone().or_else(|| parent.program.clone()),
        facility: child.facility.clone().or_else(|| parent.facility.clone()),
        file_path: child.file_path.clone().or_else(|| parent.file_path.clone()),
        pattern: child.pattern.clone().or_else(|| parent.pattern.clone()),
        patterns: if child.patterns.is_empty() {
            parent.patterns.clone()
        } else {
            child.patterns.clone()
        },
        fields,
        field_mappings,
    }
}

fn resolve_parser_def(
    parser: &ParserDef,
    defs_by_id: &HashMap<String, ParserDef>,
    visiting: &mut HashSet<String>,
) -> ParserDef {
    let Some(parent_id) = parser.parent.as_deref() else {
        return parser.clone();
    };

    if !visiting.insert(parser.id.clone()) {
        tracing::warn!(
            "Decoder hierarchy cycle detected for parser '{}' (parent '{}'); using child-only definition",
            parser.id,
            parent_id
        );
        return parser.clone();
    }

    let out = if let Some(parent) = defs_by_id.get(parent_id) {
        let parent_resolved = resolve_parser_def(parent, defs_by_id, visiting);
        merge_parent_parser(parser, &parent_resolved)
    } else {
        tracing::warn!(
            "Decoder parser '{}' references missing parent '{}'; using child-only definition",
            parser.id,
            parent_id
        );
        parser.clone()
    };

    visiting.remove(&parser.id);
    out
}

#[derive(Clone)]
struct CompiledPattern {
    re: Regex,
    fields: HashMap<String, String>,
}

#[derive(Clone)]
struct CompiledParser {
    id: String,
    name: String,
    source: Option<String>,
    channel: Option<String>,
    event_ids: Vec<u64>,
    program: Option<String>,
    facility: Option<String>,
    file_path: Option<String>,
    patterns: Vec<CompiledPattern>,
    regex_set: Option<RegexSet>,
}

/// A Wazuh-style decoder engine:
/// - Compiles regex patterns once at startup
/// - Matches on `event.event.original_message`
/// - Maps capture groups into structured fields + metadata
/// - Avoids overwriting fields that are already populated by the agent
#[derive(Clone, Default)]
pub struct DecoderEngine {
    parsers: Vec<CompiledParser>,
    route_by_source: HashMap<String, Vec<usize>>,
    route_by_channel: HashMap<String, Vec<usize>>,
    route_by_program: HashMap<String, Vec<usize>>,
    route_by_event_id: HashMap<u64, Vec<usize>>,
    generic_parser_indices: Vec<usize>,
}

impl DecoderEngine {
    #[allow(dead_code)]
    pub async fn load_from_file(path: &Path) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read parsers file: {}", path.display()))?;

        let parsed: ParsersFile = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse parsers file: {}", path.display()))?;

        let defs_by_id: HashMap<String, ParserDef> = parsed
            .parsers
            .iter()
            .cloned()
            .map(|p| (p.id.clone(), p))
            .collect();

        let mut parsers = Vec::new();

        for raw in parsed.parsers {
            let mut visiting = HashSet::new();
            let p = resolve_parser_def(&raw, &defs_by_id, &mut visiting);
            if !p.enabled {
                continue;
            }

            // Windows mappings are handled by `WindowsEventMappings`.
            if p.id == "windows_security" || !p.field_mappings.is_empty() {
                continue;
            }

            let mut compiled_patterns: Vec<CompiledPattern> = Vec::new();
            let mut regex_sources: Vec<String> = Vec::new();

            if let Some(re_s) = p.pattern.as_deref().filter(|s| !s.trim().is_empty()) {
                let re = Regex::new(re_s).with_context(|| {
                    format!("Invalid regex in parser {} (pattern): {}", p.id, re_s)
                })?;
                regex_sources.push(re_s.to_string());
                compiled_patterns.push(CompiledPattern {
                    re,
                    fields: p.fields.clone(),
                });
            }

            for pat in &p.patterns {
                let re_s = pat.regex.trim();
                if re_s.is_empty() {
                    continue;
                }
                let re = Regex::new(re_s)
                    .with_context(|| format!("Invalid regex in parser {}: {}", p.id, re_s))?;
                regex_sources.push(re_s.to_string());
                compiled_patterns.push(CompiledPattern {
                    re,
                    fields: pat.fields.clone(),
                });
            }

            if compiled_patterns.is_empty() {
                continue;
            }

            let id = p.id;
            let regex_set = if regex_sources.len() > 1 {
                Some(RegexSet::new(&regex_sources).with_context(|| {
                    format!("Invalid regex set in parser {}", id)
                })?)
            } else {
                None
            };
            parsers.push(CompiledParser {
                id: id.clone(),
                name: if p.name.trim().is_empty() { id } else { p.name },
                source: p
                    .source
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                channel: p
                    .channel
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                event_ids: p.event_ids,
                program: p
                    .program
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                facility: p
                    .facility
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                file_path: p
                    .file_path
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                patterns: compiled_patterns,
                regex_set,
            });
        }

        let mut route_by_source: HashMap<String, Vec<usize>> = HashMap::new();
        let mut route_by_channel: HashMap<String, Vec<usize>> = HashMap::new();
        let mut route_by_program: HashMap<String, Vec<usize>> = HashMap::new();
        let mut route_by_event_id: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut generic_parser_indices: Vec<usize> = Vec::new();

        for (idx, parser) in parsers.iter().enumerate() {
            if let Some(src) = parser.source.as_deref() {
                route_by_source
                    .entry(src.trim().to_lowercase())
                    .or_default()
                    .push(idx);
            }
            if let Some(channel) = parser.channel.as_deref() {
                route_by_channel
                    .entry(channel.trim().to_lowercase())
                    .or_default()
                    .push(idx);
            }
            if let Some(program) = parser.program.as_deref() {
                route_by_program
                    .entry(program.trim().to_lowercase())
                    .or_default()
                    .push(idx);
            }

            for event_id in &parser.event_ids {
                route_by_event_id.entry(*event_id).or_default().push(idx);
            }

            if parser.source.is_none()
                && parser.channel.is_none()
                && parser.program.is_none()
                && parser.event_ids.is_empty()
            {
                generic_parser_indices.push(idx);
            }
        }

        Ok(Self {
            parsers,
            route_by_source,
            route_by_channel,
            route_by_program,
            route_by_event_id,
            generic_parser_indices,
        })
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    pub fn apply(&self, event: &mut Event) {
        // Copy the message out so we can mutably borrow `event` during field application.
        let msg: String = event
            .event
            .as_ref()
            .map(|e| e.original_message.clone())
            .unwrap_or_default();
        if msg.trim().is_empty() {
            return;
        }

        let candidate_indices = self.route_candidates(event, &msg);

        for idx in candidate_indices {
            let parser = &self.parsers[idx];
            if !parser_applies(parser, event, &msg) {
                continue;
            }

            if let Some(regex_set) = &parser.regex_set {
                let matched = regex_set.matches(&msg);
                if !matched.matched_any() {
                    continue;
                }
                for pattern_idx in matched.iter() {
                    if let Some(pat) = parser.patterns.get(pattern_idx) {
                        if let Some(caps) = pat.re.captures(&msg) {
                            apply_decoder_match(event, parser, pattern_idx, &caps, &pat.fields);
                            return;
                        }
                    }
                }
            } else {
                for (pattern_idx, pat) in parser.patterns.iter().enumerate() {
                    if let Some(caps) = pat.re.captures(&msg) {
                        apply_decoder_match(event, parser, pattern_idx, &caps, &pat.fields);
                        return; // First-match wins (Wazuh-style ordering)
                    }
                }
            }
        }
    }

    fn route_candidates(&self, event: &Event, original_message: &str) -> Vec<usize> {
        if self.parsers.is_empty() {
            return Vec::new();
        }

        let mut candidates: Vec<usize> = Vec::new();

        let provider_lc = event
            .event
            .as_ref()
            .map(|e| e.provider.trim().to_lowercase())
            .unwrap_or_default();
        if !provider_lc.is_empty() {
            if provider_lc.contains("windows") || provider_lc.contains("security") {
                if let Some(v) = self.route_by_source.get("windows_event_log") {
                    candidates.extend(v.iter().copied());
                }
            }
            if provider_lc == "syslog" || provider_lc == "auth.log" || provider_lc == "journald" {
                if let Some(v) = self.route_by_source.get("syslog") {
                    candidates.extend(v.iter().copied());
                }
            }
        }

        let channel_lc = event
            .metadata
            .get("winlog.channel")
            .or_else(|| event.metadata.get("channel"))
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        if !channel_lc.is_empty() {
            if let Some(v) = self.route_by_channel.get(&channel_lc) {
                candidates.extend(v.iter().copied());
            }
        }

        let event_id = event
            .event
            .as_ref()
            .map(|e| e.event_id)
            .unwrap_or(0)
            .max(
                event
                    .metadata
                    .get("winlog.event_id")
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0),
            );
        if event_id > 0 {
            if let Some(v) = self.route_by_event_id.get(&event_id) {
                candidates.extend(v.iter().copied());
            }
        }

        let proc_lc = event
            .process
            .as_ref()
            .map(|p| p.name.trim().to_lowercase())
            .unwrap_or_default();
        let journald_ident_lc = event
            .metadata
            .get("linux.journald.syslog_identifier")
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        let syslog_prog_lc = extract_syslog_program(original_message)
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        for key in [proc_lc, journald_ident_lc, syslog_prog_lc] {
            if key.is_empty() {
                continue;
            }
            if let Some(v) = self.route_by_program.get(&key) {
                candidates.extend(v.iter().copied());
            }
        }

        if candidates.is_empty() {
            if !self.generic_parser_indices.is_empty() {
                return self.generic_parser_indices.clone();
            }
            return (0..self.parsers.len()).collect();
        }

        if !self.generic_parser_indices.is_empty() {
            candidates.extend(self.generic_parser_indices.iter().copied());
        }

        let mut seen = HashSet::new();
        let mut ordered = Vec::with_capacity(candidates.len());
        for idx in candidates {
            if seen.insert(idx) {
                ordered.push(idx);
            }
        }
        ordered
    }
}

/// Candidate locations for `parsers.yaml` relative to CWD / crate directory.
#[allow(dead_code)]
fn candidate_paths() -> [PathBuf; 3] {
    [
        PathBuf::from("parsers.yaml"),
        PathBuf::from("server/parsers.yaml"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parsers.yaml"),
    ]
}

/// Return the first existing `parsers.yaml` path, if any.
#[allow(dead_code)]
pub async fn best_effort_path() -> Option<PathBuf> {
    for path in candidate_paths() {
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Some(path);
        }
    }
    None
}

fn parser_applies(parser: &CompiledParser, event: &Event, original_message: &str) -> bool {
    // Optional event-id gating.
    if !parser.event_ids.is_empty() {
        let have = event.event.as_ref().map(|e| e.event_id).unwrap_or(0).max(
            event
                .metadata
                .get("winlog.event_id")
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0),
        );
        if have == 0 || !parser.event_ids.contains(&have) {
            return false;
        }
    }

    // Best-effort channel gating (useful for Windows Sysmon / specific channels).
    if let Some(want) = parser.channel.as_deref() {
        let want_lc = want.trim().to_lowercase();
        let have_lc = event
            .metadata
            .get("winlog.channel")
            .or_else(|| event.metadata.get("channel"))
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        if !want_lc.is_empty() && have_lc != want_lc {
            return false;
        }
    }

    // Conservative gating: if program is specified, require we can match it.
    if let Some(want) = parser.program.as_deref() {
        let want_lc = want.to_lowercase();
        let proc_lc = event
            .process
            .as_ref()
            .map(|p| p.name.trim().to_lowercase())
            .unwrap_or_default();
        let journald_ident_lc = event
            .metadata
            .get("linux.journald.syslog_identifier")
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();

        let msg_prog_lc = extract_syslog_program(original_message)
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        if proc_lc != want_lc && journald_ident_lc != want_lc && msg_prog_lc != want_lc {
            return false;
        }
    }

    // Best-effort source gating.
    if let Some(src) = parser.source.as_deref() {
        let src_lc = src.trim().to_lowercase();
        if src_lc == "syslog" {
            let provider_lc = event
                .event
                .as_ref()
                .map(|e| e.provider.trim().to_lowercase())
                .unwrap_or_default();
            if provider_lc != "syslog" && provider_lc != "auth.log" && provider_lc != "journald" {
                // Still allow if agent OS is linux and provider is unknown.
                let is_linux = event
                    .agent
                    .as_ref()
                    .and_then(|a| a.os.as_ref())
                    .map(|os| os.name.to_lowercase().contains("linux"))
                    .unwrap_or(false);
                if !is_linux {
                    return false;
                }
            }
        } else if src_lc == "windows_event_log" {
            let is_windows = event.metadata.keys().any(|k| k.starts_with("winlog."))
                || event
                    .metadata
                    .get("channel")
                    .or_else(|| event.metadata.get("winlog.channel"))
                    .map(|s| s.to_lowercase().contains("windows"))
                    .unwrap_or(false)
                || event
                    .event
                    .as_ref()
                    .map(|e| {
                        let p = e.provider.to_lowercase();
                        p.contains("windows") || p.contains("security")
                    })
                    .unwrap_or(false);
            if !is_windows {
                return false;
            }
        } else if src_lc == "json" {
            let t = original_message.trim_start();
            if !t.starts_with('{') && !t.starts_with('[') {
                return false;
            }
        }
    }

    // Facility gating (best-effort). Only enforce if we can determine a facility value.
    if let Some(want) = parser.facility.as_deref() {
        let want_lc = want.trim().to_lowercase();
        let have_lc = event
            .metadata
            .get("syslog.facility")
            .or_else(|| event.metadata.get("facility"))
            .map(|s| s.trim().to_lowercase())
            .or_else(|| extract_syslog_facility(original_message).map(|s| s.to_lowercase()))
            .unwrap_or_default();
        if !want_lc.is_empty() && !have_lc.is_empty() && have_lc != want_lc {
            return false;
        }
    }

    // File-path gating (best-effort). Only enforce if a file path is present.
    if let Some(want) = parser.file_path.as_deref() {
        let want_lc = want.trim().to_lowercase();
        let have_lc = event
            .metadata
            .get("log.file.path")
            .or_else(|| event.metadata.get("file.path"))
            .or_else(|| event.metadata.get("event.file.path"))
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        if !want_lc.is_empty() && !have_lc.is_empty() && have_lc != want_lc {
            return false;
        }
    }

    true
}

fn extract_syslog_program(original_message: &str) -> Option<String> {
    // Best-effort program extraction from classic syslog lines.
    // Example: "Jan 14 12:34:56 host sshd[123]: Failed password ..."
    // We keep this conservative and only use it for decoder gating (not for rewriting event fields).
    let s = original_message.trim();
    if s.is_empty() {
        return None;
    }

    // Month day time host program[pid]: msg
    // Capture program.
    static SYSLOG_RE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(
            r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([^\s\[]+)(?:\[\d+\])?:\s",
        )
        .unwrap()
    });

    let caps = SYSLOG_RE.captures(s)?;
    let prog = caps.get(1)?.as_str().trim();
    if prog.is_empty() {
        None
    } else {
        Some(prog.to_string())
    }
}

fn extract_syslog_facility(original_message: &str) -> Option<String> {
    // Best-effort facility extraction from RFC5424/3164 PRI prefix: "<PRI>".
    // Facility = PRI / 8, Severity = PRI % 8.
    let s = original_message.trim_start();
    if !s.starts_with('<') {
        return None;
    }
    let end = s.find('>')?;
    let pri_str = &s[1..end];
    let pri: i32 = pri_str.parse().ok()?;
    if pri < 0 {
        return None;
    }
    let facility = pri / 8;
    let name = match facility {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        12 => "ntp",
        13 => "security",
        14 => "console",
        15 => "solaris-cron",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7",
        _ => "",
    };
    if name.is_empty() {
        Some(facility.to_string())
    } else {
        Some(name.to_string())
    }
}

fn apply_decoder_match(
    event: &mut Event,
    parser: &CompiledParser,
    pattern_idx: usize,
    caps: &Captures,
    fields: &HashMap<String, String>,
) {
    // Identify decoder (non-destructive; keep first match).
    if !event.metadata.contains_key("decoder.id") {
        event
            .metadata
            .insert("decoder.id".to_string(), parser.id.clone());
        event
            .metadata
            .insert("decoder.name".to_string(), parser.name.clone());
        event
            .metadata
            .insert("decoder.pattern_index".to_string(), pattern_idx.to_string());
    }

    if !event
        .tags
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&parser.id))
    {
        event.tags.push(parser.id.clone());
    }

    for (field, template) in fields {
        let value = if let Some(arg) = template
            .strip_prefix("extract(")
            .and_then(|s| s.strip_suffix(')'))
        {
            extract_from_metadata(event, arg).unwrap_or_default()
        } else if let Some(arg) = template
            .strip_prefix("extract_list(")
            .and_then(|s| s.strip_suffix(')'))
        {
            extract_from_metadata(event, arg).unwrap_or_default()
        } else {
            expand_template(template, caps)
        };

        if value.trim().is_empty() {
            continue;
        }
        apply_field(event, field, &value);
    }
}

fn extract_from_metadata(event: &Event, key: &str) -> Option<String> {
    let k = key.trim();
    if k.is_empty() {
        return None;
    }

    // Allow either full metadata keys (winlog.event_data.X) or short forms (X).
    let mut candidates: Vec<String> = Vec::with_capacity(4);
    candidates.push(k.to_string());
    if !k.starts_with("winlog.event_data.") {
        candidates.push(format!("winlog.event_data.{}", k));
    }
    if !k.starts_with("winlog.") {
        candidates.push(format!("winlog.{}", k));
    }
    // Common alternative key name used by some collectors.
    if k.eq_ignore_ascii_case("path") {
        candidates.push("file.path".to_string());
    }

    for c in candidates {
        if let Some(v) = event.metadata.get(&c) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn expand_template(template: &str, caps: &Captures) -> String {
    // Wazuh-like $1 substitution + ${name} for named capture groups.
    let mut out = template.to_string();

    // Named groups: ${group}
    static NAMED_RE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());
    out = NAMED_RE
        .replace_all(&out, |c: &regex::Captures| {
            caps.name(&c[1]).map(|m| m.as_str()).unwrap_or("")
        })
        .to_string();

    // Numbered groups: $1..$N (caps[0] is full match; numbered captures start at 1)
    for idx in 1..caps.len() {
        let key = format!("${}", idx);
        let repl = caps.get(idx).map(|m| m.as_str()).unwrap_or("");
        if out.contains(&key) {
            out = out.replace(&key, repl);
        }
    }

    out.trim().to_string()
}

fn apply_field(event: &mut Event, field: &str, value: &str) {
    match field {
        "event.category" => {
            if let Some(cat) = parse_event_category(value) {
                let details = event.event.get_or_insert_with(default_details);
                if details.category == EventCategory::CategoryUnknown as i32 {
                    details.category = cat as i32;
                }
            }
        }
        "event.action" => {
            let details = event.event.get_or_insert_with(default_details);
            if details.action.trim().is_empty() {
                details.action = value.to_string();
            }
        }
        "event.outcome" => {
            if let Some(outcome) = parse_event_outcome(value) {
                let details = event.event.get_or_insert_with(default_details);
                if details.outcome == EventOutcome::OutcomeUnknown as i32 {
                    details.outcome = outcome as i32;
                }
            }
        }
        "event.summary" => {
            let details = event.event.get_or_insert_with(default_details);
            if details.summary.trim().is_empty() {
                details.summary = value.to_string();
            }
        }
        "event.provider" => {
            let details = event.event.get_or_insert_with(default_details);
            if details.provider.trim().is_empty() {
                details.provider = value.to_string();
            }
        }
        "event.level" => {
            let details = event.event.get_or_insert_with(default_details);
            if details.level.trim().is_empty() {
                details.level = value.to_string();
            }
        }
        "event.severity" => {
            if let Ok(severity) = value.trim().parse::<i32>() {
                let details = event.event.get_or_insert_with(default_details);
                if details.severity == 0 {
                    details.severity = severity.clamp(0, 10);
                }
            }
        }
        "event.event_id" => {
            if let Ok(event_id) = value.trim().parse::<u64>() {
                let details = event.event.get_or_insert_with(default_details);
                if details.event_id == 0 {
                    details.event_id = event_id;
                }
            }
        }
        "event.record_id" => {
            if let Ok(record_id) = value.trim().parse::<u64>() {
                let details = event.event.get_or_insert_with(default_details);
                if details.record_id == 0 {
                    details.record_id = record_id;
                }
            }
        }
        "event.original_message" => {
            let details = event.event.get_or_insert_with(default_details);
            if details.original_message.trim().is_empty() {
                details.original_message = value.to_string();
            }
        }

        "user.name" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.name.trim().is_empty() {
                user.name = value.to_string();
            }
        }
        "user.domain" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.domain.trim().is_empty() {
                user.domain = value.to_string();
            }
        }
        "user.id" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.id.trim().is_empty() {
                user.id = value.to_string();
            }
        }
        "user.privileges" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.privileges.is_empty() {
                let items = value
                    .split([';', ',', '\n'])
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                if !items.is_empty() {
                    user.privileges = items;
                }
            }
        }

        "network.src_ip" => {
            if let Some(ip) = parse_valid_ip(value) {
                let net = event.network.get_or_insert_with(Default::default);
                if net.src_ip.trim().is_empty() {
                    net.src_ip = ip;
                }
            }
        }
        "network.dst_ip" => {
            if let Some(ip) = parse_valid_ip(value) {
                let net = event.network.get_or_insert_with(Default::default);
                if net.dst_ip.trim().is_empty() {
                    net.dst_ip = ip;
                }
            }
        }
        "network.src_port" => {
            if let Ok(p) = value.trim().parse::<u32>() {
                if (1..=65535).contains(&p) {
                    let net = event.network.get_or_insert_with(Default::default);
                    if net.src_port == 0 {
                        net.src_port = p;
                    }
                }
            }
        }
        "network.dst_port" => {
            if let Ok(p) = value.trim().parse::<u32>() {
                if (1..=65535).contains(&p) {
                    let net = event.network.get_or_insert_with(Default::default);
                    if net.dst_port == 0 {
                        net.dst_port = p;
                    }
                }
            }
        }
        "network.protocol" => {
            let net = event.network.get_or_insert_with(Default::default);
            if net.protocol.trim().is_empty() {
                net.protocol = value.to_string();
            }
        }
        "network.direction" => {
            if let Some(dir) = parse_network_direction(value) {
                let net = event.network.get_or_insert_with(Default::default);
                if net.direction == NetworkDirection::DirUnknown as i32 {
                    net.direction = dir as i32;
                }
            }
        }

        "process.name" => {
            let proc_ = event.process.get_or_insert_with(Default::default);
            if proc_.name.trim().is_empty() {
                proc_.name = value.to_string();
            }
        }
        "process.command_line" => {
            let proc_ = event.process.get_or_insert_with(Default::default);
            if proc_.command_line.trim().is_empty() {
                proc_.command_line = value.to_string();
            }
        }
        "process.pid" => {
            if let Ok(pid) = value.trim().parse::<u32>() {
                let proc_ = event.process.get_or_insert_with(Default::default);
                if proc_.pid == 0 {
                    proc_.pid = pid;
                }
            }
        }
        "process.ppid" => {
            if let Ok(ppid) = value.trim().parse::<u32>() {
                let proc_ = event.process.get_or_insert_with(Default::default);
                if proc_.ppid == 0 {
                    proc_.ppid = ppid;
                }
            }
        }

        "file.path" => {
            let f = event.file.get_or_insert_with(Default::default);
            if f.path.trim().is_empty() {
                f.path = value.to_string();
            }
        }
        "file.operation" => {
            if let Some(op) = parse_file_operation(value) {
                let f = event.file.get_or_insert_with(Default::default);
                if f.operation == 0 {
                    f.operation = op as i32;
                }
            }
        }
        "registry.path" => {
            let r = event.registry.get_or_insert_with(Default::default);
            if r.path.trim().is_empty() {
                r.path = value.to_string();
            }
        }
        "registry.value" => {
            let r = event.registry.get_or_insert_with(Default::default);
            if r.value.trim().is_empty() {
                r.value = value.to_string();
            }
        }

        "threat_indicator" => {
            if event.threat_indicator.trim().is_empty() {
                event.threat_indicator = value.to_string();
            }
        }
        "threat_source" => {
            if event.threat_source.trim().is_empty() {
                event.threat_source = value.to_string();
            }
        }

        // Unknown fields go to metadata.
        _ => {
            if let Some(meta_key) = field.strip_prefix("metadata.") {
                if !meta_key.trim().is_empty() {
                    event
                        .metadata
                        .entry(meta_key.to_string())
                        .or_insert_with(|| value.to_string());
                    return;
                }
            }
            if let Some(meta_key) = field.strip_prefix("meta.") {
                if !meta_key.trim().is_empty() {
                    event
                        .metadata
                        .entry(meta_key.to_string())
                        .or_insert_with(|| value.to_string());
                    return;
                }
            }
            if let Some(tag) = field.strip_prefix("tag.") {
                let tag = tag.trim();
                if !tag.is_empty() && !event.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                    event.tags.push(tag.to_string());
                }
                return;
            }
            event
                .metadata
                .entry(field.to_string())
                .or_insert_with(|| value.to_string());
        }
    }
}

fn default_details() -> EventDetails {
    EventDetails {
        summary: String::new(),
        original_message: String::new(),
        category: EventCategory::CategoryUnknown as i32,
        action: String::new(),
        outcome: EventOutcome::OutcomeUnknown as i32,
        level: String::new(),
        severity: 0,
        provider: String::new(),
        event_id: 0,
        record_id: 0,
    }
}

fn parse_event_category(s: &str) -> Option<EventCategory> {
    match s.trim().to_uppercase().as_str() {
        "AUTH" => Some(EventCategory::Auth),
        "NETWORK" => Some(EventCategory::Network),
        "FILE" => Some(EventCategory::File),
        "PROCESS" => Some(EventCategory::Process),
        "REGISTRY" => Some(EventCategory::Registry),
        "SYSTEM" => Some(EventCategory::System),
        "OTHER" => Some(EventCategory::Other),
        _ => None,
    }
}

fn parse_event_outcome(s: &str) -> Option<EventOutcome> {
    match s.trim().to_uppercase().as_str() {
        "SUCCESS" | "ALLOW" | "ALLOWED" | "ACCEPT" | "PERMIT" => Some(EventOutcome::Success),
        "FAILURE" | "FAIL" | "ERROR" => Some(EventOutcome::Failure),
        "BLOCKED" | "BLOCK" | "DENY" | "DENIED" | "DROP" | "DROPPED" => Some(EventOutcome::Blocked),
        _ => None,
    }
}

fn parse_network_direction(s: &str) -> Option<NetworkDirection> {
    match s.trim().to_uppercase().as_str() {
        "INBOUND" | "IN" | "INGRESS" => Some(NetworkDirection::Inbound),
        "OUTBOUND" | "OUT" | "EGRESS" => Some(NetworkDirection::Outbound),
        "LATERAL" | "INTERNAL" => Some(NetworkDirection::Lateral),
        _ => None,
    }
}

fn parse_file_operation(s: &str) -> Option<percepta_server::percepta::event::FileOperation> {
    use percepta_server::percepta::event::FileOperation;
    match s.trim().to_uppercase().as_str() {
        "CREATED" | "CREATE" => Some(FileOperation::Created),
        "DELETED" | "DELETE" => Some(FileOperation::Deleted),
        "MODIFIED" | "MODIFY" | "CHANGED" => Some(FileOperation::Modified),
        "READ" | "OPEN" => Some(FileOperation::Read),
        _ => None,
    }
}

fn parse_valid_ip(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "-" || t.eq_ignore_ascii_case("unknown") {
        return None;
    }
    let ip: IpAddr = t.parse().ok()?;
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    Some(t.to_string())
}

/// Load decoder engine from the standard candidate locations.
///
/// Best-effort: missing/invalid files should not prevent startup.
#[allow(dead_code)]
pub async fn load_best_effort() -> Arc<DecoderEngine> {
    for path in candidate_paths() {
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            match DecoderEngine::load_from_file(&path).await {
                Ok(m) => {
                    tracing::info!(
                        "Loaded decoder engine from {} (empty={})",
                        path.display(),
                        m.is_empty()
                    );
                    return Arc::new(m);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load decoder engine from {}: {:#}",
                        path.display(),
                        e
                    );
                }
            }
        }
    }

    Arc::new(DecoderEngine::default())
}

#[allow(dead_code)]
async fn file_signature(path: &Path) -> Option<(u64, i64)> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    let len = meta.len();
    let modified = meta.modified().ok()?;
    let modified_unix = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some((len, modified_unix))
}

/// Start a low-overhead hot-reload loop for `parsers.yaml`.
///
/// Mechanism:
/// - Polls file metadata (mtime+size) on a fixed interval.
/// - Only re-reads + recompiles regexes when the signature changes.
///
/// This avoids the "restart manager to apply decoder changes" pain (Wazuh-style issue)
/// while staying resource-light (no hashing and no constant file reads).
#[allow(dead_code)]
pub fn start_hot_reload(decoder: Arc<parking_lot::RwLock<DecoderEngine>>) {
    percepta_server::spawn_monitored("decoder-hot-reload", async move {
        let mut current_path: Option<PathBuf> = best_effort_path().await;
        let mut last_sig: Option<(u64, i64)> = match current_path.as_deref() {
            Some(p) => file_signature(p).await,
            None => None,
        };

        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;

            // If we didn't have a file at startup, keep looking (allows operators to create it later).
            if current_path.is_none() {
                current_path = best_effort_path().await;
                if let Some(p) = current_path.as_deref() {
                    last_sig = file_signature(p).await;
                }
                continue;
            }

            let Some(path) = current_path.as_deref() else {
                continue;
            };
            let sig = file_signature(path).await;
            if sig.is_none() {
                // File was removed; keep the last loaded decoder set but keep searching.
                tracing::warn!(
                    "Decoder config disappeared: {} (keeping last loaded decoders)",
                    path.display()
                );
                current_path = None;
                last_sig = None;
                continue;
            }

            if sig == last_sig {
                continue;
            }

            match DecoderEngine::load_from_file(path).await {
                Ok(new_engine) => {
                    let empty = new_engine.is_empty();
                    *decoder.write() = new_engine;
                    last_sig = sig;
                    tracing::info!(
                        "Reloaded decoders from {} (empty={})",
                        path.display(),
                        empty
                    );
                }
                Err(e) => {
                    // Keep last known-good engine on parse/regex errors.
                    tracing::warn!(
                        "Failed to reload decoders from {} (keeping last): {:#}",
                        path.display(),
                        e
                    );
                    // Update last_sig anyway? No: keep retrying on every tick until fixed.
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_template_groups() {
        let re = Regex::new(r"Failed password for (\S+) from (\S+) port (\d+)").unwrap();
        let caps = re
            .captures("Failed password for bob from 1.2.3.4 port 2222")
            .expect("match");
        assert_eq!(expand_template("$1", &caps), "bob");
        assert_eq!(expand_template("$2:$3", &caps), "1.2.3.4:2222");
    }

    #[test]
    fn applies_linux_auth_fields_without_overwrite() {
        let mut engine = DecoderEngine::default();
        engine.parsers.push(CompiledParser {
            id: "linux_auth".to_string(),
            name: "Linux Authentication Logs".to_string(),
            source: Some("syslog".to_string()),
            channel: None,
            event_ids: Vec::new(),
            program: Some("sshd".to_string()),
            facility: None,
            file_path: None,
            patterns: vec![CompiledPattern {
                re: Regex::new(
                    r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
                )
                .unwrap(),
                fields: HashMap::from([
                    ("event.category".to_string(), "AUTH".to_string()),
                    ("event.action".to_string(), "logon".to_string()),
                    ("event.outcome".to_string(), "FAILURE".to_string()),
                    ("user.name".to_string(), "$1".to_string()),
                    ("network.src_ip".to_string(), "$2".to_string()),
                    ("network.src_port".to_string(), "$3".to_string()),
                ]),
            }],
        });

        let mut e = Event::default();
        e.event = Some(EventDetails {
            summary: "".to_string(),
            original_message:
                "sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 2222 ssh2"
                    .to_string(),
            category: EventCategory::CategoryUnknown as i32,
            action: "".to_string(),
            outcome: EventOutcome::OutcomeUnknown as i32,
            level: "Info".to_string(),
            severity: 1,
            provider: "auth.log".to_string(),
            event_id: 0,
            record_id: 0,
        });
        e.process = Some(percepta_server::percepta::event::Process {
            pid: 123,
            ppid: 0,
            name: "sshd".to_string(),
            command_line: "".to_string(),
            hash: HashMap::new(),
        });
        e.user = Some(percepta_server::percepta::event::User {
            id: "".to_string(),
            name: "already".to_string(),
            domain: "".to_string(),
            privileges: vec![],
        });

        engine.apply(&mut e);

        // User name should not be overwritten.
        assert_eq!(e.user.as_ref().unwrap().name, "already");

        // Network should be populated.
        assert_eq!(e.network.as_ref().unwrap().src_ip, "1.2.3.4");
        assert_eq!(e.network.as_ref().unwrap().src_port, 2222);

        // Taxonomy should be set.
        let details = e.event.as_ref().unwrap();
        assert_eq!(details.category, EventCategory::Auth as i32);
        assert_eq!(details.action, "logon");
        assert_eq!(details.outcome, EventOutcome::Failure as i32);

        assert_eq!(
            e.metadata.get("decoder.id").map(|s| s.as_str()),
            Some("linux_auth")
        );
    }
}
