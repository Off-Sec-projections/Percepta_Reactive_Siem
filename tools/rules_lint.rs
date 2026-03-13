use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Clone)]
struct CliArgs {
    file_path: String,
    require_metadata: bool,
    deny_warnings: bool,
    baseline_path: Option<String>,
    write_baseline_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
struct RuleDef {
    id: Option<String>,
    enabled: Option<bool>,
    confidence: Option<f64>,
    risk_score: Option<u64>,
    false_positive_rate: Option<String>,
    #[serde(default)]
    conditions: Vec<ConditionDef>,
    #[serde(default)]
    exceptions: Vec<RuleExceptionDef>,
    sequence: Option<SequenceDef>,
}

#[derive(Debug, Deserialize)]
struct RuleExceptionDef {
    #[serde(default)]
    conditions: Vec<ConditionDef>,
}

#[derive(Debug, Deserialize)]
struct SequenceDef {
    #[serde(default)]
    steps: Vec<SequenceStepDef>,
}

#[derive(Debug, Deserialize)]
struct SequenceStepDef {
    #[serde(default)]
    conditions: Vec<ConditionDef>,
}

#[derive(Debug, Deserialize)]
struct ConditionDef {
    field: Option<String>,
    operator: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum Severity {
    Error,
    Warning,
}

#[derive(Debug)]
struct Finding {
    severity: Severity,
    rule_id: String,
    location: String,
    message: String,
}

fn parse_args() -> Result<CliArgs> {
    let mut file_path = String::from("server/rules.yaml");
    let mut require_metadata = false;
    let mut deny_warnings = false;
    let mut baseline_path: Option<String> = None;
    let mut write_baseline_path: Option<String> = None;

    let mut positional: Vec<String> = Vec::new();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--require-metadata" => require_metadata = true,
            "--deny-warnings" => deny_warnings = true,
            "--baseline" => {
                let Some(v) = iter.next() else {
                    bail!("--baseline requires a file path argument");
                };
                baseline_path = Some(v);
            }
            "--write-baseline" => {
                let Some(v) = iter.next() else {
                    bail!("--write-baseline requires a file path argument");
                };
                write_baseline_path = Some(v);
            }
            "-h" | "--help" => {
                println!(
                    "rules-lint [FILE] [--require-metadata] [--deny-warnings] [--baseline FILE] [--write-baseline FILE]\n\n  FILE                YAML file path (default: server/rules.yaml)\n  --require-metadata  Fail when confidence/risk_score/false_positive_rate are missing\n  --deny-warnings     Treat warnings as failures\n  --baseline FILE     Suppress findings listed in baseline file (fingerprint format)\n  --write-baseline FILE  Write current findings as baseline fingerprints"
                );
                std::process::exit(0);
            }
            _ if arg.starts_with('-') => {
                bail!("Unknown flag: {arg}");
            }
            _ => positional.push(arg),
        }
    }

    if positional.len() > 1 {
        bail!("Expected at most one positional FILE argument");
    }
    if let Some(path) = positional.into_iter().next() {
        file_path = path;
    }

    Ok(CliArgs {
        file_path,
        require_metadata,
        deny_warnings,
        baseline_path,
        write_baseline_path,
    })
}

fn finding_fingerprint(f: &Finding) -> String {
    let sev = match f.severity {
        Severity::Error => "ERROR",
        Severity::Warning => "WARNING",
    };
    format!("{sev}|{}|{}|{}", f.rule_id, f.location, f.message)
}

fn load_baseline(path: &str) -> Result<HashSet<String>> {
    let body = fs::read_to_string(path).with_context(|| format!("read baseline file: {path}"))?;
    let mut out = HashSet::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.insert(t.to_string());
    }
    Ok(out)
}

fn write_baseline(path: &str, findings: &[Finding]) -> Result<()> {
    let mut rows: Vec<String> = findings.iter().map(finding_fingerprint).collect();
    rows.sort();
    rows.dedup();
    let mut body = String::new();
    body.push_str("# rules-lint baseline (auto-generated)\n");
    body.push_str("# Format: SEVERITY|rule_id|location|message\n");
    for r in rows {
        body.push_str(&r);
        body.push('\n');
    }
    fs::write(path, body).with_context(|| format!("write baseline file: {path}"))?;
    Ok(())
}

fn is_regex_too_broad(pattern: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return true;
    }

    const BLOCKED: &[&str] = &[
        ".*", ".+", "^.*$", "^.+$", "(.*)", "(.+)", "(?:.*)", "(?:.+)",
    ];
    if BLOCKED.iter().any(|b| p.eq_ignore_ascii_case(b)) {
        return true;
    }

    let alnum_count = p.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if alnum_count == 0 {
        return true;
    }

    if p.starts_with(".*") && p.ends_with(".*") && alnum_count < 4 {
        return true;
    }

    false
}

fn validate_rule_metadata(rule: &RuleDef, rule_id: &str, findings: &mut Vec<Finding>) {
    let confidence_ok = rule.confidence.map(|c| (0.0..=1.0).contains(&c)).unwrap_or(false);
    let risk_ok = rule.risk_score.map(|r| r <= 100).unwrap_or(false);
    let fp_ok = rule
        .false_positive_rate
        .as_ref()
        .map(|f| matches!(f.trim().to_lowercase().as_str(), "low" | "medium" | "high"))
        .unwrap_or(false);

    if let Some(c) = rule.confidence {
        if !(0.0..=1.0).contains(&c) {
            findings.push(Finding {
                severity: Severity::Error,
                rule_id: rule_id.to_string(),
                location: "confidence".to_string(),
                message: format!("confidence must be in [0,1], got {c}"),
            });
        }
    }

    if let Some(r) = rule.risk_score {
        if r > 100 {
            findings.push(Finding {
                severity: Severity::Error,
                rule_id: rule_id.to_string(),
                location: "risk_score".to_string(),
                message: format!("risk_score must be in [0,100], got {r}"),
            });
        }
    }

    if let Some(fpr) = &rule.false_positive_rate {
        let normalized = fpr.trim().to_lowercase();
        if !matches!(normalized.as_str(), "low" | "medium" | "high") {
            findings.push(Finding {
                severity: Severity::Error,
                rule_id: rule_id.to_string(),
                location: "false_positive_rate".to_string(),
                message: format!(
                    "false_positive_rate must be one of low|medium|high, got {normalized}"
                ),
            });
        }
    }

    if !confidence_ok || !risk_ok || !fp_ok {
        findings.push(Finding {
            severity: Severity::Warning,
            rule_id: rule_id.to_string(),
            location: "quality_metadata".to_string(),
            message:
                "missing or partial quality metadata (confidence/risk_score/false_positive_rate)"
                    .to_string(),
        });
    }
}

fn check_condition_regex(
    rule_id: &str,
    location: &str,
    c: &ConditionDef,
    findings: &mut Vec<Finding>,
) {
    let op = c.operator.as_deref().unwrap_or("").trim().to_lowercase();
    if op != "regex" {
        return;
    }

    let pattern = c.value.as_deref().unwrap_or("").trim().to_string();
    if pattern.is_empty() {
        findings.push(Finding {
            severity: Severity::Error,
            rule_id: rule_id.to_string(),
            location: location.to_string(),
            message: "regex operator requires non-empty value".to_string(),
        });
        return;
    }

    if let Err(err) = Regex::new(&pattern) {
        findings.push(Finding {
            severity: Severity::Error,
            rule_id: rule_id.to_string(),
            location: location.to_string(),
            message: format!("invalid regex `{pattern}`: {err}"),
        });
        return;
    }

    if is_regex_too_broad(&pattern) {
        let field = c.field.clone().unwrap_or_else(|| "<unknown-field>".to_string());
        findings.push(Finding {
            severity: Severity::Warning,
            rule_id: rule_id.to_string(),
            location: location.to_string(),
            message: format!(
                "regex for field `{field}` looks overly broad (`{pattern}`); tighten to reduce FP risk"
            ),
        });
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let body = fs::read_to_string(&args.file_path)
        .with_context(|| format!("read rules file: {}", args.file_path))?;
    let parsed: RulesFile = serde_yaml::from_str(&body)
        .with_context(|| format!("parse YAML rules file: {}", args.file_path))?;

    if parsed.rules.is_empty() {
        return Err(anyhow!("no rules found in `{}` (expected top-level `rules:`)", args.file_path));
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut ids: HashMap<String, usize> = HashMap::new();

    for (idx, rule) in parsed.rules.iter().enumerate() {
        let position = idx + 1;
        let rule_id = match rule.id.as_deref().map(str::trim) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => {
                findings.push(Finding {
                    severity: Severity::Error,
                    rule_id: format!("<index:{position}>"),
                    location: "id".to_string(),
                    message: "rule id is missing or empty".to_string(),
                });
                continue;
            }
        };

        let entry = ids.entry(rule_id.clone()).or_insert(0);
        *entry += 1;

        if rule.enabled.unwrap_or(true) {
            validate_rule_metadata(rule, &rule_id, &mut findings);
        }

        for (c_idx, cond) in rule.conditions.iter().enumerate() {
            let loc = format!("conditions[{c_idx}]");
            check_condition_regex(&rule_id, &loc, cond, &mut findings);
        }

        for (ex_idx, ex) in rule.exceptions.iter().enumerate() {
            for (c_idx, cond) in ex.conditions.iter().enumerate() {
                let loc = format!("exceptions[{ex_idx}].conditions[{c_idx}]");
                check_condition_regex(&rule_id, &loc, cond, &mut findings);
            }
        }

        if let Some(seq) = &rule.sequence {
            for (step_idx, step) in seq.steps.iter().enumerate() {
                for (c_idx, cond) in step.conditions.iter().enumerate() {
                    let loc = format!("sequence.steps[{step_idx}].conditions[{c_idx}]");
                    check_condition_regex(&rule_id, &loc, cond, &mut findings);
                }
            }
        }
    }

    for (id, count) in ids {
        if count > 1 {
            findings.push(Finding {
                severity: Severity::Error,
                rule_id: id,
                location: "id".to_string(),
                message: format!("duplicate rule id appears {count} times"),
            });
        }
    }

    if args.require_metadata {
        for finding in &mut findings {
            if matches!(finding.severity, Severity::Warning)
                && finding.location == "quality_metadata"
            {
                finding.severity = Severity::Error;
                finding.message.push_str(" (strict mode enabled)");
            }
        }
    }

    if let Some(path) = args.write_baseline_path.as_deref() {
        write_baseline(path, &findings)?;
        eprintln!("rules-lint: wrote baseline to {}", path);
    }

    let mut suppressed = 0usize;
    let active_findings: Vec<Finding> = if let Some(path) = args.baseline_path.as_deref() {
        let baseline = load_baseline(path)?;
        findings
            .into_iter()
            .filter(|f| {
                let keep = !baseline.contains(&finding_fingerprint(f));
                if !keep {
                    suppressed += 1;
                }
                keep
            })
            .collect()
    } else {
        findings
    };

    let mut errors = 0usize;
    let mut warnings = 0usize;

    for f in &active_findings {
        match f.severity {
            Severity::Error => {
                errors += 1;
                eprintln!("ERROR   rule={} location={} :: {}", f.rule_id, f.location, f.message);
            }
            Severity::Warning => {
                warnings += 1;
                eprintln!("WARNING rule={} location={} :: {}", f.rule_id, f.location, f.message);
            }
        }
    }

    eprintln!(
        "rules-lint summary: rules={} errors={} warnings={} suppressed={} file={}",
        parsed.rules.len(),
        errors,
        warnings,
        suppressed,
        args.file_path
    );

    if errors > 0 || (args.deny_warnings && warnings > 0) {
        bail!("rules lint failed")
    }

    Ok(())
}
