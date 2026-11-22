//! Анализ RAW-отчёта токен-сканера: риски, дубликаты, группы, статистика.

use crate::config::Config;
use crate::mask::masked;
use crate::model::{RawTokenReport, TokenAnalysisReport, TokenFinding, TokenGroup, TokenSummary};
use crate::risk;
use std::collections::BTreeMap;

fn entropy_bonus(entropy: f64) -> i64 {
    if entropy >= 4.0 {
        30
    } else if entropy >= 3.0 {
        10
    } else {
        0
    }
}

pub fn analyze(raw: &RawTokenReport, config: &Config) -> TokenAnalysisReport {
    let mut sorted: Vec<_> = raw.findings.clone();
    sorted.sort_by(|left, right| {
        (&left.file, left.line, left.column).cmp(&(&right.file, right.line, right.column))
    });

    let mut occurrences: BTreeMap<String, i64> = BTreeMap::new();
    for finding in &sorted {
        *occurrences.entry(finding.fingerprint.clone()).or_insert(0) += 1;
    }

    let mut findings = Vec::new();
    let mut groups: BTreeMap<String, TokenGroup> = BTreeMap::new();
    let mut by_severity: BTreeMap<String, i64> = [
        ("critical".to_string(), 0),
        ("high".to_string(), 0),
        ("low".to_string(), 0),
        ("medium".to_string(), 0),
        ("false_positive".to_string(), 0),
    ]
    .into_iter()
    .collect();

    for (index, item) in sorted.iter().enumerate() {
        let mask = masked(&item.context, item.secret_length);
        let (score, level, duplicate_of) = if item.false_positive {
            (0, "false_positive".to_string(), String::new())
        } else {
            let score = config.risk_weight(&item.context) + entropy_bonus(item.entropy);
            let level = risk::level_for_score(score, config);
            let duplicate_of = if occurrences.get(&item.fingerprint).copied().unwrap_or(0) > 1
                && sorted[..index]
                    .iter()
                    .any(|previous| previous.fingerprint == item.fingerprint)
            {
                item.fingerprint.clone()
            } else {
                String::new()
            };
            (score, level, duplicate_of)
        };
        *by_severity.entry(level.clone()).or_insert(0) += 1;

        findings.push(TokenFinding {
            file: item.file.clone(),
            line: item.line,
            column: item.column,
            fingerprint: item.fingerprint.clone(),
            id_length: item.id_length,
            timestamp_length: item.timestamp_length,
            secret_length: item.secret_length,
            entropy: item.entropy,
            context: item.context.clone(),
            risk_score: score,
            risk_level: level.clone(),
            duplicate_of,
            masked_value: mask.clone(),
        });

        let group = groups.entry(item.fingerprint.clone()).or_insert_with(|| TokenGroup {
            fingerprint: item.fingerprint.clone(),
            occurrences: 0,
            files: Vec::new(),
            risk_level: level.clone(),
            masked_value: mask.clone(),
        });
        group.occurrences += 1;
        if !group.files.contains(&item.file) {
            group.files.push(item.file.clone());
        }
    }

    for group in groups.values_mut() {
        group.files.sort();
    }

    let duplicates = findings.iter().filter(|item| !item.duplicate_of.is_empty()).count();
    let false_positives = findings
        .iter()
        .filter(|item| item.risk_level == "false_positive")
        .count();

    TokenAnalysisReport {
        version: "1.0".to_string(),
        summary: TokenSummary {
            scanned_files: raw.scanned_files,
            skipped_files: raw.skipped_files,
            raw_findings: raw.findings.len() as i64,
            findings: findings.len() as i64,
            duplicates: duplicates as i64,
            false_positives: false_positives as i64,
            by_severity,
        },
        findings,
        groups: groups.into_values().collect(),
    }
}
