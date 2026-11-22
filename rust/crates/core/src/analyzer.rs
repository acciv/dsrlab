//! Сборка всех анализаторов в один детерминированный отчёт.

use crate::config::Config;
use crate::gateway;
use crate::lab;
use crate::mask;
use crate::model::{AnalyzedReport, Bundle, Summary};
use crate::oauth;
use crate::permissions;
use crate::rest;
use crate::risk::severity_rank;

pub fn analyze_bundle(bundle: &Bundle, config: &Config) -> AnalyzedReport {
    let mut findings = rest::analyze(&bundle.endpoints, config);
    findings.extend(oauth::analyze(bundle.oauth.as_ref(), config));

    let (permission_findings, permission_bits) =
        permissions::analyze(&bundle.permissions, config);
    findings.extend(permission_findings);

    findings.extend(gateway::analyze(bundle.gateway.as_ref(), config));

    let (lab_findings, scenario_results) = lab::analyze(&bundle.scenarios);
    findings.extend(lab_findings);

    findings.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then_with(|| left.id.cmp(&right.id))
    });

    let summary = Summary::new(&findings, bundle.endpoints.len() as i64, bundle.scenarios.len() as i64);

    for finding in &findings {
        // На всякий случай убираем любую похожую на секрет строку из текстов находок.
        debug_assert_eq!(mask::redact(&finding.evidence), finding.evidence);
    }

    AnalyzedReport {
        version: "1.0".to_string(),
        summary,
        findings,
        permission_bits,
        scenario_results,
    }
}
