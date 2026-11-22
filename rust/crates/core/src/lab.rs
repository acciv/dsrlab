//! Exploit Research Lab: описание сценариев и проверка исправлений.
//!
//! Все проверки выполняются на локальном mock-сервере. Здесь нет сетевого кода:
//! Rust получает уже собранные Python-клиентом результаты и проверяет их логику.

use crate::model::{Finding, Scenario, ScenarioResult};

const VALID_SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

pub fn analyze(scenarios: &[Scenario]) -> (Vec<Finding>, Vec<ScenarioResult>) {
    let mut findings = Vec::new();
    let mut results = Vec::new();

    for scenario in scenarios {
        let missing = [
            ("id", scenario.id.is_empty()),
            ("type", scenario.type_name.is_empty()),
            ("endpoint", scenario.endpoint.is_empty()),
            ("fix_check", scenario.fix_check.is_empty()),
        ]
        .iter()
        .filter(|(_, absent)| *absent)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();

        if !missing.is_empty() {
            findings.push(Finding::new(
                "lab",
                "lab-invalid-scenario",
                "Сценарий лаборатории описан неполно",
                "low",
                &format!("{}: отсутствуют {}", scenario.id, missing.join(", ")),
                "Заполните id, type, endpoint и fix_check в сценарии.",
            ));
        }

        let severity = if VALID_SEVERITIES.contains(&scenario.impact.as_str()) {
            scenario.impact.clone()
        } else {
            "medium".to_string()
        };
        let status = if scenario.fixed {
            "fixed"
        } else {
            "reproduced"
        };
        let notes = if scenario.fixed {
            format!("Проверка исправления: {}", scenario.fix_check)
        } else {
            format!(
                "Локальная симуляция на mock-сервере: {} ({})",
                scenario.title, scenario.endpoint
            )
        };

        results.push(ScenarioResult {
            id: scenario.id.clone(),
            status: status.to_string(),
            severity,
            notes,
        });
    }

    (findings, results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::model::Bundle;

    #[test]
    fn lab_marks_reproduced_and_fixed() {
        let value = json::parse(
            r#"{"scenarios":[
                {"id":"ratelimit-001","type":"rate_limit","title":"429",
                 "endpoint":"/rate-limited","fix_check":"Retry-After","impact":"high","fixed":false},
                {"id":"forbidden-002","type":"permissions","title":"403",
                 "endpoint":"/forbidden","fix_check":"проверка прав","impact":"low","fixed":true}
            ]}"#,
        )
        .unwrap();
        let bundle = Bundle::from_value(&value).unwrap();
        let (findings, results) = analyze(&bundle.scenarios);
        assert!(findings.is_empty());
        assert_eq!(results[0].status, "reproduced");
        assert_eq!(results[0].severity, "high");
        assert_eq!(results[1].status, "fixed");
        assert_eq!(results[1].severity, "low");
    }

    #[test]
    fn lab_reports_invalid_scenario() {
        let scenario = Scenario {
            id: String::new(),
            type_name: String::new(),
            title: "тест".to_string(),
            endpoint: String::new(),
            mock_response: 0,
            expected: String::new(),
            fix_check: String::new(),
            impact: "unknown".to_string(),
            fixed: false,
        };
        let (findings, results) = analyze(&[scenario]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "lab-invalid-scenario");
        assert_eq!(results[0].severity, "medium");
    }
}
