//! Ядро Discord API Security Research Lab.
//!
//! Наружу отдаются только детерминированные JSON-отчёты без секретов.

pub mod analyzer;
pub mod config;
pub mod gateway;
pub mod json;
pub mod lab;
pub mod logging;
pub mod mask;
pub mod model;
pub mod oauth;
pub mod permissions;
pub mod rest;
pub mod risk;
pub mod tokens;

use config::Config;
use json::{parse, to_string_pretty};
use model::{Bundle, RawTokenReport};

pub fn version() -> &'static str {
    "dscore 1.0.0"
}

pub fn validate_config_json(config_json: &str) -> Result<(), String> {
    config::validate_value(&parse(config_json)?)
}

pub fn analyze_json(bundle_json: &str, config_json: &str) -> Result<String, String> {
    logging::info("analyze: разбор bundle и конфигурации");
    let bundle = Bundle::from_value(&parse(bundle_json)?)?;
    let config = Config::from_value(&parse(config_json)?)?;
    let report = analyzer::analyze_bundle(&bundle, &config);
    Ok(to_string_pretty(&report.to_value()))
}

pub fn analyze_tokens_json(raw_json: &str, config_json: &str) -> Result<String, String> {
    logging::info("analyze-tokens: разбор RAW и конфигурации");
    let raw = RawTokenReport::from_value(&parse(raw_json)?)?;
    let config = Config::from_value(&parse(config_json)?)?;
    let report = tokens::analyze(&raw, &config);
    let text = to_string_pretty(&report.to_value());
    debug_assert_eq!(mask::redact(&text), text);
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Config, GatewayConfig, RiskLevels};
    use model::{Endpoint, PermissionEntry, Scenario};

    fn config_text() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../configs/default.json");
        std::fs::read_to_string(path).unwrap()
    }

    fn bundle_text() -> String {
        r#"{
          "version":"1.0",
          "endpoints":[
            {"method":"GET","path":"/users/@me","auth":"bearer","rate_limit":"per-route",
             "scopes":["identify"],"errors":[401,403],"description":"текущий пользователь"},
            {"method":"GET","path":"/gateway","auth":"none","rate_limit":"per-route","errors":[401]},
            {"method":"POST","path":"/channels/100000000000000003/messages","auth":"bot",
             "rate_limit":"per-route","errors":[401,403]}
          ],
          "oauth":{"client_id":"100000000000000001",
            "redirect_uris":["http://localhost:8080/callback"],
            "scopes":["identify","email"],"pkce":true,"state":true,
            "token_endpoint_auth_method":"client_secret_basic"},
          "permissions":[{"role":"reader","bits":1024,"scope":"guild"},
            {"role":"bot","bits":8,"scope":"guild"}],
          "gateway":{"version":10,"heartbeat_interval":41250,
            "intents":["GUILDS","GUILD_MESSAGES"],"events":["READY","MESSAGE_CREATE"],
            "reconnect":"exponential-backoff","resume":true},
          "scenarios":[{"id":"ratelimit-001","type":"rate_limit","title":"429",
            "endpoint":"/rate-limited","mock_response":429,"expected":"Retry-After",
            "fix_check":"заголовок есть","impact":"medium","fixed":false}]
        }"#
        .to_string()
    }

    fn test_config() -> Config {
        Config {
            version: "1.0".to_string(),
            exclude_dirs: Vec::new(),
            exclude_extensions: Vec::new(),
            max_file_bytes: 1000,
            max_line_bytes: 1000,
            workers: 1,
            patterns: vec![config::PatternRule {
                id: "discord_bot_token".to_string(),
                pattern_type: "discord_bot_token".to_string(),
                risk_weight: 50,
            }],
            false_positive_markers: vec!["DUMMY".to_string()],
            risk_levels: RiskLevels {
                low: 25,
                medium: 50,
                high: 75,
                critical: 90,
            },
            public_paths: vec!["/gateway".to_string()],
            dangerous_scopes: vec!["guilds.join".to_string()],
            dangerous_permissions: vec!["ADMINISTRATOR".to_string(), "BAN_MEMBERS".to_string()],
            gateway: GatewayConfig {
                heartbeat_min: 1000,
                heartbeat_max: 60000,
                min_version: 10,
            },
        }
    }

    fn raw_text() -> String {
        r#"{
          "scanned_files":3,"skipped_files":0,
          "findings":[
            {"file":"b.py","line":9,"column":4,"fingerprint":"sha256:bb","id_length":18,
             "timestamp_length":6,"secret_length":27,"entropy":4.2,
             "context":"discord_bot_token","false_positive":false},
            {"file":"a.py","line":2,"column":1,"fingerprint":"sha256:aa","id_length":18,
             "timestamp_length":6,"secret_length":27,"entropy":4.2,
             "context":"discord_bot_token","false_positive":false},
            {"file":"c.py","line":3,"column":1,"fingerprint":"sha256:cc","id_length":18,
             "timestamp_length":6,"secret_length":27,"entropy":4.2,
             "context":"discord_bot_token","false_positive":false},
            {"file":"a.py","line":2,"column":40,"fingerprint":"sha256:aa","id_length":18,
             "timestamp_length":6,"secret_length":27,"entropy":4.2,
             "context":"discord_bot_token","false_positive":false}
          ]
        }"#
        .to_string()
    }

    #[test]
    fn version_is_stable() {
        assert_eq!(version(), "dscore 1.0.0");
    }

    #[test]
    fn validate_accepts_default_config() {
        assert!(validate_config_json(&config_text()).is_ok());
    }

    #[test]
    fn validate_rejects_broken_config() {
        assert!(validate_config_json("{\"version\":1}").is_err());
    }

    #[test]
    fn analyze_json_returns_expected_sections() {
        let report = analyze_json(&bundle_text(), &config_text()).unwrap();
        let value = parse(&report).unwrap();
        assert_eq!(value.get("version").unwrap().as_str(), Some("1.0"));
        assert!(value.get("summary").is_some());
        assert!(value.get("findings").is_some());
        assert!(value.get("permission_bits").is_some());
        assert!(value.get("scenario_results").is_some());
    }

    #[test]
    fn analyze_json_flags_admin_permission() {
        let report = analyze_json(&bundle_text(), &config_text()).unwrap();
        assert!(report.contains("perm-admin-granted"));
        assert!(report.contains("critical"));
    }

    #[test]
    fn analyze_json_rejects_bad_bundle() {
        assert!(analyze_json("[]", &config_text()).is_err());
    }

    #[test]
    fn findings_are_sorted_by_severity_then_id() {
        let config = test_config();
        let bundle = Bundle {
            version: "1.0".to_string(),
            endpoints: vec![Endpoint {
                method: "GET".to_string(),
                path: "/private".to_string(),
                auth: "none".to_string(),
                rate_limit: String::new(),
                scopes: Vec::new(),
                errors: vec![401],
                description: String::new(),
            }],
            oauth: Some(model::OAuthConfig {
                client_id: "100000000000000001".to_string(),
                redirect_uris: Vec::new(),
                scopes: Vec::new(),
                pkce: false,
                state: true,
                token_endpoint_auth_method: "client_secret_basic".to_string(),
            }),
            permissions: vec![PermissionEntry {
                role: "bot".to_string(),
                bits: 1 << 3,
                scope: "guild".to_string(),
            }],
            gateway: Some(model::GatewayInfo {
                version: 10,
                heartbeat_interval: 41250,
                intents: vec!["GUILDS".to_string()],
                events: vec!["READY".to_string()],
                reconnect: "exponential-backoff".to_string(),
                resume: false,
            }),
            scenarios: Vec::new(),
        };
        let report = analyzer::analyze_bundle(&bundle, &config);
        let sorted: Vec<(&str, &str)> = report
            .findings
            .iter()
            .map(|item| (item.severity.as_str(), item.id.as_str()))
            .collect();
        assert_eq!(
            sorted,
            vec![
                ("critical", "perm-admin-granted"),
                ("high", "rest-auth-missing"),
                ("medium", "oauth-pkce-disabled"),
                ("medium", "rest-rate-limit-missing"),
                ("low", "gateway-resume-disabled"),
            ]
        );
    }

    #[test]
    fn rest_rules_work() {
        let config = test_config();
        let endpoints = vec![Endpoint {
            method: "POST".to_string(),
            path: "/secret".to_string(),
            auth: "none".to_string(),
            rate_limit: String::new(),
            scopes: Vec::new(),
            errors: Vec::new(),
            description: String::new(),
        }];
        let findings = rest::analyze(&endpoints, &config);
        let ids: Vec<&str> = findings.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn oauth_rules_work() {
        let config = test_config();
        let oauth = model::OAuthConfig {
            client_id: "100000000000000001".to_string(),
            redirect_uris: vec!["https://example.test/*".to_string()],
            scopes: vec!["guilds.join".to_string()],
            pkce: false,
            state: false,
            token_endpoint_auth_method: "none".to_string(),
        };
        assert_eq!(oauth::analyze(Some(&oauth), &config).len(), 5);
    }

    #[test]
    fn permission_decode_works() {
        let names = permissions::decode(1 << 3 | 1 << 11);
        assert_eq!(names, vec!["ADMINISTRATOR", "SEND_MESSAGES"]);
    }

    #[test]
    fn gateway_rules_work() {
        let config = test_config();
        let gateway = model::GatewayInfo {
            version: 9,
            heartbeat_interval: 100,
            intents: Vec::new(),
            events: Vec::new(),
            reconnect: String::new(),
            resume: false,
        };
        assert_eq!(gateway::analyze(Some(&gateway), &config).len(), 5);
    }

    #[test]
    fn lab_results_are_deterministic() {
        let scenario = Scenario {
            id: "sc-1".to_string(),
            type_name: "rate_limit".to_string(),
            title: "429".to_string(),
            endpoint: "/rate-limited".to_string(),
            mock_response: 429,
            expected: "Retry-After".to_string(),
            fix_check: "present".to_string(),
            impact: "high".to_string(),
            fixed: false,
        };
        let (findings, results) = lab::analyze(&[scenario]);
        assert!(findings.is_empty());
        assert_eq!(results[0].status, "reproduced");
        assert_eq!(results[0].severity, "high");
    }

    #[test]
    fn token_analysis_detects_duplicates() {
        let config = test_config();
        let raw = RawTokenReport::from_value(&parse(&raw_text()).unwrap()).unwrap();
        let report = tokens::analyze(&raw, &config);
        assert_eq!(report.summary.raw_findings, 4);
        assert_eq!(report.summary.duplicates, 1);
        assert_eq!(report.groups.len(), 3);
        assert_eq!(report.findings[0].file, "a.py");
        assert_eq!(report.findings[0].risk_level, "high");
        assert_eq!(report.findings[1].duplicate_of, "sha256:aa");
    }

    #[test]
    fn token_analysis_marks_false_positives() {
        let config = test_config();
        let mut raw = RawTokenReport::from_value(&parse(&raw_text()).unwrap()).unwrap();
        for finding in &mut raw.findings {
            finding.false_positive = true;
        }
        let report = tokens::analyze(&raw, &config);
        assert_eq!(report.summary.false_positives, 4);
        assert!(report
            .findings
            .iter()
            .all(|item| item.risk_level == "false_positive" && item.risk_score == 0));
        assert_eq!(report.summary.by_severity.get("false_positive"), Some(&4));
    }

    #[test]
    fn token_facade_never_returns_a_secret() {
        let secret = "100000000000000001.aB3xYz.SYNTHETICabcdefghijklmnopqr";
        let raw = format!(
            r#"{{"scanned_files":1,"skipped_files":0,"findings":[
              {{"file":"x.py","line":1,"column":1,"fingerprint":"sha256:aa","id_length":18,
                "timestamp_length":6,"secret_length":27,"entropy":4.2,
                "context":"discord_bot_token","false_positive":false}}]}}"#
        );
        assert!(analyze_tokens_json(&raw, &config_text()).is_ok());
        assert!(!secret.contains("masked"));
        assert_eq!(mask::redact(secret), "[REDACTED]");
    }

    #[test]
    fn redaction_covers_both_shapes() {
        let text = "a 100000000000000001.aB3xYz.SYNTHETICabcdefghijklmnopqr b 123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";
        assert_eq!(mask::redact(text), "a [REDACTED] b [REDACTED]");
    }

    #[test]
    fn token_facade_rejects_invalid_raw() {
        assert!(analyze_tokens_json("{}", &config_text()).is_err());
    }

    #[test]
    fn reports_contain_no_full_secret() {
        let analysis = analyze_json(&bundle_text(), &config_text()).unwrap();
        let tokens = analyze_tokens_json(&raw_text(), &config_text()).unwrap();
        assert_eq!(mask::redact(&analysis), analysis);
        assert_eq!(mask::redact(&tokens), tokens);
    }
}
