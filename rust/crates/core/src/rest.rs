//! Анализатор структуры REST API.

use crate::config::Config;
use crate::model::{Endpoint, Finding};

pub fn analyze(endpoints: &[Endpoint], config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    for endpoint in endpoints {
        let target = format!("{} {}", endpoint.method, endpoint.path);

        if endpoint.rate_limit.trim().is_empty() {
            findings.push(Finding::new(
                "rest",
                "rest-rate-limit-missing",
                "У endpoint не описано ограничение частоты запросов",
                "medium",
                &target,
                "Опишите rate limit и проверяйте заголовки X-RateLimit-* и Retry-After.",
            ));
        }

        if endpoint.auth == "none"
            && !config
                .public_paths
                .iter()
                .any(|path| path == &endpoint.path)
        {
            findings.push(Finding::new(
                "rest",
                "rest-auth-missing",
                "Endpoint доступен без авторизации",
                "high",
                &target,
                "Включите проверку авторизации или явно объявите endpoint публичным.",
            ));
        }

        if endpoint.auth != "none" && !endpoint.errors.contains(&401) {
            findings.push(Finding::new(
                "rest",
                "rest-401-not-documented",
                "Для защищённого endpoint не описан ответ 401",
                "low",
                &target,
                "Добавьте код 401 в документацию ответов endpoint.",
            ));
        }

        if endpoint.method == "POST" && endpoint.errors.is_empty() {
            findings.push(Finding::new(
                "rest",
                "rest-errors-not-documented",
                "Для POST-запроса не описаны коды ошибок",
                "low",
                &target,
                "Перечислите возможные коды ошибок в документации endpoint.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::model::Bundle;

    fn config() -> Config {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../configs/default.json");
        let text = std::fs::read_to_string(path).unwrap();
        Config::from_value(&json::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn finds_rest_problems() {
        let bundle = json::parse(
            r#"{"endpoints":[
                {"method":"POST","path":"/users/@me","auth":"bearer","rate_limit":"","errors":[]},
                {"method":"GET","path":"/gateway","auth":"none","rate_limit":"per-route","errors":[401]},
                {"method":"GET","path":"/private","auth":"none","rate_limit":"per-route","errors":[401]}
            ]}"#,
        )
        .unwrap();
        let endpoints = Bundle::from_value(&bundle).unwrap().endpoints;
        let findings = analyze(&endpoints, &config());
        let ids: Vec<&str> = findings.iter().map(|item| item.id.as_str()).collect();
        assert!(ids.contains(&"rest-rate-limit-missing"));
        assert!(ids.contains(&"rest-auth-missing"));
        assert!(ids.contains(&"rest-errors-not-documented"));
        assert_eq!(ids.iter().filter(|id| **id == "rest-401-not-documented").count(), 1);
    }
}
