//! Анализатор конфигурации Gateway.

use crate::config::Config;
use crate::model::{Finding, GatewayInfo};

pub fn analyze(gateway: Option<&GatewayInfo>, config: &Config) -> Vec<Finding> {
    let gateway = match gateway {
        Some(value) => value,
        None => return Vec::new(),
    };
    let mut findings = Vec::new();

    if gateway.heartbeat_interval < config.gateway.heartbeat_min
        || gateway.heartbeat_interval > config.gateway.heartbeat_max
    {
        findings.push(Finding::new(
            "gateway",
            "gateway-heartbeat-range",
            "Интервал heartbeat вне допустимого диапазона",
            "medium",
            &format!("heartbeat_interval={}", gateway.heartbeat_interval),
            "Используйте интервал из HELLO и отправляйте heartbeat вовремя.",
        ));
    }

    if !gateway.resume {
        findings.push(Finding::new(
            "gateway",
            "gateway-resume-disabled",
            "Возобновление сессии отключено",
            "low",
            "resume=false",
            "Поддерживайте RESUME, чтобы не терять события после разрыва.",
        ));
    }

    if !gateway.events.iter().any(|event| event == "READY") {
        findings.push(Finding::new(
            "gateway",
            "gateway-ready-missing",
            "В списке событий нет READY",
            "low",
            "events без READY",
            "Добавьте обработку READY как начала успешного соединения.",
        ));
    }

    if gateway.intents.is_empty() {
        findings.push(Finding::new(
            "gateway",
            "gateway-intents-empty",
            "Не объявлены intents",
            "low",
            "intents=[]",
            "Запросите только те intents, которые действительно нужны.",
        ));
    }

    if gateway.version < config.gateway.min_version {
        findings.push(Finding::new(
            "gateway",
            "gateway-old-version",
            "Используется устаревшая версия Gateway",
            "low",
            &format!("version={}", gateway.version),
            "Обновитесь до актуальной версии протокола Gateway.",
        ));
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
        Config::from_value(&json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn finds_gateway_problems() {
        let value = json::parse(
            r#"{"gateway":{"version":9,"heartbeat_interval":100,
                "intents":[],"events":["MESSAGE_CREATE"],"resume":false}}"#,
        )
        .unwrap();
        let bundle = Bundle::from_value(&value).unwrap();
        let findings = analyze(bundle.gateway.as_ref(), &config());
        let ids: Vec<&str> = findings.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids.len(), 5);
        assert!(ids.contains(&"gateway-heartbeat-range"));
        assert!(ids.contains(&"gateway-old-version"));
    }
}
