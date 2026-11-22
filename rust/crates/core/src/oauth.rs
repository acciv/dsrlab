//! Анализатор конфигурации OAuth2.

use crate::config::Config;
use crate::model::{Finding, OAuthConfig};

fn is_local(uri: &str) -> bool {
    uri.starts_with("http://localhost")
        || uri.starts_with("http://127.0.0.1")
        || uri.starts_with("https://localhost")
        || uri.starts_with("https://127.0.0.1")
}

pub fn analyze(oauth: Option<&OAuthConfig>, config: &Config) -> Vec<Finding> {
    let oauth = match oauth {
        Some(value) => value,
        None => return Vec::new(),
    };
    let mut findings = Vec::new();

    for uri in &oauth.redirect_uris {
        if uri.contains('*') || (uri.starts_with("http://") && !is_local(uri)) {
            findings.push(Finding::new(
                "oauth",
                "oauth-redirect-insecure",
                "Небезопасный redirect URI",
                "high",
                uri,
                "Используйте точный HTTPS URI или localhost для локальной разработки.",
            ));
        }
    }

    let dangerous: Vec<&String> = oauth
        .scopes
        .iter()
        .filter(|scope| config.dangerous_scopes.iter().any(|item| item == *scope))
        .collect();
    if !dangerous.is_empty() {
        let evidence = dangerous
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            "oauth",
            "oauth-dangerous-scope",
            "Запрошены опасные OAuth2-права",
            "high",
            &evidence,
            "Уберите права, которые приложению не нужны, и согласуйте их с пользователем.",
        ));
    }

    if !oauth.pkce {
        findings.push(Finding::new(
            "oauth",
            "oauth-pkce-disabled",
            "PKCE отключён",
            "medium",
            "pkce=false",
            "Включите PKCE для публичных OAuth2-клиентов.",
        ));
    }

    if !oauth.state {
        findings.push(Finding::new(
            "oauth",
            "oauth-state-disabled",
            "Защита state отключена",
            "medium",
            "state=false",
            "Включайте непредсказуемый state и проверяйте его в callback.",
        ));
    }

    if oauth.token_endpoint_auth_method == "none" {
        findings.push(Finding::new(
            "oauth",
            "oauth-token-auth-none",
            "Token endpoint не аутентифицирует клиента",
            "high",
            "token_endpoint_auth_method=none",
            "Используйте client_secret_basic или client_secret_post.",
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
    fn finds_oauth_problems() {
        let bundle = json::parse(
            r#"{"oauth":{"client_id":"100000000000000001",
                "redirect_uris":["http://example.test/cb","http://localhost:8080/cb"],
                "scopes":["identify","guilds.join"],"pkce":false,"state":false,
                "token_endpoint_auth_method":"none"}}"#,
        )
        .unwrap();
        let bundle = Bundle::from_value(&bundle).unwrap();
        let findings = analyze(bundle.oauth.as_ref(), &config());
        let ids: Vec<&str> = findings.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids.len(), 5);
        assert!(ids.contains(&"oauth-redirect-insecure"));
        assert!(ids.contains(&"oauth-dangerous-scope"));
        assert!(ids.contains(&"oauth-pkce-disabled"));
        assert!(ids.contains(&"oauth-state-disabled"));
        assert!(ids.contains(&"oauth-token-auth-none"));
    }
}
