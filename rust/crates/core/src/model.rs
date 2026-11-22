//! Модели входного BUNDLE, RAW токен-сканера и выходных отчётов.

use crate::json::Value;
use std::collections::BTreeMap;

fn req_str(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string field '{}'", key))
}

fn opt_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn req_num(value: &Value, key: &str) -> Result<i64, String> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .map(|number| number as i64)
        .ok_or_else(|| format!("missing numeric field '{}'", key))
}

fn opt_num(value: &Value, key: &str, default: i64) -> i64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .map(|number| number as i64)
        .unwrap_or(default)
}

fn req_bool(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean field '{}'", key))
}

fn opt_bool(value: &Value, key: &str, default: bool) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn strings(value: Option<&Value>, key: &str) -> Result<Vec<String>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(item) => item
            .as_array()
            .ok_or_else(|| format!("'{}' must be an array", key))?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("'{}' must contain strings", key))
            })
            .collect(),
    }
}

fn numbers(value: Option<&Value>, key: &str) -> Result<Vec<i64>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(item) => item
            .as_array()
            .ok_or_else(|| format!("'{}' must be an array", key))?
            .iter()
            .map(|entry| {
                entry
                    .as_f64()
                    .map(|number| number as i64)
                    .ok_or_else(|| format!("'{}' must contain numbers", key))
            })
            .collect(),
    }
}

fn obj() -> BTreeMap<String, Value> {
    BTreeMap::new()
}

fn string_array(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

/// Описание одного REST endpoint.
#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub auth: String,
    pub rate_limit: String,
    pub scopes: Vec<String>,
    pub errors: Vec<i64>,
    pub description: String,
}

impl Endpoint {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            method: req_str(value, "method")?,
            path: req_str(value, "path")?,
            auth: opt_str(value, "auth"),
            rate_limit: opt_str(value, "rate_limit"),
            scopes: strings(value.get("scopes"), "scopes")?,
            errors: numbers(value.get("errors"), "errors")?,
            description: opt_str(value, "description"),
        })
    }
}

/// Конфигурация OAuth2 проверяемого приложения.
#[derive(Clone, Debug, PartialEq)]
pub struct OAuthConfig {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    pub state: bool,
    pub token_endpoint_auth_method: String,
}

impl OAuthConfig {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            client_id: opt_str(value, "client_id"),
            redirect_uris: strings(value.get("redirect_uris"), "redirect_uris")?,
            scopes: strings(value.get("scopes"), "scopes")?,
            pkce: opt_bool(value, "pkce", true),
            state: opt_bool(value, "state", true),
            token_endpoint_auth_method: opt_str(value, "token_endpoint_auth_method"),
        })
    }
}

/// Запись о правах роли.
#[derive(Clone, Debug, PartialEq)]
pub struct PermissionEntry {
    pub role: String,
    pub bits: i64,
    pub scope: String,
}

impl PermissionEntry {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            role: req_str(value, "role")?,
            bits: req_num(value, "bits")?,
            scope: opt_str(value, "scope"),
        })
    }
}

/// Параметры Gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayInfo {
    pub version: i64,
    pub heartbeat_interval: i64,
    pub intents: Vec<String>,
    pub events: Vec<String>,
    pub reconnect: String,
    pub resume: bool,
}

impl GatewayInfo {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            version: opt_num(value, "version", 10),
            heartbeat_interval: opt_num(value, "heartbeat_interval", 41250),
            intents: strings(value.get("intents"), "intents")?,
            events: strings(value.get("events"), "events")?,
            reconnect: opt_str(value, "reconnect"),
            resume: opt_bool(value, "resume", true),
        })
    }
}

/// Сценарий лаборатории.
#[derive(Clone, Debug, PartialEq)]
pub struct Scenario {
    pub id: String,
    pub type_name: String,
    pub title: String,
    pub endpoint: String,
    pub mock_response: i64,
    pub expected: String,
    pub fix_check: String,
    pub impact: String,
    pub fixed: bool,
}

impl Scenario {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            id: opt_str(value, "id"),
            type_name: opt_str(value, "type"),
            title: opt_str(value, "title"),
            endpoint: opt_str(value, "endpoint"),
            mock_response: opt_num(value, "mock_response", 0),
            expected: opt_str(value, "expected"),
            fix_check: opt_str(value, "fix_check"),
            impact: opt_str(value, "impact"),
            fixed: opt_bool(value, "fixed", false),
        })
    }
}

/// Полный входной набор данных аудита.
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub version: String,
    pub endpoints: Vec<Endpoint>,
    pub oauth: Option<OAuthConfig>,
    pub permissions: Vec<PermissionEntry>,
    pub gateway: Option<GatewayInfo>,
    pub scenarios: Vec<Scenario>,
}

impl Bundle {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        if !matches!(value, Value::Object(_)) {
            return Err("bundle must be a JSON object".to_string());
        }
        let endpoints = value
            .get("endpoints")
            .map(|item| {
                item.as_array()
                    .ok_or_else(|| "endpoints must be an array".to_string())?
                    .iter()
                    .map(Endpoint::from_value)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let permissions = value
            .get("permissions")
            .map(|item| {
                item.as_array()
                    .ok_or_else(|| "permissions must be an array".to_string())?
                    .iter()
                    .map(PermissionEntry::from_value)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let scenarios = value
            .get("scenarios")
            .map(|item| {
                item.as_array()
                    .ok_or_else(|| "scenarios must be an array".to_string())?
                    .iter()
                    .map(Scenario::from_value)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            version: opt_str(value, "version"),
            endpoints,
            oauth: value
                .get("oauth")
                .map(OAuthConfig::from_value)
                .transpose()?,
            permissions,
            gateway: value
                .get("gateway")
                .map(GatewayInfo::from_value)
                .transpose()?,
            scenarios,
        })
    }
}

/// Одна находка анализа.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub module: String,
    pub id: String,
    pub title: String,
    pub severity: String,
    pub evidence: String,
    pub recommendation: String,
}

impl Finding {
    pub fn new(
        module: &str,
        id: &str,
        title: &str,
        severity: &str,
        evidence: &str,
        recommendation: &str,
    ) -> Self {
        Self {
            module: module.to_string(),
            id: id.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            evidence: evidence.to_string(),
            recommendation: recommendation.to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("module".into(), Value::String(self.module.clone()));
        value.insert("id".into(), Value::String(self.id.clone()));
        value.insert("title".into(), Value::String(self.title.clone()));
        value.insert("severity".into(), Value::String(self.severity.clone()));
        value.insert("evidence".into(), Value::String(self.evidence.clone()));
        value.insert(
            "recommendation".into(),
            Value::String(self.recommendation.clone()),
        );
        Value::Object(value)
    }
}

/// Декодированные права роли.
#[derive(Clone, Debug, PartialEq)]
pub struct PermissionBits {
    pub role: String,
    pub bits: i64,
    pub names: Vec<String>,
    pub excessive: bool,
}

impl PermissionBits {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("role".into(), Value::String(self.role.clone()));
        value.insert("bits".into(), Value::Number(self.bits as f64));
        value.insert("names".into(), string_array(&self.names));
        value.insert("excessive".into(), Value::Bool(self.excessive));
        Value::Object(value)
    }
}

/// Результат сценария лаборатории.
#[derive(Clone, Debug, PartialEq)]
pub struct ScenarioResult {
    pub id: String,
    pub status: String,
    pub severity: String,
    pub notes: String,
}

impl ScenarioResult {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("id".into(), Value::String(self.id.clone()));
        value.insert("status".into(), Value::String(self.status.clone()));
        value.insert("severity".into(), Value::String(self.severity.clone()));
        value.insert("notes".into(), Value::String(self.notes.clone()));
        Value::Object(value)
    }
}

fn counter(items: &[String], keys: &[&str]) -> BTreeMap<String, i64> {
    let mut result: BTreeMap<String, i64> = keys.iter().map(|key| (key.to_string(), 0)).collect();
    for item in items {
        *result.entry(item.clone()).or_insert(0) += 1;
    }
    result
}

fn counter_value(items: &BTreeMap<String, i64>) -> Value {
    Value::Object(
        items
            .iter()
            .map(|(key, count)| (key.clone(), Value::Number(*count as f64)))
            .collect(),
    )
}

/// Сводка ANALYSIS.json.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub endpoints: i64,
    pub scenarios: i64,
    pub findings: i64,
    pub by_module: BTreeMap<String, i64>,
    pub by_severity: BTreeMap<String, i64>,
}

impl Summary {
    pub fn new(findings: &[Finding], endpoints: i64, scenarios: i64) -> Self {
        let modules: Vec<String> = findings.iter().map(|item| item.module.clone()).collect();
        let severities: Vec<String> = findings.iter().map(|item| item.severity.clone()).collect();
        Self {
            endpoints,
            scenarios,
            findings: findings.len() as i64,
            by_module: counter(
                &modules,
                &["gateway", "lab", "oauth", "permissions", "rest"],
            ),
            by_severity: counter(&severities, &["critical", "high", "low", "medium"]),
        }
    }

    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("endpoints".into(), Value::Number(self.endpoints as f64));
        value.insert("scenarios".into(), Value::Number(self.scenarios as f64));
        value.insert("findings".into(), Value::Number(self.findings as f64));
        value.insert("by_module".into(), counter_value(&self.by_module));
        value.insert("by_severity".into(), counter_value(&self.by_severity));
        Value::Object(value)
    }
}

/// Выход анализа BUNDLE.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalyzedReport {
    pub version: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub permission_bits: Vec<PermissionBits>,
    pub scenario_results: Vec<ScenarioResult>,
}

impl AnalyzedReport {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("version".into(), Value::String(self.version.clone()));
        value.insert("summary".into(), self.summary.to_value());
        value.insert(
            "findings".into(),
            Value::Array(self.findings.iter().map(Finding::to_value).collect()),
        );
        value.insert(
            "permission_bits".into(),
            Value::Array(
                self.permission_bits
                    .iter()
                    .map(PermissionBits::to_value)
                    .collect(),
            ),
        );
        value.insert(
            "scenario_results".into(),
            Value::Array(
                self.scenario_results
                    .iter()
                    .map(ScenarioResult::to_value)
                    .collect(),
            ),
        );
        Value::Object(value)
    }
}

/// Находка RAW токен-сканера.
#[derive(Clone, Debug, PartialEq)]
pub struct RawTokenFinding {
    pub file: String,
    pub line: i64,
    pub column: i64,
    pub fingerprint: String,
    pub id_length: i64,
    pub timestamp_length: i64,
    pub secret_length: i64,
    pub entropy: f64,
    pub context: String,
    pub false_positive: bool,
}

impl RawTokenFinding {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            file: req_str(value, "file")?,
            line: req_num(value, "line")?,
            column: req_num(value, "column")?,
            fingerprint: req_str(value, "fingerprint")?,
            id_length: req_num(value, "id_length")?,
            timestamp_length: req_num(value, "timestamp_length")?,
            secret_length: req_num(value, "secret_length")?,
            entropy: value
                .get("entropy")
                .and_then(Value::as_f64)
                .ok_or_else(|| "missing entropy".to_string())?,
            context: opt_str(value, "context"),
            false_positive: req_bool(value, "false_positive")?,
        })
    }
}

/// RAW.json токен-сканера.
#[derive(Clone, Debug, PartialEq)]
pub struct RawTokenReport {
    pub scanned_files: i64,
    pub skipped_files: i64,
    pub findings: Vec<RawTokenFinding>,
}

impl RawTokenReport {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let findings = value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing findings array".to_string())?
            .iter()
            .map(RawTokenFinding::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            scanned_files: req_num(value, "scanned_files")?,
            skipped_files: req_num(value, "skipped_files")?,
            findings,
        })
    }
}

/// Проанализированная токен-находка.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenFinding {
    pub file: String,
    pub line: i64,
    pub column: i64,
    pub fingerprint: String,
    pub id_length: i64,
    pub timestamp_length: i64,
    pub secret_length: i64,
    pub entropy: f64,
    pub context: String,
    pub risk_score: i64,
    pub risk_level: String,
    pub duplicate_of: String,
    pub masked_value: String,
}

impl TokenFinding {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("file".into(), Value::String(self.file.clone()));
        value.insert("line".into(), Value::Number(self.line as f64));
        value.insert("column".into(), Value::Number(self.column as f64));
        value.insert("fingerprint".into(), Value::String(self.fingerprint.clone()));
        value.insert("id_length".into(), Value::Number(self.id_length as f64));
        value.insert(
            "timestamp_length".into(),
            Value::Number(self.timestamp_length as f64),
        );
        value.insert("secret_length".into(), Value::Number(self.secret_length as f64));
        value.insert("entropy".into(), Value::Number(self.entropy));
        value.insert("context".into(), Value::String(self.context.clone()));
        value.insert("risk_score".into(), Value::Number(self.risk_score as f64));
        value.insert("risk_level".into(), Value::String(self.risk_level.clone()));
        value.insert("duplicate_of".into(), Value::String(self.duplicate_of.clone()));
        value.insert("masked_value".into(), Value::String(self.masked_value.clone()));
        Value::Object(value)
    }
}

/// Группа одинаковых токенов.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenGroup {
    pub fingerprint: String,
    pub occurrences: i64,
    pub files: Vec<String>,
    pub risk_level: String,
    pub masked_value: String,
}

impl TokenGroup {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("fingerprint".into(), Value::String(self.fingerprint.clone()));
        value.insert("occurrences".into(), Value::Number(self.occurrences as f64));
        value.insert("files".into(), string_array(&self.files));
        value.insert("risk_level".into(), Value::String(self.risk_level.clone()));
        value.insert("masked_value".into(), Value::String(self.masked_value.clone()));
        Value::Object(value)
    }
}

/// Выход анализа токенов.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenAnalysisReport {
    pub version: String,
    pub summary: TokenSummary,
    pub findings: Vec<TokenFinding>,
    pub groups: Vec<TokenGroup>,
}

impl TokenAnalysisReport {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("version".into(), Value::String(self.version.clone()));
        value.insert("summary".into(), self.summary.to_value());
        value.insert(
            "findings".into(),
            Value::Array(self.findings.iter().map(TokenFinding::to_value).collect()),
        );
        value.insert(
            "groups".into(),
            Value::Array(self.groups.iter().map(TokenGroup::to_value).collect()),
        );
        Value::Object(value)
    }
}

/// Сводка анализа токенов.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenSummary {
    pub scanned_files: i64,
    pub skipped_files: i64,
    pub raw_findings: i64,
    pub findings: i64,
    pub duplicates: i64,
    pub false_positives: i64,
    pub by_severity: BTreeMap<String, i64>,
}

impl TokenSummary {
    pub fn to_value(&self) -> Value {
        let mut value = obj();
        value.insert("scanned_files".into(), Value::Number(self.scanned_files as f64));
        value.insert("skipped_files".into(), Value::Number(self.skipped_files as f64));
        value.insert("raw_findings".into(), Value::Number(self.raw_findings as f64));
        value.insert("findings".into(), Value::Number(self.findings as f64));
        value.insert("duplicates".into(), Value::Number(self.duplicates as f64));
        value.insert(
            "false_positives".into(),
            Value::Number(self.false_positives as f64),
        );
        value.insert("by_severity".into(), counter_value(&self.by_severity));
        Value::Object(value)
    }
}
