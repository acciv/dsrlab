//! Загрузка и проверка конфигурации без внешних crates.

use crate::json::Value;

#[derive(Clone, Debug, PartialEq)]
pub struct GatewayConfig {
    pub heartbeat_min: i64,
    pub heartbeat_max: i64,
    pub min_version: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RiskLevels {
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PatternRule {
    pub id: String,
    pub pattern_type: String,
    pub risk_weight: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub version: String,
    pub exclude_dirs: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub max_file_bytes: i64,
    pub max_line_bytes: i64,
    pub workers: i64,
    pub patterns: Vec<PatternRule>,
    pub false_positive_markers: Vec<String>,
    pub risk_levels: RiskLevels,
    pub public_paths: Vec<String>,
    pub dangerous_scopes: Vec<String>,
    pub dangerous_permissions: Vec<String>,
    pub gateway: GatewayConfig,
}

fn req_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("config: missing string '{}'", key))
}

fn req_number(value: &Value, key: &str) -> Result<i64, String> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .map(|number| number as i64)
        .ok_or_else(|| format!("config: missing number '{}'", key))
}

fn req_strings(value: &Value, key: &str) -> Result<Vec<String>, String> {
    let array = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("config: '{}' must be an array", key))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("config: '{}' must contain strings", key))
        })
        .collect()
}

impl Config {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let version = req_string(value, "version")?;
        let exclude_dirs = req_strings(value, "exclude_dirs")?;
        let exclude_extensions = req_strings(value, "exclude_extensions")?;
        let max_file_bytes = req_number(value, "max_file_bytes")?;
        let max_line_bytes = req_number(value, "max_line_bytes")?;
        let workers = req_number(value, "workers")?;
        let false_positive_markers = req_strings(value, "false_positive_markers")?;
        let public_paths = req_strings(value, "public_paths")?;
        let dangerous_scopes = req_strings(value, "dangerous_scopes")?;
        let dangerous_permissions = req_strings(value, "dangerous_permissions")?;

        if max_file_bytes <= 0 || max_line_bytes <= 0 || workers < 0 {
            return Err("config: limits must be positive and workers non-negative".to_string());
        }

        let raw_patterns = value
            .get("patterns")
            .and_then(Value::as_array)
            .ok_or_else(|| "config: 'patterns' must be an array".to_string())?;
        let mut patterns = Vec::new();
        for (index, item) in raw_patterns.iter().enumerate() {
            let id = item
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("config: pattern {} missing id", index))?;
            let pattern_type = item
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("config: pattern {} missing type", index))?;
            let regex = item
                .get("regex")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("config: pattern {} missing regex", index))?;
            let value_group = item
                .get("value_group")
                .and_then(Value::as_f64)
                .ok_or_else(|| format!("config: pattern {} missing value_group", index))?;
            let risk_weight = item
                .get("risk_weight")
                .and_then(Value::as_f64)
                .ok_or_else(|| format!("config: pattern {} missing risk_weight", index))?;
            let expected_length = item
                .get("expected_length")
                .and_then(Value::as_f64)
                .ok_or_else(|| format!("config: pattern {} missing expected_length", index))?;
            if id.is_empty() || pattern_type.is_empty() || regex.is_empty() {
                return Err(format!("config: pattern {} has empty fields", index));
            }
            if value_group < 1.0 || risk_weight < 0.0 || expected_length < 0.0 {
                return Err(format!("config: pattern {} has invalid numbers", index));
            }
            patterns.push(PatternRule {
                id: id.to_string(),
                pattern_type: pattern_type.to_string(),
                risk_weight: risk_weight as i64,
            });
        }

        let levels = value
            .get("risk_levels")
            .ok_or_else(|| "config: missing 'risk_levels'".to_string())?;
        let risk_levels = RiskLevels {
            low: levels
                .get("low")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: risk_levels.low missing".to_string())?
                as i64,
            medium: levels
                .get("medium")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: risk_levels.medium missing".to_string())?
                as i64,
            high: levels
                .get("high")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: risk_levels.high missing".to_string())?
                as i64,
            critical: levels
                .get("critical")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: risk_levels.critical missing".to_string())?
                as i64,
        };
        if !(0 < risk_levels.low
            && risk_levels.low <= risk_levels.medium
            && risk_levels.medium <= risk_levels.high
            && risk_levels.high <= risk_levels.critical)
        {
            return Err("config: risk_levels must be ordered low <= medium <= high <= critical"
                .to_string());
        }

        let gateway_value = value
            .get("gateway")
            .ok_or_else(|| "config: missing 'gateway'".to_string())?;
        let gateway = GatewayConfig {
            heartbeat_min: gateway_value
                .get("heartbeat_min")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: gateway.heartbeat_min missing".to_string())?
                as i64,
            heartbeat_max: gateway_value
                .get("heartbeat_max")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: gateway.heartbeat_max missing".to_string())?
                as i64,
            min_version: gateway_value
                .get("min_version")
                .and_then(Value::as_f64)
                .ok_or_else(|| "config: gateway.min_version missing".to_string())?
                as i64,
        };
        if gateway.heartbeat_min <= 0
            || gateway.heartbeat_min >= gateway.heartbeat_max
            || gateway.min_version <= 0
        {
            return Err("config: invalid gateway limits".to_string());
        }

        Ok(Self {
            version,
            exclude_dirs,
            exclude_extensions,
            max_file_bytes,
            max_line_bytes,
            workers,
            patterns,
            false_positive_markers,
            risk_levels,
            public_paths,
            dangerous_scopes,
            dangerous_permissions,
            gateway,
        })
    }

    pub fn risk_weight(&self, pattern_id: &str) -> i64 {
        self.patterns
            .iter()
            .find(|pattern| pattern.id == pattern_id)
            .map(|pattern| pattern.risk_weight)
            .unwrap_or(25)
    }
}

pub fn validate_value(value: &Value) -> Result<(), String> {
    Config::from_value(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn sample() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../configs/default.json"
        ))
        .unwrap()
    }

    #[test]
    fn default_config_is_valid() {
        let value = json::parse(&sample()).unwrap();
        assert!(validate_value(&value).is_ok());
    }

    #[test]
    fn invalid_risk_order_is_rejected() {
        let value = json::parse(&sample()).unwrap();
        let mut config = Config::from_value(&value).unwrap();
        config.risk_levels.low = 90;
        assert!(config.risk_levels.high < config.risk_levels.low);
    }
}
