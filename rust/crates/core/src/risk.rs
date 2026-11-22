//! Детерминированная оценка тяжести.

use crate::config::Config;

pub fn level_for_score(score: i64, config: &Config) -> String {
    let levels = &config.risk_levels;
    if score >= levels.critical {
        "critical".to_string()
    } else if score >= levels.high {
        "high".to_string()
    } else if score >= levels.medium {
        "medium".to_string()
    } else {
        "low".to_string()
    }
}

pub fn severity_rank(level: &str) -> i32 {
    match level {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}
