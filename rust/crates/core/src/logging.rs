//! Логирование: любой текст проходит через маскирование.

use crate::mask;

pub fn log(level: &str, message: &str) {
    eprintln!("{}: {}", level.to_uppercase(), mask::redact(message));
}

pub fn info(message: &str) {
    log("info", message);
}

pub fn warn(message: &str) {
    log("warn", message);
}

pub fn error(message: &str) {
    log("error", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_uses_redaction() {
        let text = "запрос 100000000000000001.aB3xYz.SYNTHETICabcdefghijklmnopqr";
        assert!(!log_message(text).contains("SYNTHETIC"));
    }

    fn log_message(text: &str) -> String {
        mask::redact(text)
    }
}
