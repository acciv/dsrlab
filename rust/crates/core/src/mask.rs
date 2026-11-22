//! Маскирование секретов: в выводе остаётся только тип, длина и отпечаток.

fn is_secret_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

fn is_digit(ch: char) -> bool {
    ch.is_ascii_digit()
}

fn match_token(chars: &[char], start: usize) -> Option<usize> {
    if start > 0 && is_secret_char(chars[start - 1]) {
        return None;
    }
    let mut pos = start;
    while pos < chars.len() && is_digit(chars[pos]) && pos - start < 21 {
        pos += 1;
    }
    let id_len = pos - start;
    if !(17..=20).contains(&id_len) || chars.get(pos) != Some(&'.') {
        return None;
    }
    pos += 1;
    for _ in 0..6 {
        if chars.get(pos).copied().map(is_secret_char) != Some(true) {
            return None;
        }
        pos += 1;
    }
    if chars.get(pos) != Some(&'.') {
        return None;
    }
    pos += 1;
    for _ in 0..27 {
        if chars.get(pos).copied().map(is_secret_char) != Some(true) {
            return None;
        }
        pos += 1;
    }
    if chars.get(pos).copied().map(is_secret_char) == Some(true) {
        return None;
    }
    Some(pos)
}

fn match_generic(chars: &[char], start: usize) -> Option<usize> {
    if start > 0 && is_secret_char(chars[start - 1]) {
        return None;
    }
    let mut pos = start;
    while pos < chars.len() && is_digit(chars[pos]) && pos - start < 13 {
        pos += 1;
    }
    let id_len = pos - start;
    if !(6..=12).contains(&id_len) || chars.get(pos) != Some(&':') {
        return None;
    }
    pos += 1;
    for _ in 0..30 {
        if chars.get(pos).copied().map(is_secret_char) != Some(true) {
            return None;
        }
        pos += 1;
    }
    while chars.get(pos).copied().map(is_secret_char) == Some(true) && pos - start < 63 {
        pos += 1;
    }
    if chars.get(pos).copied().map(is_secret_char) == Some(true) {
        return None;
    }
    Some(pos)
}

/// Заменяет известные формы секретов на `[REDACTED]`, сохраняя UTF-8.
pub fn redact(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if is_digit(chars[index]) {
            if let Some(end) = match_token(&chars, index) {
                out.push_str("[REDACTED]");
                index = end;
                continue;
            }
            if let Some(end) = match_generic(&chars, index) {
                out.push_str("[REDACTED]");
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Единственный безопасный способ показать значение: тип, длина, пометка.
pub fn masked(context: &str, length: i64) -> String {
    format!("<{}:{}:masked>", context, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_discord_token_shape() {
        let text = "Token 100000000000000001.aB3xYz.SYNTHETICabcdefghijklmnopqr end";
        assert_eq!(redact(text), "Token [REDACTED] end");
    }

    #[test]
    fn redacts_generic_shape_and_keeps_unicode() {
        let text = "ключ 123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef и ещё";
        assert_eq!(redact(text), "ключ [REDACTED] и ещё");
    }

    #[test]
    fn masked_value_has_no_secret_material() {
        assert_eq!(masked("discord_bot_token", 27), "<discord_bot_token:27:masked>");
    }
}
