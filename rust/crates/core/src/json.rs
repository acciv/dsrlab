//! Минимальный JSON-парсер и writer без внешних crates.
//! Объекты хранятся в BTreeMap, поэтому вывод детерминирован.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(values) => Some(values),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|values| values.get(key))
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        input: input.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos == parser.input.len() {
        Ok(value)
    } else {
        Err(format!("unexpected trailing data at byte {}", parser.pos))
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.input.get(self.pos).copied() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => {
                self.keyword(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.keyword(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.keyword(b"null")?;
                Ok(Value::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(byte) => Err(format!("unexpected byte '{}' at {}", byte as char, self.pos)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn keyword(&mut self, word: &[u8]) -> Result<(), String> {
        if self.input.get(self.pos..self.pos + word.len()) == Some(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(format!("invalid keyword at {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.input.get(self.pos) != Some(&b'"') {
            return Err(format!("expected string at {}", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.input.len() {
            let byte = self.input[self.pos];
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = *self
                        .input
                        .get(self.pos)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&first)
                                && self.input.get(self.pos) == Some(&b'\\')
                                && self.input.get(self.pos + 1) == Some(&b'u')
                            {
                                self.pos += 2;
                                let second = self.parse_hex4()?;
                                if (0xDC00..=0xDFFF).contains(&second) {
                                    let code = 0x10000
                                        + ((first - 0xD800) << 10)
                                        + (second - 0xDC00);
                                    out.push(char::from_u32(code).ok_or_else(|| {
                                        format!("invalid unicode escape at {}", self.pos)
                                    })?);
                                } else {
                                    return Err("invalid low surrogate".to_string());
                                }
                            } else {
                                out.push(char::from_u32(first).ok_or_else(|| {
                                    format!("invalid unicode escape at {}", self.pos)
                                })?);
                            }
                        }
                        other => {
                            return Err(format!("invalid escape '{}' at {}", other as char, self.pos))
                        }
                    }
                }
                0..=0x1F => return Err(format!("control character in string at {}", self.pos)),
                _ => {
                    let rest = std::str::from_utf8(&self.input[self.pos..])
                        .map_err(|_| format!("invalid UTF-8 at {}", self.pos))?;
                    let ch = rest.chars().next().unwrap();
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
        Err("unterminated string".to_string())
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.input.len() {
            return Err("short unicode escape".to_string());
        }
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self.input[self.pos];
            self.pos += 1;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => return Err(format!("invalid hex digit at {}", self.pos - 1)),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        while self.pos < self.input.len()
            && matches!(self.input[self.pos], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        let number = text
            .parse::<f64>()
            .map_err(|_| format!("invalid number '{}' at {}", text, start))?;
        if !number.is_finite() {
            return Err(format!("non-finite number at {}", start));
        }
        Ok(Value::Number(number))
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut values = BTreeMap::new();
        self.skip_ws();
        if self.input.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Value::Object(values));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.input.get(self.pos) != Some(&b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let value = self.parse_value()?;
            values.insert(key, value);
            self.skip_ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(values));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut values = Vec::new();
        self.skip_ws();
        if self.input.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(values));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }
}

pub fn to_string_pretty(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, 0, &mut out);
    out
}

fn write_value(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&format_number(*number)),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                out.push_str(&"  ".repeat(level + 1));
                write_value(item, level + 1, out);
                if index + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(level));
            out.push(']');
        }
        Value::Object(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (index, (key, item)) in items.iter().enumerate() {
                out.push_str(&"  ".repeat(level + 1));
                write_string(key, out);
                out.push_str(": ");
                write_value(item, level + 1, out);
                if index + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(level));
            out.push('}');
        }
    }
}

fn format_number(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 9_007_199_254_740_992.0 {
        return format!("{}", number as i64);
    }
    let text = format!("{:.6}", number);
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-0" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_json() {
        let value = parse(r#"{"a":[1,2,{"b":true}],"c":null}"#).unwrap();
        assert_eq!(value.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(value.get("c").unwrap(), &Value::Null);
    }

    #[test]
    fn parses_escapes_and_pretty_output_is_stable() {
        let value = parse(r#"{"text":"строка\n\"кавычки\"","entropy":4.12}"#).unwrap();
        assert!(value.get("text").unwrap().as_str().unwrap().contains('\n'));
        let text = to_string_pretty(&value);
        assert!(text.contains("\"entropy\": 4.12"));
        assert_eq!(text, to_string_pretty(&parse(&text).unwrap()));
    }
}
