//! CLI ядра: dscore.

use dscore::{analyze_json, analyze_tokens_json, mask, validate_config_json, version};
use std::{env, fs, process};

fn usage() -> &'static str {
    "dscore — ядро Discord API Security Research Lab\n\n\
Использование:\n\
  dscore analyze <bundle.json> <config.json>\n\
  dscore analyze-tokens <token_raw.json> <config.json>\n\
  dscore validate-config <config.json>\n\
  dscore version\n\
  dscore help"
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("analyze") => {
            if args.len() != 3 {
                return Err("analyze: нужен bundle.json и config.json".to_string());
            }
            let bundle = fs::read_to_string(&args[1]).map_err(|err| err.to_string())?;
            let config = fs::read_to_string(&args[2]).map_err(|err| err.to_string())?;
            println!("{}", analyze_json(&bundle, &config)?);
            Ok(())
        }
        Some("analyze-tokens") => {
            if args.len() != 3 {
                return Err("analyze-tokens: нужны token_raw.json и config.json".to_string());
            }
            let raw = fs::read_to_string(&args[1]).map_err(|err| err.to_string())?;
            let config = fs::read_to_string(&args[2]).map_err(|err| err.to_string())?;
            println!("{}", analyze_tokens_json(&raw, &config)?);
            Ok(())
        }
        Some("validate-config") => {
            if args.len() != 2 {
                return Err("validate-config: нужен путь к config.json".to_string());
            }
            let config = fs::read_to_string(&args[1]).map_err(|err| err.to_string())?;
            validate_config_json(&config)?;
            println!("ok");
            Ok(())
        }
        Some("version") => {
            println!("{}", version());
            Ok(())
        }
        Some("help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(format!("неизвестная команда: {}", other)),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ошибка: {}", mask::redact(&error));
        process::exit(1);
    }
}
