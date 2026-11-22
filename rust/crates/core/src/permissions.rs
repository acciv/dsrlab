//! Декодирование битов прав Discord и поиск избыточных прав.

use crate::config::Config;
use crate::model::{Finding, PermissionBits, PermissionEntry};

/// Таблица битов Discord в формате (имя, номер бита).
pub const PERMISSION_BITS: &[(&str, u8)] = &[
    ("CREATE_INSTANT_INVITE", 0),
    ("KICK_MEMBERS", 1),
    ("BAN_MEMBERS", 2),
    ("ADMINISTRATOR", 3),
    ("MANAGE_CHANNELS", 4),
    ("MANAGE_GUILD", 5),
    ("ADD_REACTIONS", 6),
    ("VIEW_AUDIT_LOG", 7),
    ("VIEW_CHANNEL", 10),
    ("SEND_MESSAGES", 11),
    ("MANAGE_MESSAGES", 13),
    ("MENTION_EVERYONE", 17),
    ("CONNECT", 20),
    ("SPEAK", 21),
    ("MANAGE_NICKNAMES", 27),
    ("MANAGE_ROLES", 28),
    ("MANAGE_WEBHOOKS", 29),
    ("USE_APPLICATION_COMMANDS", 31),
    ("MANAGE_THREADS", 34),
    ("MODERATE_MEMBERS", 40),
    ("SEND_VOICE_MESSAGES", 46),
    ("SEND_POLLS", 49),
];

pub fn decode(bits: i64) -> Vec<String> {
    if bits < 0 {
        return Vec::new();
    }
    let unsigned = bits as u64;
    PERMISSION_BITS
        .iter()
        .filter(|(_, bit)| unsigned & (1u64 << *bit as u64) != 0)
        .map(|(name, _)| name.to_string())
        .collect()
}

fn dangerous_names<'a>(names: &'a [String], config: &'a Config) -> Vec<&'a String> {
    names
        .iter()
        .filter(|name| config.dangerous_permissions.iter().any(|item| item == *name))
        .collect()
}

pub fn analyze(entries: &[PermissionEntry], config: &Config) -> (Vec<Finding>, Vec<PermissionBits>) {
    let mut findings = Vec::new();
    let mut decoded_entries = Vec::new();

    for entry in entries {
        let names = decode(entry.bits);
        let dangerous = dangerous_names(&names, config);
        let excessive = !dangerous.is_empty();
        decoded_entries.push(PermissionBits {
            role: entry.role.clone(),
            bits: entry.bits,
            names: names.clone(),
            excessive,
        });

        if names.iter().any(|name| name == "ADMINISTRATOR") {
            findings.push(Finding::new(
                "permissions",
                "perm-admin-granted",
                "Роли выдано право ADMINISTRATOR",
                "critical",
                &entry.role,
                "Уберите ADMINISTRATOR и выдайте только конкретные права.",
            ));
        } else if excessive {
            let evidence = format!(
                "{}: {}",
                entry.role,
                dangerous
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            findings.push(Finding::new(
                "permissions",
                "perm-excessive",
                "У роли избыточные права",
                "high",
                &evidence,
                "Оставьте только права, необходимые роли для работы.",
            ));
        }

        if entry.scope == "global" && excessive {
            findings.push(Finding::new(
                "permissions",
                "perm-global-scope",
                "Опасные права выданы в глобальном контексте",
                "medium",
                &entry.role,
                "Ограничьте эти права конкретным сервером или приложением.",
            ));
        }
    }

    (findings, decoded_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn config() -> Config {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../configs/default.json");
        Config::from_value(&json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn decodes_permission_bits() {
        let names = decode(1 << 3 | 1 << 11 | 1 << 29);
        assert!(names.contains(&"ADMINISTRATOR".to_string()));
        assert!(names.contains(&"SEND_MESSAGES".to_string()));
        assert!(names.contains(&"MANAGE_WEBHOOKS".to_string()));
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn detects_excessive_and_global_permissions() {
        let entries = vec![PermissionEntry {
            role: "moderator".to_string(),
            bits: 1 << 2 | 1 << 4,
            scope: "global".to_string(),
        }];
        let (findings, bits) = analyze(&entries, &config());
        assert!(bits[0].excessive);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "perm-excessive");
        assert_eq!(findings[1].id, "perm-global-scope");
    }
}
