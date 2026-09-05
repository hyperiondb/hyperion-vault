use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Manual,
    Automatic,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Manual => "manual",
            SecretKind::Automatic => "automatic",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "manual" => Some(SecretKind::Manual),
            "automatic" => Some(SecretKind::Automatic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretFormat {
    Opaque,
    Userpass,
}

impl SecretFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretFormat::Opaque => "opaque",
            SecretFormat::Userpass => "userpass",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "opaque" => Some(SecretFormat::Opaque),
            "userpass" => Some(SecretFormat::Userpass),
            _ => None,
        }
    }
}

pub const MAX_SECRET_NAME_LEN: usize = 255;
pub const MIN_SECRET_VERSION: i32 = 1;

pub fn is_valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SECRET_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.'))
}

pub fn is_valid_secret_version(version: i32) -> bool {
    version >= MIN_SECRET_VERSION
}

pub fn is_normalized_secret_name(name: &str) -> bool {
    is_valid_secret_name(name)
        && !name.starts_with('/')
        && !name.ends_with('/')
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

pub fn aad_for(name: &str, version: i32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + 12);
    aad.extend_from_slice(name.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(version.to_string().as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_format_roundtrips_through_str() {
        for f in [SecretFormat::Opaque, SecretFormat::Userpass] {
            assert_eq!(SecretFormat::parse(f.as_str()), Some(f));
        }
    }

    #[test]
    fn secret_name_rules_reject_separator_bytes() {
        assert!(is_valid_secret_name("db/password"));
        assert!(!is_valid_secret_name("x\u{0}y"));
        assert!(!is_valid_secret_name("x\u{1}y"));
        assert!(!is_valid_secret_name(""));
        assert!(!is_valid_secret_name(&"a".repeat(MAX_SECRET_NAME_LEN + 1)));
    }

    #[test]
    fn a_normalized_name_has_no_dot_or_empty_segments() {
        assert!(is_normalized_secret_name("db/password"));
        assert!(is_normalized_secret_name("a.b/c-d_e"));
        assert!(!is_normalized_secret_name("a/../b"));
        assert!(!is_normalized_secret_name("a/./b"));
        assert!(!is_normalized_secret_name("a//b"));
        assert!(!is_normalized_secret_name("/a"));
        assert!(!is_normalized_secret_name("a/"));
        assert!(!is_normalized_secret_name(".."));
        assert!(!is_normalized_secret_name("."));
    }

    #[test]
    fn secret_version_must_be_positive() {
        assert!(is_valid_secret_version(1));
        assert!(!is_valid_secret_version(0));
        assert!(!is_valid_secret_version(-1));
        assert!(!is_valid_secret_version(i32::MIN));
    }

    #[test]
    fn secret_format_rejects_unknown() {
        assert_eq!(SecretFormat::parse("kv"), None);
        assert_eq!(SecretFormat::parse(""), None);
    }
}
