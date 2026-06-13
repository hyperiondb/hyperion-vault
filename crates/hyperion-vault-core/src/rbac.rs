pub const ACTIONS: [&str; 4] = ["create", "update", "delete", "rotate"];

pub fn is_valid_action(action: &str) -> bool {
    action == "*" || ACTIONS.contains(&action)
}

pub fn path_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

pub fn action_matches(rule_action: &str, action: &str) -> bool {
    rule_action == "*" || rule_action == action
}

pub fn authorize(is_admin: bool, rules: &[(String, String)], action: &str, name: &str) -> bool {
    is_admin
        || rules
            .iter()
            .any(|(a, p)| action_matches(a, action) && path_matches(p, name))
}

pub fn visible(is_admin: bool, rules: &[(String, String)], name: &str) -> bool {
    is_admin || rules.iter().any(|(_, p)| path_matches(p, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, p)| (a.to_string(), p.to_string()))
            .collect()
    }

    #[test]
    fn glob_prefix_matches_under_path() {
        assert!(path_matches("stripe/*", "stripe/secret-key"));
        assert!(!path_matches("stripe/*", "db/root"));
    }

    #[test]
    fn exact_pattern_requires_exact_name() {
        assert!(path_matches("db/pw", "db/pw"));
        assert!(!path_matches("db/pw", "db/pw2"));
    }

    #[test]
    fn lone_star_matches_everything() {
        assert!(path_matches("*", "anything/at/all"));
    }

    #[test]
    fn action_wildcard_matches_any_action() {
        assert!(action_matches("*", "create"));
        assert!(action_matches("create", "create"));
        assert!(!action_matches("create", "delete"));
    }

    #[test]
    fn admin_bypasses_all_rules() {
        assert!(authorize(true, &[], "delete", "anything"));
    }

    #[test]
    fn payment_role_scoped_to_stripe() {
        let r = rules(&[("create", "stripe/*"), ("rotate", "stripe/*")]);
        assert!(authorize(false, &r, "create", "stripe/secret-key"));
        assert!(authorize(false, &r, "rotate", "stripe/webhook"));
        assert!(!authorize(false, &r, "delete", "stripe/secret-key"));
        assert!(!authorize(false, &r, "create", "db/root"));
    }

    #[test]
    fn visibility_follows_patterns() {
        let r = rules(&[("create", "stripe/*")]);
        assert!(visible(false, &r, "stripe/a"));
        assert!(!visible(false, &r, "db/a"));
        assert!(visible(true, &[], "db/a"));
    }

    #[test]
    fn action_validation() {
        assert!(is_valid_action("create"));
        assert!(is_valid_action("*"));
        assert!(!is_valid_action("read"));
        assert!(!is_valid_action(""));
    }
}
