use hyperion_vault_core::rbac;

fn rules(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(a, p)| (a.to_string(), p.to_string()))
        .collect()
}

#[test]
fn deny_by_default_for_non_admin_without_rules() {
    let none = rules(&[]);
    for action in rbac::ACTIONS {
        assert!(!rbac::authorize(false, &none, action, "anything"));
    }
}

#[test]
fn admin_is_allowed_every_action_and_path() {
    for action in rbac::ACTIONS {
        assert!(rbac::authorize(true, &[], action, "db/root"));
    }
}

#[test]
fn exact_rule_matches_only_that_name_and_action() {
    let r = rules(&[("update", "db/root")]);
    assert!(rbac::authorize(false, &r, "update", "db/root"));
    assert!(!rbac::authorize(false, &r, "update", "db/root2"));
    assert!(!rbac::authorize(false, &r, "delete", "db/root"));
}

#[test]
fn prefix_glob_matches_subpaths_not_bare_prefix() {
    let r = rules(&[("*", "stripe/*")]);
    assert!(rbac::authorize(false, &r, "create", "stripe/key"));
    assert!(rbac::authorize(false, &r, "rotate", "stripe/sub/key"));
    assert!(!rbac::authorize(false, &r, "create", "stripe"));
    assert!(!rbac::authorize(false, &r, "create", "db/stripe"));
}

#[test]
fn action_must_match_the_rule() {
    let r = rules(&[("create", "stripe/*")]);
    assert!(rbac::authorize(false, &r, "create", "stripe/key"));
    assert!(!rbac::authorize(false, &r, "delete", "stripe/key"));
    assert!(!rbac::authorize(false, &r, "rotate", "stripe/key"));
}

#[test]
fn wildcard_action_grants_all_actions_on_path() {
    let r = rules(&[("*", "svc/*")]);
    for action in rbac::ACTIONS {
        assert!(rbac::authorize(false, &r, action, "svc/token"));
    }
}

#[test]
fn wildcard_path_grants_one_action_everywhere() {
    let r = rules(&[("rotate", "*")]);
    assert!(rbac::authorize(false, &r, "rotate", "anything/here"));
    assert!(!rbac::authorize(false, &r, "create", "anything/here"));
}

#[test]
fn multiple_rules_are_a_union() {
    let r = rules(&[("create", "stripe/*"), ("delete", "db/legacy")]);
    assert!(rbac::authorize(false, &r, "create", "stripe/x"));
    assert!(rbac::authorize(false, &r, "delete", "db/legacy"));
    assert!(!rbac::authorize(false, &r, "delete", "stripe/x"));
    assert!(!rbac::authorize(false, &r, "create", "db/legacy"));
}

#[test]
fn payment_role_is_confined_to_stripe() {
    let r = rules(&[("*", "stripe/*")]);
    assert!(rbac::authorize(false, &r, "create", "stripe/secret-key"));
    assert!(rbac::authorize(false, &r, "rotate", "stripe/webhook"));
    assert!(rbac::authorize(false, &r, "delete", "stripe/old"));
    assert!(!rbac::authorize(false, &r, "create", "db/root"));
    assert!(!rbac::authorize(false, &r, "rotate", "payments/other"));
}

#[test]
fn visibility_ignores_action_and_follows_paths() {
    let r = rules(&[("create", "stripe/*")]);
    assert!(rbac::visible(false, &r, "stripe/a"));
    assert!(!rbac::visible(false, &r, "db/a"));
    assert!(rbac::visible(true, &[], "db/a"));
    assert!(!rbac::visible(false, &[], "stripe/a"));
}

#[test]
fn patterns_are_case_sensitive() {
    let r = rules(&[("create", "Stripe/*")]);
    assert!(rbac::authorize(false, &r, "create", "Stripe/key"));
    assert!(!rbac::authorize(false, &r, "create", "stripe/key"));
}

#[test]
fn only_known_actions_are_valid() {
    for action in ["create", "update", "delete", "rotate", "*"] {
        assert!(rbac::is_valid_action(action));
    }
    for action in ["read", "list", "admin", "", "Create"] {
        assert!(!rbac::is_valid_action(action));
    }
}
