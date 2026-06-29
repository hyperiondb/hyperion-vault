#![no_main]

use arbitrary::Arbitrary;
use hyperion_vault_core::rbac::{
    action_matches, authorize, is_valid_action, path_matches, visible,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    is_admin: bool,
    rules: Vec<(String, String)>,
    action: String,
    name: String,
}

// The authorization predicates must never panic, and the core access-control
// invariants must hold for any combination of rules, actions and names.
fuzz_target!(|input: Input| {
    let _ = is_valid_action(&input.action);
    let _ = path_matches(&input.action, &input.name);
    let _ = action_matches(&input.action, &input.action);

    let allowed = authorize(input.is_admin, &input.rules, &input.action, &input.name);
    let vis = visible(input.is_admin, &input.rules, &input.name);

    if input.is_admin {
        assert!(
            allowed && vis,
            "admin must be authorized and see everything"
        );
    }
    assert!(
        !allowed || vis,
        "authorize() must imply visible() — you cannot act on what you cannot see"
    );
    assert!(
        path_matches("*", &input.name),
        "a lone * must match any name"
    );
});
