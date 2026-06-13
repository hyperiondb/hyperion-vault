use std::net::Ipv4Addr;
use std::str::FromStr;

use hyperion_vault_core::ip_allowlist::IpAllowlist;

fn ip(s: &str) -> Ipv4Addr {
    Ipv4Addr::from_str(s).unwrap()
}

#[test]
fn empty_allowlist_denies_everything() {
    let allow = IpAllowlist::parse("").unwrap();
    assert!(allow.is_empty());
    assert!(!allow.contains(ip("10.0.0.1")));
    assert!(!allow.contains(ip("127.0.0.1")));
    assert!(!allow.contains(ip("0.0.0.0")));
}

#[test]
fn whitespace_only_allowlist_denies_everything() {
    let allow = IpAllowlist::parse("  ,  , ").unwrap();
    assert!(allow.is_empty());
    assert!(!allow.contains(ip("10.0.0.1")));
}

#[test]
fn single_address_matches_exactly() {
    let allow = IpAllowlist::parse("203.0.113.7").unwrap();
    assert!(allow.contains(ip("203.0.113.7")));
    assert!(!allow.contains(ip("203.0.113.8")));
    assert!(!allow.contains(ip("203.0.113.6")));
}

#[test]
fn cidr_block_matches_range_only() {
    let allow = IpAllowlist::parse("10.1.0.0/16").unwrap();
    assert!(allow.contains(ip("10.1.0.1")));
    assert!(allow.contains(ip("10.1.255.254")));
    assert!(!allow.contains(ip("10.2.0.1")));
    assert!(!allow.contains(ip("11.1.0.1")));
}

#[test]
fn multiple_entries_with_whitespace_are_parsed() {
    let allow = IpAllowlist::parse(" 192.168.1.10 , 10.0.0.0/24 ,172.16.5.5").unwrap();
    assert_eq!(allow.len(), 3);
    assert!(allow.contains(ip("192.168.1.10")));
    assert!(allow.contains(ip("10.0.0.200")));
    assert!(allow.contains(ip("172.16.5.5")));
    assert!(!allow.contains(ip("10.0.1.1")));
    assert!(!allow.contains(ip("8.8.8.8")));
}

#[test]
fn invalid_entries_are_rejected() {
    assert!(IpAllowlist::parse("not-an-ip").is_err());
    assert!(IpAllowlist::parse("999.1.1.1").is_err());
    assert!(IpAllowlist::parse("10.0.0.0/33").is_err());
    assert!(IpAllowlist::parse("::1").is_err());
    assert!(IpAllowlist::parse("10.0.0.1,bad").is_err());
}

#[test]
fn slash_32_is_equivalent_to_single_host() {
    let allow = IpAllowlist::parse("203.0.113.7/32").unwrap();
    assert!(allow.contains(ip("203.0.113.7")));
    assert!(!allow.contains(ip("203.0.113.8")));
}
