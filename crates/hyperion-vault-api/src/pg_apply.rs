use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres::config::SslMode;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{NoTls, Socket};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::config::PgTlsMode;
use crate::store::PgRoleTarget;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_PG_PORT: u16 = 5432;

pub struct PgTargetPolicy {
    hosts: Vec<(String, u16)>,
    mode: PgTlsMode,
    tls: Option<MakeRustlsConnect>,
}

impl PgTargetPolicy {
    pub fn build(raw_hosts: &str, mode: PgTlsMode, ca_file: Option<&str>) -> Result<Self> {
        Self::from_hosts(parse_hosts(raw_hosts)?, mode, ca_file)
    }

    pub fn seeded<I>(hosts: I, mode: PgTlsMode, ca_file: Option<&str>) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut parsed = Vec::new();
        for entry in hosts {
            let (host, port) = split_hostport(entry.trim());
            if host.is_empty() {
                continue;
            }
            push_host(&mut parsed, host, port);
        }
        Self::from_hosts(parsed, mode, ca_file)
    }

    fn from_hosts(
        hosts: Vec<(String, u16)>,
        mode: PgTlsMode,
        ca_file: Option<&str>,
    ) -> Result<Self> {
        let tls = if hosts.is_empty() {
            None
        } else {
            match mode {
                PgTlsMode::Disable => None,
                PgTlsMode::VerifyFull => Some(MakeRustlsConnect::new(client_config(ca_file)?)),
                PgTlsMode::Prefer => match client_config(ca_file) {
                    Ok(config) => Some(MakeRustlsConnect::new(config)),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "VAULT_PG_TARGET_TLS=prefer but no usable certificate store; rotation will connect to Postgres targets without TLS"
                        );
                        None
                    }
                },
            }
        };
        Ok(Self { hosts, mode, tls })
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }

    pub fn tls_required(&self) -> bool {
        self.tls.is_some() && self.mode == PgTlsMode::VerifyFull
    }

    pub fn hosts(&self) -> Vec<String> {
        self.hosts
            .iter()
            .map(|(host, port)| format!("{host}:{port}"))
            .collect()
    }

    pub fn check(&self, target: &PgRoleTarget) -> Result<()> {
        if target.hosts.is_empty() {
            bail!("pg_replica target has no hosts");
        }
        if self.hosts.is_empty() {
            bail!("pg_replica targets are refused: VAULT_PG_TARGET_HOSTS is empty");
        }
        for hostport in &target.hosts {
            if !self.allows(hostport) {
                bail!("pg_replica host '{hostport}' is not in VAULT_PG_TARGET_HOSTS");
            }
        }
        Ok(())
    }

    fn allows(&self, hostport: &str) -> bool {
        let (host, port) = split_hostport(hostport);
        let host = host.to_ascii_lowercase();
        self.hosts
            .iter()
            .any(|(allowed, allowed_port)| *allowed == host && *allowed_port == port)
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_rotate(
        &self,
        host: &str,
        port: u16,
        database: &str,
        user: &str,
        password: &str,
        role: &str,
        new_password: &str,
    ) -> Result<bool> {
        let mut config = tokio_postgres::Config::new();
        config
            .host(host)
            .port(port)
            .dbname(database)
            .user(user)
            .password(password)
            .application_name("hyperion-vault")
            .connect_timeout(Duration::from_secs(3));

        match (&self.tls, self.mode) {
            (Some(tls), PgTlsMode::VerifyFull) => {
                config.ssl_mode(SslMode::Require);
                rotate_with(&config, tls.clone(), host, port, role, new_password).await
            }
            (Some(tls), _) => {
                config.ssl_mode(SslMode::Prefer);
                rotate_with(&config, tls.clone(), host, port, role, new_password).await
            }
            (None, _) => {
                config.ssl_mode(SslMode::Disable);
                rotate_with(&config, NoTls, host, port, role, new_password).await
            }
        }
    }
}

pub async fn apply_password(
    policy: &PgTargetPolicy,
    target: &PgRoleTarget,
    login_user: &str,
    login_password: &str,
    role: &str,
    new_password: &str,
) -> Result<()> {
    policy.check(target)?;
    let mut last_err: Option<anyhow::Error> = None;
    for hostport in &target.hosts {
        let (host, port) = split_hostport(hostport);
        match policy
            .try_rotate(
                host,
                port,
                &target.database,
                login_user,
                login_password,
                role,
                new_password,
            )
            .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => continue,
            Err(err) => {
                tracing::warn!(node = %hostport, error = %err, "pg_replica rotate_credential attempt failed");
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow!(
            "no writable primary among pg_replica nodes {:?}",
            target.hosts
        )
    }))
}

async fn rotate_with<T>(
    config: &tokio_postgres::Config,
    tls: T,
    host: &str,
    port: u16,
    role: &str,
    new_password: &str,
) -> Result<bool>
where
    T: MakeTlsConnect<Socket> + Send,
    T::TlsConnect: Send,
    T::Stream: Send + 'static,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let connect = config.connect(tls);
    let (client, connection) = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => return Err(anyhow!("connect {host}:{port}: {err}")),
        Err(_) => return Err(anyhow!("connect {host}:{port}: timed out")),
    };

    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let result = client
        .query_one(
            "SELECT replica.rotate_credential($1, $2)",
            &[&role, &new_password],
        )
        .await;
    drop(client);
    driver.abort();

    match result {
        Ok(row) => Ok(row.get::<_, bool>(0)),
        Err(err) => Err(anyhow!("rotate_credential on {host}:{port}: {err}")),
    }
}

fn parse_hosts(raw: &str) -> Result<Vec<(String, u16)>> {
    let mut hosts = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (host, port) = split_hostport(entry);
        if host.is_empty() {
            bail!("VAULT_PG_TARGET_HOSTS entry '{entry}' has an empty host");
        }
        push_host(&mut hosts, host, port);
    }
    Ok(hosts)
}

fn push_host(hosts: &mut Vec<(String, u16)>, host: &str, port: u16) {
    let host = host.to_ascii_lowercase();
    if !hosts.iter().any(|(h, p)| *h == host && *p == port) {
        hosts.push((host, port));
    }
}

fn client_config(ca_file: Option<&str>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let certs = CertificateDer::pem_file_iter(path)
                .with_context(|| format!("open VAULT_PG_TARGET_CA_FILE '{path}'"))?;
            let mut added = 0usize;
            for cert in certs {
                let cert =
                    cert.with_context(|| format!("read VAULT_PG_TARGET_CA_FILE '{path}'"))?;
                roots.add(cert)?;
                added += 1;
            }
            if added == 0 {
                bail!("VAULT_PG_TARGET_CA_FILE '{path}' contains no certificates");
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            let (added, _ignored) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                bail!(
                    "no usable certificates in the system trust store ({:?}); set VAULT_PG_TARGET_CA_FILE",
                    native.errors
                );
            }
        }
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("rustls client config")?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub fn split_hostport(hostport: &str) -> (&str, u16) {
    if let Some(rest) = hostport.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((host, "")) => (host, DEFAULT_PG_PORT),
            Some((host, tail)) => match tail.strip_prefix(':').map(str::parse) {
                Some(Ok(port)) => (host, port),
                _ => (hostport, DEFAULT_PG_PORT),
            },
            None => (hostport, DEFAULT_PG_PORT),
        };
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(port) => (host, port),
            Err(_) => (hostport, DEFAULT_PG_PORT),
        },
        _ => (hostport, DEFAULT_PG_PORT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(raw: &str) -> PgTargetPolicy {
        PgTargetPolicy::build(raw, PgTlsMode::Disable, None).expect("policy")
    }

    fn target(hosts: &[&str]) -> PgRoleTarget {
        PgRoleTarget {
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            database: "postgres".to_string(),
            role: None,
            login_secret: None,
        }
    }

    #[test]
    fn seeded_hosts_are_deduplicated() {
        let policy = PgTargetPolicy::seeded(
            ["10.0.0.2:5432".to_string(), "10.0.0.2".to_string()],
            PgTlsMode::Disable,
            None,
        )
        .expect("policy");
        assert_eq!(policy.len(), 1);
        assert!(policy.check(&target(&["10.0.0.2:5432"])).is_ok());
        assert!(policy.check(&target(&["10.0.0.9:5432"])).is_err());
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(split_hostport("10.0.0.2:5433"), ("10.0.0.2", 5433));
        assert_eq!(split_hostport("db"), ("db", 5432));
    }

    #[test]
    fn splits_bracketed_ipv6() {
        assert_eq!(split_hostport("[::1]:5433"), ("::1", 5433));
        assert_eq!(split_hostport("[::1]"), ("::1", 5432));
        assert_eq!(
            split_hostport("[fe80::1%eth0]:5432"),
            ("fe80::1%eth0", 5432)
        );
    }

    #[test]
    fn keeps_an_unparseable_port_inside_the_host() {
        assert_eq!(split_hostport("db:99999"), ("db:99999", 5432));
        assert_eq!(split_hostport("::1"), ("::1", 5432));
    }

    #[test]
    fn empty_allowlist_refuses_every_target() {
        let policy = policy("");
        assert!(policy.is_empty());
        assert!(policy.check(&target(&["10.0.0.2:5432"])).is_err());
    }

    #[test]
    fn allowlisted_host_is_accepted() {
        let policy = policy("10.0.0.2:5432, 10.0.0.3:5432");
        assert!(policy
            .check(&target(&["10.0.0.2:5432", "10.0.0.3:5432"]))
            .is_ok());
    }

    #[test]
    fn host_outside_allowlist_is_refused() {
        let policy = policy("10.0.0.2:5432");
        let err = policy
            .check(&target(&["10.0.0.2:5432", "attacker.example:5432"]))
            .expect_err("must refuse");
        assert!(err.to_string().contains("attacker.example:5432"));
    }

    #[test]
    fn port_must_match_the_allowlist() {
        let policy = policy("10.0.0.2:5432");
        assert!(policy.check(&target(&["10.0.0.2:6432"])).is_err());
    }

    #[test]
    fn host_without_port_defaults_to_5432_on_both_sides() {
        let policy = policy("db.internal");
        assert!(policy.check(&target(&["DB.internal:5432"])).is_ok());
    }

    #[test]
    fn target_without_hosts_is_refused() {
        let policy = policy("10.0.0.2:5432");
        assert!(policy.check(&target(&[])).is_err());
    }
}
