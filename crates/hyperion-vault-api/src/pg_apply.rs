use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio_postgres::NoTls;

use crate::store::PgRoleTarget;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn apply_password(
    target: &PgRoleTarget,
    login_user: &str,
    login_password: &str,
    role: &str,
    new_password: &str,
) -> Result<()> {
    if target.hosts.is_empty() {
        return Err(anyhow!("pg_replica target has no hosts"));
    }
    let mut last_err: Option<anyhow::Error> = None;
    for hostport in &target.hosts {
        let (host, port) = split_hostport(hostport);
        match try_rotate(
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

#[allow(clippy::too_many_arguments)]
async fn try_rotate(
    host: &str,
    port: u16,
    database: &str,
    user: &str,
    password: &str,
    role: &str,
    new_password: &str,
) -> Result<bool> {
    let config = format!(
        "host={host} port={port} dbname={database} user={user} password={password} connect_timeout=3"
    );

    let connect = tokio_postgres::connect(&config, NoTls);
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

fn split_hostport(hostport: &str) -> (&str, u16) {
    match hostport.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().unwrap_or(5432)),
        None => (hostport, 5432),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_and_port() {
        assert_eq!(split_hostport("10.0.0.2:5433"), ("10.0.0.2", 5433));
        assert_eq!(split_hostport("db"), ("db", 5432));
    }
}
