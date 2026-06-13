use anyhow::Result;
use deadpool_postgres::{Client, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::config::TargetSessionAttrs;
use tokio_postgres::{Config as PgConfig, NoTls};

use crate::config::Config;

pub struct Db {
    writer: Pool,
    reader: Pool,
}

impl Db {
    pub fn connect(cfg: &Config) -> Result<Self> {
        let writer = build_pool(cfg, TargetSessionAttrs::ReadWrite)?;
        let reader = build_pool(cfg, TargetSessionAttrs::Any)?;
        Ok(Self { writer, reader })
    }

    pub async fn writer(&self) -> Result<Client, deadpool_postgres::PoolError> {
        self.writer.get().await
    }

    pub async fn reader(&self) -> Result<Client, deadpool_postgres::PoolError> {
        self.reader.get().await
    }
}

fn build_pool(cfg: &Config, attrs: TargetSessionAttrs) -> Result<Pool> {
    let mut pg = PgConfig::new();
    for host in &cfg.pg_hosts {
        pg.host(host);
    }
    pg.port(cfg.pg_port);
    pg.user(&cfg.pg_user);
    if !cfg.pg_password.is_empty() {
        pg.password(&cfg.pg_password);
    }
    pg.dbname(&cfg.pg_dbname);
    pg.application_name("pg_vault_api");
    pg.target_session_attrs(attrs);

    let manager = deadpool_postgres::Manager::from_config(
        pg,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );

    Ok(Pool::builder(manager).max_size(cfg.pool_max).build()?)
}
