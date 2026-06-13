#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hyperion_vault_api::serve().await
}
