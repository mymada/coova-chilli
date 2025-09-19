use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    chilli_bin::run().await
}
