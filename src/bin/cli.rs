use std::sync::Arc;
use devices_manager::connection_protocol::{self, AppConfig, AppError};
use tokio::io::{self, AsyncBufReadExt, BufReader};

async fn get_input(prompt: &str) -> Result<String, AppError> {
    println!("{}", prompt);
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line.trim().to_string())
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| AppError::NetworkError("Failed crypto provider".to_string()))?;

    let config = Arc::new(AppConfig::load_or_create().await?);
    let (cert_chain, key) = connection_protocol::make_cert_and_key().await?;
    let server = connection_protocol::start_server_with_channel(cert_chain, key, Arc::clone(&config), None);

    println!("CLI Server started. Press 'q' to stop.");
    loop {
        let resp = get_input("> ").await?;
        if resp.to_lowercase() == "q" {
            break;
        }
    }
    server.stop().await;
    Ok(())
}
