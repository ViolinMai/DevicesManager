use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngExt;
use quinn::{self, Endpoint, SendStream, ServerConfig};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;

struct DeviceInfo {
    index: u8,
    name: String,
    ip: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileIndexing {
    id: usize,
    name: String,
    size: u64,
    path: PathBuf,
    is_dir: bool,
    parent_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeviceIndex {
    files: Vec<FileIndexing>,
}

// ------------------- TOFU VERIFIER -------------------

#[derive(Debug)]
struct TofuVerifier {
    target_device_name: String,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let current_fingerprint = hex::encode(hasher.finalize());

        let peers_file = "known_peers.json";
        let mut known_peers: HashMap<String, String> = if Path::new(peers_file).exists() {
            let data = fs::read_to_string(peers_file).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        if let Some(saved_fingerprint) = known_peers.get(&self.target_device_name) {
            if saved_fingerprint == &current_fingerprint {
                return Ok(ServerCertVerified::assertion());
            } else {
                eprintln!("\n⚠️ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! ⚠️");
                return Err(rustls::Error::General("Host key fingerprint mismatch!".into()));
            }
        }

        println!("\n[Security] New device discovered: {}", self.target_device_name);
        println!("[Security] Fingerprint: {}", current_fingerprint);

        known_peers.insert(self.target_device_name.clone(), current_fingerprint);
        if let Ok(json_data) = serde_json::to_string_pretty(&known_peers) {
            let _ = fs::write(peers_file, json_data);
            println!("[Security] Device trusted and stored in known_peers.json");
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ------------------- HELPERS & CERTIFICATE -------------------

pub fn get_fallback_device_name() -> String {
    "Huawei-P30-Lite".to_string()
}

async fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("Failed to read input");
    line.trim().to_string()
}

async fn make_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_path = Path::new("cert.der");
    let key_path = Path::new("key.der");

    if cert_path.exists() && key_path.exists() {
        let cert_bytes = fs::read(cert_path).expect("Failed to read cert.der");
        let key_bytes = fs::read(key_path).expect("Failed to read key.der");

        let cert_der = CertificateDer::from(cert_bytes);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));
        return (vec![cert_der], key);
    }

    let subject_alt_names = vec!["localhost".to_string()];
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_raw = cert.der().to_vec();
    let key_raw = signing_key.serialize_der();

    fs::write(cert_path, &cert_raw).expect("Failed to write cert.der");
    fs::write(key_path, &key_raw).expect("Failed to write key.der");

    let cert_der = CertificateDer::from(cert_raw);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_raw));
    (vec![cert_der], key)
}

// ------------------- SERVER LOGIC -------------------

async fn server(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    json_bytes: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
    device_index: DeviceIndex,
) {
    let config = ServerConfig::with_single_cert(cert_chain, key).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
    let endpoint = Endpoint::server(config, addr).unwrap();
    let dev_idx_stream = device_index.clone();

    let listen_socket = UdpSocket::bind("0.0.0.0:8888")
        .await
        .expect("Failed to bind UDP socket");

    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        loop {
            if let Ok((_bytes_read, client_addr)) = listen_socket.recv_from(&mut buffer).await {
                let device_name = get_fallback_device_name();
                let reply_message = device_name;
                let _ = listen_socket.send_to(reply_message.as_bytes(), client_addr).await;
            }
        }
    });

    while let Some(incoming) = endpoint.accept().await {
        let j = json_bytes.clone();
        let s = salt.clone();
        let n = nonce.clone();
        let dev_idx_clone = dev_idx_stream.clone();

        tokio::spawn(async move {
            let call = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };

            loop {
                let (send, mut recv) = match call.accept_bi().await {
                    Ok(stream) => stream,
                    Err(_) => break,
                };

                let mut read_code_buf = [0u8; 1];
                if recv.read_exact(&mut read_code_buf).await.is_err() {
                    break;
                }

                match read_code_buf[0] {
                    1 => {
                        tokio::spawn(async move {
                            handle_recieved_file(send, recv).await;
                        });
                    }
                    2 => {
                        let (j_stream, s_stream, n_stream) = (j.clone(), s.clone(), n.clone());
                        tokio::spawn(async move {
                            handle_sending_json(send, recv, j_stream, s_stream, n_stream).await;
                        });
                    }
                    3 => {
                        let dev_idx = dev_idx_clone.clone();
                        tokio::spawn(async move {
                            let mut id = [0u8; 8];
                            if recv.read_exact(&mut id).await.is_ok() {
                                let target_id = u64::from_be_bytes(id) as usize;
                                handle_sending_requested_file(dev_idx, send, target_id).await;
                            }
                        });
                    }
                    _ => {}
                }
            }
        });
    }
}

// ------------------- CLIENT LOGIC -------------------

async fn client() {
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut client = Endpoint::client(addr).unwrap();

    let broadcast_socket = UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind UDP socket");
    broadcast_socket.set_broadcast(true).expect("Failed to enable broadcast");
    let message = b"WHO IS THE SERVER?";
    broadcast_socket.send_to(message, "192.168.1.255:8888").await.expect("Failed to send broadcast");
    println!("Broadcast message sent, searching for devices...");

    let mut responses = [0u8; 1024];
    let mut discovered_servers: Vec<DeviceInfo> = Vec::new();
    let mut index: u8 = 1;

    loop {
        match tokio::time::timeout(Duration::from_millis(1500), broadcast_socket.recv_from(&mut responses)).await {
            Ok(Ok((bytes_read, server_addr))) => {
                let msg = String::from_utf8_lossy(&responses[..bytes_read]).to_string();
                discovered_servers.push(DeviceInfo {
                    index,
                    name: msg,
                    ip: server_addr,
                });
                index += 1;
            }
            _ => break,
        }
    }

    if discovered_servers.is_empty() {
        println!("No servers found on the network.");
        return;
    }

    for device in &discovered_servers {
        println!("{} - Device: {}, IP: {}", device.index, device.name, device.ip);
    }

    let chosen_server = get_input("Choose a server (num): ").await;
    let chosen_num: u8 = chosen_server.trim().parse::<u8>().expect("Invalid number");
    let targeted_device = discovered_servers.iter().find(|device| device.index == chosen_num).expect("Device not found");
    let target_name = targeted_device.name.clone();

    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TofuVerifier {
            target_device_name: target_name,
        }))
        .with_no_client_auth();

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client.set_default_client_config(client_config);

    let target_addr = SocketAddr::new(targeted_device.ip.ip(), 8080);
    println!("Connecting to server at: {}", target_addr);

    let connection = client.connect(target_addr, "localhost").unwrap().await.unwrap();
    println!("Connected successfully!");

    receive_json_call(&connection).await;

    let sending_choice = get_input("Do you want to request/download a file? (y/n)").await;
    if sending_choice.to_lowercase() == "y" {
        let number_chosen = get_input("Enter the file/s number (split with a comma): ").await;
        let ids: Vec<usize> = number_chosen.split(',').filter_map(|s| s.trim().parse::<usize>().ok()).collect();
        let mut handles = Vec::new();

        for id in ids {
            let con = connection.clone();
            let handle = tokio::spawn(async move {
                let (mut send, recv) = con.open_bi().await.expect("Failed to open stream");
                send.write_all(&[3u8]).await.unwrap();
                send.write_all(&(id as u64).to_be_bytes()).await.unwrap();
                println!("Requesting file num: {}", id);
                handle_recieved_file(send, recv).await;
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
        println!("Finished all requests successfully.");
    }
}

// ------------------- FILE TRANSFER & INDEXING -------------------

async fn filing(file_path: &str, file_send: SendStream) -> u64 {
    let file = tokio::fs::File::open(file_path).await.unwrap();
    let file_metadata = file.metadata().await.unwrap();
    let file_size = file_metadata.len();
    let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
    let name_bytes = file_name.as_bytes().to_vec();
    let name_size = name_bytes.len() as u16;
    sending_file(file_send, name_size, name_bytes, file_size, file).await;
    file_size
}

async fn sending_file(
    mut file_send: SendStream,
    name_size: u16,
    name_bytes: Vec<u8>,
    file_size: u64,
    mut file: tokio::fs::File,
) {
    file_send.write_all(&name_size.to_be_bytes()).await.unwrap();
    file_send.write_all(&name_bytes).await.unwrap();
    file_send.write_all(&file_size.to_be_bytes()).await.unwrap();
    let _ = tokio::io::copy(&mut file, &mut file_send).await;
    let _ = file_send.finish();
}

async fn handle_recieved_file(mut file_send: quinn::SendStream, mut file_recv: quinn::RecvStream) {
    let mut name_size_buf = [0u8; 2];
    file_recv.read_exact(&mut name_size_buf).await.expect("Failed name size read");
    let name_size = u16::from_be_bytes(name_size_buf) as usize;

    let mut name_buf = vec![0u8; name_size];
    file_recv.read_exact(&mut name_buf).await.expect("Failed name read");
    let file_name = String::from_utf8(name_buf).unwrap();

    let mut file_size_buf = [0u8; 8];
    file_recv.read_exact(&mut file_size_buf).await.expect("Failed size read");

    let where_to_write = "/sdcard/Download/";
    let mut path = PathBuf::from(where_to_write);
    path.push(&file_name);

    if path.exists() {
        println!("File already exists: {:?}", path);
        let _ = file_send.write_all(b"ALREADY_EXISTS").await;
        let _ = file_send.finish();
    } else {
        let mut received_file = tokio::fs::File::create(&path).await.unwrap();
        tokio::io::copy(&mut file_recv, &mut received_file).await.expect("Copy failed");
        received_file.flush().await.expect("Flush failed");
        println!("File saved successfully to: {:?}", path);
    }
}

async fn handle_sending_json(
    mut send: quinn::SendStream,
    _recv: quinn::RecvStream,
    json_bytes: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
) {
    send.write_all(&(json_bytes.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&json_bytes).await.unwrap();
    send.write_all(&(salt.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&salt).await.unwrap();
    send.write_all(&(nonce.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&nonce).await.unwrap();
    let _ = send.finish();
}

async fn handle_sending_requested_file(dev_idx: DeviceIndex, send: quinn::SendStream, target_id: usize) {
    if let Some(target_file) = dev_idx.files.iter().find(|file| file.id == target_id) {
        filing(target_file.path.to_str().unwrap(), send).await;
    }
}

async fn receive_json_call(connection: &quinn::Connection) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[2u8]).await.unwrap();
    let _ = send.finish();

    let mut json_len_buffer = [0u8; 8];
    recv.read_exact(&mut json_len_buffer).await.unwrap();
    let json_len = u64::from_be_bytes(json_len_buffer) as usize;
    let mut encrypted_json = vec![0u8; json_len];
    recv.read_exact(&mut encrypted_json).await.unwrap();

    let mut salt_len_buffer = [0u8; 8];
    recv.read_exact(&mut salt_len_buffer).await.unwrap();
    let salt_len = u64::from_be_bytes(salt_len_buffer) as usize;
    let mut salt = vec![0u8; salt_len];
    recv.read_exact(&mut salt).await.unwrap();

    let mut nonce_len_buffer = [0u8; 8];
    recv.read_exact(&mut nonce_len_buffer).await.unwrap();
    let nonce_len = u64::from_be_bytes(nonce_len_buffer) as usize;
    let mut nonce = vec![0u8; nonce_len];
    recv.read_exact(&mut nonce).await.unwrap();

    let pin = get_input("Enter the device pin: ").await;
    match decrypt_json(&encrypted_json, &salt, &nonce, &pin) {
        Ok(f) => {
            println!("Decrypted successfully!");
            for file in &f.files {
                println!(
                    "{} - Name: {}, Size: {} bytes, Path: {:?}, Parent: {:?}",
                    file.id,
                    file.name,
                    file.size,
                    file.path,
                    file.parent_dir.as_deref().unwrap_or("Root")
                );
            }
        }
        Err(e) => println!("Error while decrypting: {}", e),
    }
}

async fn file_indexing(all_files: &mut Vec<FileIndexing>, counter: &mut usize, root_path: PathBuf) {
    let mut dirs_to_scan = vec![root_path];
    while let Some(current_dir) = dirs_to_scan.pop() {
        if let Ok(mut entries) = tokio::fs::read_dir(&current_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                let path = entry.path();
                if is_dir {
                    dirs_to_scan.push(path);
                } else {
                    let file = FileIndexing {
                        id: *counter,
                        name: entry.file_name().to_string_lossy().to_string(),
                        size: entry.metadata().await.map(|m| m.len()).unwrap_or(0),
                        path: entry.path(),
                        is_dir: false,
                        parent_dir: path.parent().and_then(|p| p.file_name()).map(|name| name.to_string_lossy().to_string()),
                    };
                    *counter += 1;
                    all_files.push(file);
                }
            }
        }
    }
}

async fn json_retrieving() -> (Vec<u8>, Vec<u8>, Vec<u8>, DeviceIndex) {
    let mut all_files: Vec<FileIndexing> = Vec::new();
    let mut counter: usize = 1;
    file_indexing(&mut all_files, &mut counter, PathBuf::from("/sdcard/Download")).await;
    let device = DeviceIndex { files: all_files };
    let json_bytes = serde_json::to_vec(&device).unwrap();
    let (encrypted_json, salt, nonce) = encrypting_json(json_bytes).await;
    (encrypted_json, salt, nonce, device)
}

async fn encrypting_json(json_bytes: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let pin = "1234";
    let mut key_bytes = [0u8; 32];
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);

    Argon2::default().hash_password_into(pin.as_bytes(), &salt, &mut key_bytes).unwrap();
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).unwrap();
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).unwrap();

    let encrypted_bytes = cipher.encrypt(&nonce, json_bytes.as_ref()).unwrap();
    (encrypted_bytes, nonce_bytes.to_vec(), salt.to_vec())
}

fn decrypt_json(
    encrypted_bytes: &[u8],
    salt: &[u8],
    nonce_bytes: &[u8],
    pin: &String,
) -> Result<DeviceIndex, Box<dyn std::error::Error>> {
    let mut key_bytes = [0u8; 32];
    Argon2::default().hash_password_into(pin.as_bytes(), salt, &mut key_bytes)?;
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice())?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(nonce_bytes)?;
    let decrypted_bytes = cipher.decrypt(&nonce, encrypted_bytes)?;
    let device_index: DeviceIndex = serde_json::from_slice(&decrypted_bytes)?;
    Ok(device_index)
}

// ------------------- MAIN -------------------

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();
    let (cert_chain, key) = make_cert_and_key().await;

    println!("Indexing files in /sdcard/Download...");
    let (encrypted_json, salt, nonce, device_index) = json_retrieving().await;

    tokio::spawn(async move {
        server(cert_chain, key, encrypted_json, salt, nonce, device_index).await;
    });

    let response = get_input("Do you want to run the client? (y/n)").await;
    if response.to_lowercase() == "y" {
        client().await;
    } else {
        println!("Server running in background. Press Ctrl+C to stop.");
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}