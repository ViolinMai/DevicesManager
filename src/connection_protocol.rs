use quinn::{self, Endpoint, SendStream, ServerConfig};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::fs;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use whoami;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

static APP_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_app_data_dir(path: PathBuf) {
    let _ = APP_DATA_DIR.set(path);
}

pub fn get_app_data_path(filename: &str) -> PathBuf {
    let base = APP_DATA_DIR.get().cloned().unwrap_or_else(|| PathBuf::from("./data"));
    base.join(filename)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub device_name: String,
    pub share_roots: Vec<PathBuf>,
    pub download_dir: PathBuf,
    pub broadcast_addr: String,
}

impl AppConfig {
    pub async fn load_or_create() -> Result<Self, AppError> {
        let config_path = get_app_data_path("config.json");
        if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)?;
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                return Ok(cfg);
            }
            #[derive(Deserialize)]
            struct LegacyConfig {
                device_name: String,
                share_root: PathBuf,
                download_dir: PathBuf,
                broadcast_addr: String,
            }
            if let Ok(legacy) = serde_json::from_str::<LegacyConfig>(&data) {
                let upgraded = AppConfig {
                    device_name: legacy.device_name,
                    share_roots: vec![legacy.share_root],
                    download_dir: legacy.download_dir,
                    broadcast_addr: legacy.broadcast_addr,
                };
                let _ = upgraded.save();
                return Ok(upgraded);
            }
        }
        
        let fallback_name = get_fallback_device_name();
        let default_cfg = AppConfig {
            device_name: fallback_name,
            share_roots: vec![get_app_data_path("shared")],
            download_dir: get_app_data_path("downloads"),
            broadcast_addr: "192.168.1.255:8888".to_string(),
        };

        if let Some(parent) = config_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_string_pretty(&default_cfg)?;
        std::fs::write(&config_path, data)?;
        Ok(default_cfg)
    }

    pub fn save(&self) -> Result<(), AppError> {
        let config_path = get_app_data_path("config.json");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, data)?;
        Ok(())
    }
}

pub struct PeersStorage;

impl PeersStorage {
    fn path() -> PathBuf {
        get_app_data_path("peers.json")
    }

    pub fn load() -> Result<HashMap<String, String>, AppError> {
        let p = Self::path();
        if !p.exists() {
            return Ok(HashMap::new());
        }
        let data = std::fs::read_to_string(&p)?;
        let peers: HashMap<String, String> = serde_json::from_str(&data)?;
        Ok(peers)
    }

    pub fn save(peers: &HashMap<String, String>) -> Result<(), AppError> {
        let p = Self::path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_string_pretty(peers)?;
        std::fs::write(p, data)?;
        Ok(())
    }

    pub fn trust_peer(device_name: String, fingerprint: String) -> Result<(), AppError> {
        let mut peers = Self::load()?;
        peers.insert(device_name, fingerprint);
        Self::save(&peers)
    }
}

pub struct ServerHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    pub async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }
}

pub fn start_server_with_channel(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    config_lock: Arc<RwLock<AppConfig>>,
    pairing_tx: Option<mpsc::Sender<PairingRequest>>,
) -> ServerHandle {
    let shutdown = CancellationToken::new();
    let shutdown_for_server = shutdown.clone();

    let task = tokio::spawn(async move {
        if let Err(e) = server(cert_chain, key, shutdown_for_server, config_lock, pairing_tx).await {
            eprintln!("[SERVER] ❌ Server encountered error: {:?}", e);
        }
    });

    ServerHandle { shutdown, task }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceInfo {
    pub index: u8,
    pub name: String,
    pub ip: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub device_name: String,
    pub fingerprint: String,
}

#[derive(Debug)]
pub enum AppError {
    NetworkError(String),
    FileNotFound(u64),
    AlreadyExists,
    IncompleteTransfer { expected: u64, got: u64 },
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    Utf8Error(std::string::FromUtf8Error),
    InvalidFileName,
    InvalidInput(String),
    ServerNotFound,
    QuinnConnectionError(quinn::ConnectionError),
    QuinnConnectError(quinn::ConnectError),
    QuinnReadExactError(quinn::ReadExactError),
    QuinnReadToEndError(quinn::ReadToEndError),
    QuinnWriteError(quinn::WriteError),
    RustlsError(rustls::Error),
    TokioJoinError(tokio::task::JoinError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
            AppError::FileNotFound(id) => write!(f, "File ID {} not found", id),
            AppError::AlreadyExists => write!(f, "File already exists"),
            AppError::IncompleteTransfer { expected, got } => write!(f, "Incomplete transfer: expected {} bytes, got {}", expected, got),
            AppError::IoError(e) => write!(f, "I/O Error: {}", e),
            AppError::JsonError(e) => write!(f, "JSON Error: {}", e),
            AppError::Utf8Error(e) => write!(f, "UTF-8 Conversion Error: {}", e),
            AppError::InvalidFileName => write!(f, "Invalid file name"),
            AppError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            AppError::ServerNotFound => write!(f, "Selected server not found"),
            AppError::QuinnConnectionError(e) => write!(f, "QUIC Connection Error: {}", e),
            AppError::QuinnConnectError(e) => write!(f, "QUIC Connect Error: {}", e),
            AppError::QuinnReadExactError(e) => write!(f, "QUIC Read Error: {}", e),
            AppError::QuinnReadToEndError(e) => write!(f, "QUIC Read-to-End Error: {}", e),
            AppError::QuinnWriteError(e) => write!(f, "QUIC Write Error: {}", e),
            AppError::RustlsError(e) => write!(f, "TLS Error: {}", e),
            AppError::TokioJoinError(e) => write!(f, "Task Join Error: {}", e),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError { fn from(err: std::io::Error) -> Self { AppError::IoError(err) } }
impl From<serde_json::Error> for AppError { fn from(err: serde_json::Error) -> Self { AppError::JsonError(err) } }
impl From<std::string::FromUtf8Error> for AppError { fn from(err: std::string::FromUtf8Error) -> Self { AppError::Utf8Error(err) } }
impl From<quinn::ConnectionError> for AppError { fn from(err: quinn::ConnectionError) -> Self { AppError::QuinnConnectionError(err) } }
impl From<quinn::ConnectError> for AppError { fn from(err: quinn::ConnectError) -> Self { AppError::QuinnConnectError(err) } }
impl From<quinn::ReadExactError> for AppError { fn from(err: quinn::ReadExactError) -> Self { AppError::QuinnReadExactError(err) } }
impl From<quinn::ReadToEndError> for AppError { fn from(err: quinn::ReadToEndError) -> Self { AppError::QuinnReadToEndError(err) } }
impl From<quinn::WriteError> for AppError { fn from(err: quinn::WriteError) -> Self { AppError::QuinnWriteError(err) } }
impl From<rustls::Error> for AppError { fn from(err: rustls::Error) -> Self { AppError::RustlsError(err) } }
impl From<tokio::task::JoinError> for AppError { fn from(err: tokio::task::JoinError) -> Self { AppError::TokioJoinError(err) } }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileIndexing {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub path: PathBuf,
    pub is_dir: bool,
    pub parent_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DeviceIndex {
    pub files: Vec<FileIndexing>,
}

#[derive(Debug)]
struct TofuClientVerifier {
    pairing_tx: Option<mpsc::Sender<PairingRequest>>,
}

impl ClientCertVerifier for TofuClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] { &[] }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let current_fingerprint = hex::encode(hasher.finalize());

        let known_peers = PeersStorage::load().map_err(|e| {
            rustls::Error::General(format!("Failed to load trusted peers: {}", e))
        })?;

        if known_peers.values().any(|fp| fp == &current_fingerprint) {
            return Ok(ClientCertVerified::assertion());
        }

        let client_name = format!("Peer-{}", &current_fingerprint[..8]);
        if let Some(ref tx) = self.pairing_tx {
            let _ = tx.try_send(PairingRequest {
                device_name: client_name.clone(),
                fingerprint: current_fingerprint.clone(),
            });
        }

        Err(rustls::Error::General(format!("Untrusted client: {}. Pairing requested.", client_name)))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct TofuVerifier {
    target_device_name: String,
    pairing_tx: Option<mpsc::Sender<PairingRequest>>,
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

        let known_peers = PeersStorage::load().map_err(|e| {
            rustls::Error::General(format!("Failed to load trusted peers: {}", e))
        })?;

        if let Some(saved_fingerprint) = known_peers.get(&self.target_device_name) {
            if saved_fingerprint == &current_fingerprint {
                return Ok(ServerCertVerified::assertion());
            } else {
                eprintln!("\n⚠️ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! ⚠️");
                return Err(rustls::Error::General("Host key fingerprint mismatch!".into()));
            }
        }

        if let Some(ref tx) = self.pairing_tx {
            let _ = tx.try_send(PairingRequest {
                device_name: self.target_device_name.clone(),
                fingerprint: current_fingerprint.clone(),
            });
        }

        Err(rustls::Error::General(format!("Untrusted server: {}. Pairing requested.", self.target_device_name)))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn get_fallback_device_name() -> String {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        let devname = whoami::devicename().unwrap_or_else(|_| "Desktop-Unknown".to_string());
        if devname != "localhost" && !devname.is_empty() {
            return devname;
        }
        format!("{}", whoami::platform())
    }

    #[cfg(target_os = "android")]
    {
        "Android Device".to_string()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos", target_os = "android")))]
    {
        "Generic Device".to_string()
    }
}

pub async fn make_cert_and_key() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AppError> {
    let cert_path = get_app_data_path("cert.der");
    let key_path = get_app_data_path("key.der");

    if cert_path.exists() && key_path.exists(){
        let cert_bytes = std::fs::read(&cert_path)?;
        let key_bytes = std::fs::read(&key_path)?;

        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivatePkcs8KeyDer::from(key_bytes);
        let key = PrivateKeyDer::Pkcs8(key_der);
        return Ok((vec![cert_der], key));
    }

    let subject_alt_names = vec!["localhost".to_string()];
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).map_err(|e| AppError::NetworkError(e.to_string()))?;
    let cert_raw = cert.der().to_vec();
    let key_raw = signing_key.serialize_der();

    if let Some(parent) = cert_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    std::fs::write(&cert_path, &cert_raw)?;
    std::fs::write(&key_path, &key_raw)?;

    let cert_der = CertificateDer::from(cert_raw);
    let key: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_raw));

    Ok((vec![cert_der], key))
}

async fn server(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    shutdown: CancellationToken,
    config_lock: Arc<RwLock<AppConfig>>,
    pairing_tx: Option<mpsc::Sender<PairingRequest>>,
) -> Result<(), AppError> {
    let client_verifier = Arc::new(TofuClientVerifier { pairing_tx });
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;

    let mut config_quinn = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| AppError::NetworkError(format!("{:?}", e)))?,
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(|_| AppError::NetworkError("Timeout conversion failed".to_string()))?));
    config_quinn.transport_config(Arc::new(transport_config));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
    let endpoint = Endpoint::server(config_quinn, addr)?;
    println!("\n[SERVER] 🚀 QUIC Server is listening on {}", addr);

    let listen_socket = tokio::net::UdpSocket::bind("0.0.0.0:8888").await?;
    let discovery_shutdown = shutdown.clone();
    let cfg_clone = Arc::clone(&config_lock);

    let discovery_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = discovery_shutdown.cancelled() => break,
                result = listen_socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((bytes_read, client_addr)) => {
                            let incoming_msg = String::from_utf8_lossy(&buffer[..bytes_read]);
                            if incoming_msg.trim() == "WHO IS THE SERVER?" {
                                let dev_name = {
                                    cfg_clone.read().map(|c| c.device_name.clone()).unwrap_or_else(|_| "Unknown".into())
                                };
                                let reply_message = format!("DM1:{}", dev_name);
                                let _ = listen_socket.send_to(reply_message.as_bytes(), client_addr).await;
                            }
                        },
                        Err(ref e) if e.raw_os_error() == Some(10040) => continue,
                        Err(_) => {}
                    }
                }
            }
        }
    });

    loop {
        let incoming = tokio::select! {
            _ = shutdown.cancelled() => break,
            maybe_incoming = endpoint.accept() => match maybe_incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
        let current_cfg_lock = Arc::clone(&config_lock);
        
        tokio::spawn(async move {
            let call = match incoming.await {
                Ok(conn) => conn,
                Err(_) => return,
            };

            let (share_roots, download_dir) = {
                let r = current_cfg_lock.read().unwrap();
                (r.share_roots.clone(), r.download_dir.clone())
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
                        let dl = download_dir.clone();
                        tokio::spawn(async move {
                            let _ = handle_recieved_file(send, recv, &dl).await;
                        });
                    }
                    2 => {
                        let roots = share_roots.clone();
                        tokio::spawn(async move {
                            let (json_bytes, dev_index) = tokio::task::spawn_blocking(move || {
                                build_full_multithreaded_index(&roots)
                            }).await.unwrap_or_default();
                            
                            println!("[SERVER] 📤 Sending multi-threaded index: {} items ({} bytes)", dev_index.files.len(), json_bytes.len());
                            let _ = handle_sending_json(send, recv, json_bytes).await;
                        });
                    }
                    3 => {
                        let roots = share_roots.clone();
                        tokio::spawn(async move {
                            let mut id_buf = [0u8; 8];
                            if recv.read_exact(&mut id_buf).await.is_ok() {
                                let target_id = u64::from_be_bytes(id_buf);
                                if let Some(target_file) = find_file_flat(&roots, target_id).await {
                                    let _ = filing(target_file.path.to_str().unwrap(), send).await;
                                }
                            }
                        });
                    }
                    _ => {}
                }
            }
        });
    }

    endpoint.close(0u32.into(), b"server shutting down");
    let _ = discovery_task.await;
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    Ok(())
}

pub async fn discover_network_devices(broadcast_addr: &str) -> Result<Vec<DeviceInfo>, AppError> {
    let broadcast_socket = UdpSocket::bind("0.0.0.0:0").await?;
    broadcast_socket.set_broadcast(true)?;
    broadcast_socket.send_to(b"WHO IS THE SERVER?", broadcast_addr).await?;

    let mut responses = vec![0u8; 65535];
    let mut discovered_servers: Vec<DeviceInfo> = Vec::new();
    let mut index: u8 = 1;

    loop {
        match tokio::time::timeout(Duration::from_millis(1500), broadcast_socket.recv_from(&mut responses)).await {
            Ok(Ok((bytes_read, server_addr))) => {
                let msg = String::from_utf8_lossy(&responses[..bytes_read]).trim().to_string();
                if let Some(name) = msg.strip_prefix("DM1:") {
                    discovered_servers.push(DeviceInfo {
                        index,
                        name: name.to_string(),
                        ip: server_addr,
                    });
                    index += 1;
                }
            }
            Ok(Err(ref e)) if e.raw_os_error() == Some(10040) => continue,
            _ => break,
        }
    }
    Ok(discovered_servers)
}

pub async fn connect_to_server(
    target_addr: SocketAddr,
    target_name: String,
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pairing_tx: Option<mpsc::Sender<PairingRequest>>,
) -> Result<quinn::Connection, AppError> {
    let addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| AppError::NetworkError(e.to_string()))?;
    let mut client = Endpoint::client(addr)?;

    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TofuVerifier {
            target_device_name: target_name,
            pairing_tx,
        }))
        .with_client_auth_cert(cert, key)?;

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| AppError::NetworkError(format!("{:?}", e)))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(|_| AppError::NetworkError("Timeout conversion failed".to_string()))?));
    transport_config.keep_alive_interval(Some(Duration::from_secs(2)));

    client_config.transport_config(Arc::new(transport_config));
    client.set_default_client_config(client_config);

    let call = client.connect(target_addr, "localhost")?.await;
    let connection = call?;
    Ok(connection)
}

pub async fn fetch_device_index(connection: &quinn::Connection) -> Result<DeviceIndex, AppError> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&[2u8]).await?;
    let _ = send.finish();

    let mut json_len_buffer = [0u8; 8];
    recv.read_exact(&mut json_len_buffer).await?;
    let json_len = u64::from_be_bytes(json_len_buffer) as usize;

    let mut json_buffer = vec![0u8; json_len];
    recv.read_exact(&mut json_buffer).await?;

    let device_index: DeviceIndex = serde_json::from_slice(&json_buffer)?;
    Ok(device_index)
}

pub async fn download_requested_file(
    connection: &quinn::Connection,
    id: u64,
    download_dir: PathBuf,
) -> Result<(), AppError> {
    let (mut send, recv) = connection.open_bi().await?;
    send.write_all(&[3u8]).await?;
    send.write_all(&id.to_be_bytes()).await?;
    handle_recieved_file(send, recv, &download_dir).await?;
    Ok(())
}

async fn filing(file_path: &str, file_send: SendStream) -> Result<u64, AppError> {
    let file = tokio::fs::File::open(file_path).await?;
    let file_metadata = file.metadata().await?;
    let file_size = file_metadata.len();
    let file_name = Path::new(file_path).file_name().and_then(|n| n.to_str()).ok_or(AppError::InvalidFileName)?;
    let name_bytes = file_name.as_bytes().to_vec();
    let name_size = name_bytes.len() as u16;
    sending_file(file_send, name_size, name_bytes, file_size, file).await?;
    Ok(file_size)
}

async fn sending_file(
    mut file_send: SendStream,
    name_size: u16,
    name_bytes: Vec<u8>,
    file_size: u64,
    mut file: tokio::fs::File,
) -> Result<(), AppError> {
    let start_time = std::time::Instant::now();
    file_send.write_all(&name_size.to_be_bytes()).await?;
    file_send.write_all(&name_bytes).await?;
    file_send.write_all(&file_size.to_be_bytes()).await?;
    let _ = tokio::io::copy(&mut file, &mut file_send).await?;
    let _ = file_send.finish();

    let duration = start_time.elapsed();
    let size_mb: f32 = file_size as f32 / (1024.0 * 1024.0);
    let speed_mb_s: f32 = size_mb / duration.as_secs_f32();
    println!("[SERVER] ✅ Transfer complete: {} MB, Duration: {:.2}s, Speed: {:.2} MB/s", size_mb, duration.as_secs_f32(), speed_mb_s);
    Ok(())
}

async fn handle_recieved_file(mut file_send: quinn::SendStream, mut file_recv: quinn::RecvStream, download_dir: &Path) -> Result<(), AppError> {
    let mut name_size_buf = [0u8; 2];
    file_recv.read_exact(&mut name_size_buf).await?;
    let name_size = u16::from_be_bytes(name_size_buf) as usize;

    let mut name_buf = vec![0u8; name_size];
    file_recv.read_exact(&mut name_buf).await?;
    let file_name = String::from_utf8(name_buf)?;

    let mut file_size_buf = [0u8; 8];
    file_recv.read_exact(&mut file_size_buf).await?;
    let file_size = u64::from_be_bytes(file_size_buf);

    if !download_dir.exists() {
        tokio::fs::create_dir_all(download_dir).await?;
    }

    let clean_file_name = Path::new(&file_name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(AppError::InvalidFileName)?;

    let mut path = download_dir.to_path_buf();
    path.push(clean_file_name);
    if path.exists() {
        file_send.write_all(b"ALREADY_EXISTS").await?;
        let _ = file_send.finish();
        return Ok(());
    }

    let unique_tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let previous_file = download_dir.join(format!("{}.{}.part", clean_file_name, unique_tag));
    let final_file = download_dir.join(clean_file_name);

    let mut recived_file = tokio::fs::File::create(&previous_file).await?;
    let bytes_copied = tokio::io::copy(&mut file_recv, &mut recived_file).await?;
    recived_file.flush().await?;
    drop(recived_file);

    if bytes_copied == file_size {
        fs::rename(&previous_file, &final_file).await?;
        Ok(())
    } else {
        let _ = tokio::fs::remove_file(&previous_file).await;
        Err(AppError::IncompleteTransfer { expected: file_size, got: bytes_copied })
    }
}

async fn handle_sending_json(mut send: quinn::SendStream, mut _recv: quinn::RecvStream, json_bytes: Vec<u8>) -> Result<(), AppError> {
    send.write_all(&(json_bytes.len() as u64).to_be_bytes()).await?;
    send.write_all(&json_bytes).await?;
    let _ = send.finish();
    Ok(())
}

fn compute_stable_file_id(path_str: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(path_str.as_bytes());
    let hash = hasher.finalize();
    u64::from_be_bytes(hash[0..8].try_into().unwrap())
}

/// حساب عدد الخيوط المناسبة تلقائياً حسب قدرة المعالج والنظام
fn get_optimal_worker_count() -> usize {
    let total_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    #[cfg(target_os = "android")]
    {
        // على أندرويد: نقيد الخيوط بحد أقصى مسارين لحفظ البطارية والحرارة
        total_cores.min(2).max(1)
    }

    #[cfg(not(target_os = "android"))]
    {
        // على الكمبيوتر (ويندوز/لينكس): استغلال ما يقارب 75% إلى 80% من المسارات (مثلاً 20-22 مسار من أصل 28)
        if total_cores > 8 {
            (total_cores * 3) / 4
        } else {
            total_cores.max(2)
        }
    }
}

/// بناء الفهرس بشكل متوازي متعدد الخيوط فائق السرعة
pub fn build_full_multithreaded_index(roots: &[PathBuf]) -> (Vec<u8>, DeviceIndex) {
    let start_time = std::time::Instant::now();
    let num_workers = get_optimal_worker_count();
    println!("[INDEXER] ⚙️ Starting multi-threaded indexing using {} worker threads...", num_workers);

    let queue: Arc<StdMutex<Vec<(PathBuf, String)>>> = Arc::new(StdMutex::new(Vec::new()));
    let results: Arc<StdMutex<Vec<FileIndexing>>> = Arc::new(StdMutex::new(Vec::new()));

    // 1. تسجيل الجذور الرئيسية في النتائج وطابور الفحص
    for root in roots {
        if !root.exists() { continue; }
        let root_name = root.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| root.to_string_lossy().to_string());

        let root_id = compute_stable_file_id(&root.to_string_lossy());
        results.lock().unwrap().push(FileIndexing {
            id: root_id,
            name: root_name.clone(),
            size: 0,
            path: root.clone(),
            is_dir: true,
            parent_dir: None,
        });

        queue.lock().unwrap().push((root.clone(), root_name));
    }

    // 2. إطلاق مجموعة الـ Worker Threads للفحص المتوازي
    std::thread::scope(|s| {
        for _ in 0..num_workers {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);

            s.spawn(move || {
                let sensitive = ["key.der", "cert.der", "peers.json", "config.json"];
                loop {
                    // سحب مجلد للمعالجة
                    let task = {
                        let mut q = queue.lock().unwrap();
                        q.pop()
                    };

                    let (current_dir, parent_folder_name) = match task {
                        Some(t) => t,
                        None => break, // انتهت المهام
                    };

                    if let Ok(entries) = std::fs::read_dir(&current_dir) {
                        let mut local_new_dirs = Vec::new();
                        let mut local_items = Vec::new();

                        for entry in entries.flatten() {
                            let fname = entry.file_name().to_string_lossy().to_string();
                            if sensitive.contains(&fname.as_str()) || fname.ends_with(".part") {
                                continue;
                            }
                            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                            let p = entry.path();
                            let file_id = compute_stable_file_id(&p.to_string_lossy());
                            let size = if is_dir { 0 } else { entry.metadata().map(|m| m.len()).unwrap_or(0) };

                            local_items.push(FileIndexing {
                                id: file_id,
                                name: fname.clone(),
                                size,
                                path: p.clone(),
                                is_dir,
                                parent_dir: Some(parent_folder_name.clone()),
                            });

                            if is_dir {
                                local_new_dirs.push((p, fname));
                            }
                        }

                        // حفظ النتائج وإعادة إضافة المجلدات الجديدة للطابور
                        results.lock().unwrap().extend(local_items);
                        if !local_new_dirs.is_empty() {
                            queue.lock().unwrap().extend(local_new_dirs);
                        }
                    }
                }
            });
        }
    });

    let mut final_files = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    // ترتيب: المجلدات أولاً ثم ترتيب أبجدي
    final_files.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));

    let index = DeviceIndex { files: final_files };
    let json_bytes = serde_json::to_vec(&index).unwrap_or_default();
    println!("[INDEXER] ⚡ Indexed {} files & folders in {:.2?} ({} KB)", index.files.len(), start_time.elapsed(), json_bytes.len() / 1024);
    (json_bytes, index)
}

async fn find_file_flat(roots: &[PathBuf], target_id: u64) -> Option<FileIndexing> {
    let (_, index) = build_full_multithreaded_index(roots);
    index.files.into_iter().find(|f| f.id == target_id)
}
