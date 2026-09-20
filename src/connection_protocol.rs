use quinn::{self, Endpoint, SendStream, ServerConfig};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;
use std::io::Write;
use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tokio::fs;
use whoami;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(target_os = "android")]
use jni::{objects::JString, JNIEnv};

struct DeviceInfo {
    index: u8,
    name: String,
    ip: SocketAddr,
}

#[derive(Debug)]
pub enum AppError {
    NetworkError(String),
    FileNotFound(usize),
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

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::IoError(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::JsonError(err)
    }
}

impl From<std::string::FromUtf8Error> for AppError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        AppError::Utf8Error(err)
    }
}

impl From<quinn::ConnectionError> for AppError {
    fn from(err: quinn::ConnectionError) -> Self {
        AppError::QuinnConnectionError(err)
    }
}

impl From<quinn::ConnectError> for AppError {
    fn from(err: quinn::ConnectError) -> Self {
        AppError::QuinnConnectError(err)
    }
}

impl From<quinn::ReadExactError> for AppError {
    fn from(err: quinn::ReadExactError) -> Self {
        AppError::QuinnReadExactError(err)
    }
}

impl From<quinn::ReadToEndError> for AppError {
    fn from(err: quinn::ReadToEndError) -> Self {
        AppError::QuinnReadToEndError(err)
    }
}

impl From<quinn::WriteError> for AppError {
    fn from(err: quinn::WriteError) -> Self {
        AppError::QuinnWriteError(err)
    }
}

impl From<rustls::Error> for AppError {
    fn from(err: rustls::Error) -> Self {
        AppError::RustlsError(err)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(err: tokio::task::JoinError) -> Self {
        AppError::TokioJoinError(err)
    }
}

// JSON STRUCT
#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileIndexing {
    id: usize,
    name: String,
    size: u64,
    path: std::path::PathBuf,
    is_dir: bool,
    parent_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeviceIndex {
    files: Vec<FileIndexing>,
}

use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

#[derive(Debug)]
struct TofuClientVerifier;

impl ClientCertVerifier for TofuClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let current_fingerprint = hex::encode(hasher.finalize());

        let peers_file = "known_peers.json";
        let mut known_peers: HashMap<String, String> = if Path::new(peers_file).exists() {
            let data = std::fs::read_to_string(peers_file).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        // التحقق مما إذا كانت بصمة هذا العميل معروفة ومسجلة مسبقاً
        if known_peers.values().any(|fp| fp == &current_fingerprint) {
            return Ok(ClientCertVerified::assertion());
        }

        println!("\n[Security] Unknown client is trying to connect!");
        println!("[Security] Client Fingerprint: {}", current_fingerprint);

        print!("Do you want to accept and pair with this device? (y/n): ");
        let _ = std::io::stdout().flush();
        let mut choice = String::new();
        let _ = std::io::stdin().read_line(&mut choice);

        if choice.trim().to_lowercase() != "y" {
            return Err(rustls::Error::General("Client rejected by user".into()));
        }

        // تسجيل العميل بالبصمة
        let client_id = format!("Peer-{}", &current_fingerprint[..8]);
        known_peers.insert(client_id, current_fingerprint);
        let _ = std::fs::write(peers_file, serde_json::to_string_pretty(&known_peers).unwrap());
        println!("[Security] Client trusted and saved!");

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
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
            message,
            cert,
            dss,
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
        // reading the hash cert coming
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let current_fingerprint = hex::encode(hasher.finalize());
        // here we make a json for known peers we prevuoesly dealt with
        let peers_file = "known_peers.json";
        let mut known_peers: HashMap<String, String> = if Path::new(peers_file).exists() {
            let data = std::fs::read_to_string(peers_file).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        // checking if that device is known
        if let Some(saved_fingerprint) = known_peers.get(&self.target_device_name) {
            if saved_fingerprint == &current_fingerprint {
                // we know him
                return Ok(ServerCertVerified::assertion());
            } else {
                // WHO IS THAT GUY????
                eprintln!("\n⚠️ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! ⚠️");
                return Err(rustls::Error::General("Host key fingerprint mismatch!".into()));
            }
        }

        // first date
        println!("\n[Security] New device discovered: {}", self.target_device_name);
        println!("[Security] Fingerprint: {}", current_fingerprint);
        
        // getting their contact
        print!("Do you want to trust this device? (y/n): ");
        let _ = std::io::stdout().flush();
        let mut user_choice = String::new();
        let _ = std::io::stdin().read_line(&mut user_choice);

        if user_choice.trim().to_lowercase() != "y" {
            return Err(rustls::Error::General("User rejected the peer fingerprint".into()));
        }
        known_peers.insert(self.target_device_name.clone(), current_fingerprint);
        let json_data = serde_json::to_string_pretty(&known_peers).unwrap();
        let _ = std::fs::write(peers_file, json_data);
        println!("[Security] Device trusted and stored in known_peers.json");

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
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
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(target_os = "android")]
use jni::{objects::JString, JNIEnv};

/// Tries to fetch a recognizable system model or device name. 
pub fn get_fallback_device_name(#[cfg(target_os = "android")] env: &mut JNIEnv) -> String {
    
    //WINDOWS & LINUX
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        // Try getting the computer name first (e.g., "Desktop-XYZ")
        let devname = whoami::devicename().unwrap_or_else(|_| "Desktop-Unknown".to_string());
        if devname != "localhost" && !devname.is_empty() {
            return devname;
        }
        
        // Fallback to OS type if computer name is generic
        format!("{}", whoami::platform())
    }

    //ANDROID
    #[cfg(target_os = "android")]
    {
        // Retrieves the manufacturing string + model code
        get_android_hardware_details(env).unwrap_or_else(|_| "Android Device".to_string())
    }

    // FALLBACK FOR OTHER OS
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "android")))]
    {
        "Generic Device".to_string()
    }
}

/// Combines Manufacturer + Model to give the user a highly recognizable code
#[cfg(target_os = "android")]
fn get_android_hardware_details(env: &mut JNIEnv) -> Result<String, jni::errors::Error> {
    let build_class = env.find_class("android/os/Build")?;
    
    // 1. Get Manufacturer (e.g., "Samsung")
    let manu_jstring: JString = env.get_static_field(build_class, "MANUFACTURER", "Ljava/lang/String;")?
        .l()?.into();
    let manufacturer: String = env.get_string(&manu_jstring)?.into();

    // 2. Get Model Code (e.g., "SM-S928B")
    let model_jstring: JString = env.get_static_field(build_class, "MODEL", "Ljava/lang/String;")?
        .l()?.into();
    let model: String = env.get_string(&model_jstring)?.into();
    
    Ok(format!("{} {}", manufacturer, model))
}

async fn get_input(prompt: &str) -> Result<String, AppError> {
    println!("{}", prompt);
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    
    reader.read_line(&mut line).await?;
    
    Ok(line.trim().to_string())
}

// This makes a new certificate and key and send it to main
async fn make_cert_and_key() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AppError> {
    let cert_path = Path::new("cert.der");
    let key_path = Path::new("key.der");

    if cert_path.exists() && key_path.exists(){
        let cert_bytes = std::fs::read(cert_path)?;
        let key_bytes = std::fs::read(key_path)?;

        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivatePkcs8KeyDer::from(key_bytes);
        let key = PrivateKeyDer::Pkcs8(key_der);
        return Ok((vec![cert_der], key));
    }
    //(1)
    // server_name
    let subject_alt_names = vec!["localhost".to_string()];

    // generating a certificate
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).map_err(|e| AppError::NetworkError(e.to_string()))?;
    let cert_raw = cert.der().to_vec();
    let key_raw = signing_key.serialize_der();

    // saving the identity in the system
    std::fs::write(cert_path, &cert_raw)?;
    std::fs::write(key_path, &key_raw)?;
    // making the key
    let cert_der = CertificateDer::from(cert_raw);
    let key: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_raw));

    //sending to to main
    //(2)
    Ok((vec![cert_der], key))
}

// This handles the endpoints

async fn server(
    // this id the listner endpoint
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    json_bytes: Vec<u8>,
    device_index: DeviceIndex,
) -> Result<(), AppError> {
    //(5)
    //here we configured the server config to the local cert we made and the key
    let client_verifier = Arc::new(TofuClientVerifier);

    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier) // إجبار العميل على تقديم شهادته وفحصها
        .with_single_cert(cert_chain, key)?;

    let mut config = ServerConfig::with_crypto(Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| AppError::NetworkError(format!("{:?}", e)))?,
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(|_| AppError::NetworkError("Timeout conversion failed".to_string()))?));
    config.transport_config(Arc::new(transport_config));
    //making the server address
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);

    //here the server boots
    let endpoint = Endpoint::server(config, addr)?;

    // cloning the file index to pass it to the server
    let dev_idx_stream = device_index.clone();

    // a while loop to listen
    //(5-b) we are opening a broadcast channel to listen for clients
    let listen_socket = tokio::net::UdpSocket::bind("0.0.0.0:8888").await?;
    tokio::spawn(async move{
        let mut buffer = [0u8; 1024];
        loop{
            match listen_socket.recv_from(&mut buffer).await{
                Ok((bytes_read, client_addr)) => {
                    println!("Received {} bytes from {}", bytes_read, client_addr);
                    let device_name = get_fallback_device_name();
                    let device = DeviceInfo {
                        index: 0,
                        name: device_name,
                        ip: client_addr,
                    };
                    let reply_message = format!("{}", device.name);
                    // Handle the received data
                    match listen_socket.send_to(reply_message.as_bytes(), client_addr).await{
                        Ok(n) => {
                            println!("Sent {} bytes to {}", n, client_addr);
                            
                        },
                        Err(e) => {
                            eprintln!("Failed to send data: {}", e);
                        }
                    };
                },
                Err(e) => {
                    eprintln!("Failed to receive data: {}", e);
                }

        };
        
    }


    });
    
    //(6-a)
    while let Some(incoming) = endpoint.accept().await {
        let j = json_bytes.clone();
        let dev_idx_clone = dev_idx_stream.clone();
        tokio::spawn(async move {
            let call = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Incoming connection error: {}", e);
                    return;
                }
            };
            loop {
                let (mut send, mut recv) = match call.accept_bi().await {
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
                            if let Err(e) = handle_recieved_file(send, recv).await {
                                eprintln!("handle_recieved_file error: {:?}", e);
                            }
                        });
                    }
                    2 => {
                        let j_stream = j.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = handle_sending_json(send, recv, j_stream).await {
                                eprintln!("handle_sending_json error: {:?}", e);
                            }
                        });
                    }
                    3 => {
                        let dev_idx = dev_idx_clone.clone();
                        tokio::spawn(async move{
                            let mut id = [0u8; 8];
                            if let Err(e) = recv.read_exact(&mut id).await {
                                eprintln!("failed to read requested file id: {:?}", e);
                                return;
                            }
                            let target_id = u64::from_be_bytes(id) as usize;
                            if let Err(e) = handle_sending_requested_file(dev_idx, send, recv, target_id).await {
                                eprintln!("handle_sending_requested_file error: {:?}", e);
                            }
                        });
                    }
                    _ => {
                        println!("Uknown code: {:?}", read_code_buf);
                    }
                }
            }
        });
    }
    Ok(())
}

async fn client(cert: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<(), AppError> {
    let addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| AppError::NetworkError(e.to_string()))?;
    let mut client = Endpoint::client(addr)?;



    // initiated a connection
    //(6-b)
    let broadcast_socket = UdpSocket::bind("0.0.0.0:0").await?;
    broadcast_socket.set_broadcast(true)?;
    let massage = b"WHO IS THE SERVER?";
    broadcast_socket.send_to(massage, "192.168.1.255:8888").await?;
    println!("Broadcast message sent, waiting for response...");
    let mut responses = [0u8; 1024];
    let mut discovered_servers: Vec<DeviceInfo> = Vec::new();
    let mut index: u8 = 1;
    loop{
        match tokio::time::timeout(Duration::from_millis(1500), broadcast_socket.recv_from(&mut responses)).await{
            Ok(Ok((bytes_read, server_addr))) => {
                let msg = String::from_utf8_lossy(&responses[..bytes_read]).to_string();
                println!("Received response from {}: {}", server_addr, msg);
                discovered_servers.push(DeviceInfo{
                    index: index,
                    name: msg,
                    ip: server_addr,
                });
                index +=1;
            }
            Ok(Err(e)) => {
                eprintln!("Socket error: {}", e);
                break;
            }
            Err(ee) => {
                eprintln!("No more responses: {}", ee);
                break;
            }
        }
        
        
        
    }
    for (_index, device) in discovered_servers.iter().enumerate(){
        println!("{} - Device name: {}, IP: {}",device.index, device.name, device.ip);
    }
    let chosen_server = get_input("Choose a server (num): ").await?;
    let chosen_num: u8 = chosen_server.trim().parse::<u8>().map_err(|e| AppError::InvalidInput(e.to_string()))?;
    let targeted_device = discovered_servers.iter().find(|device| device.index == chosen_num).ok_or(AppError::ServerNotFound)?;
    let target_name = targeted_device.name.clone();


    // here we changed the client config so they can trust the cert we created
    // the without client auth means that it's a one way authintcation by the server
    // بدلاً من .with_no_client_auth() القديمة:
    let rustls_config = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(TofuVerifier {
        target_device_name: target_name,
    }))
    .with_client_auth_cert(cert, key)?; // giving the client's cert to the server

    // here we we gave quinn the nedded engine to operate and then passed it to the client
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
    .map_err(|e| AppError::NetworkError(format!("{:?}", e)))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(|_| AppError::NetworkError("Timeout conversion failed".to_string()))?)); // 5 mins so the connection doesn't die
    transport_config.keep_alive_interval(Some(Duration::from_secs(2))); // a heartbeat every 2 secs

    client_config.transport_config(Arc::new(transport_config)); 
    client.set_default_client_config(client_config);



    let server_ip = targeted_device.ip.ip();
    let target_addr = SocketAddr::new(server_ip, 8080);
    println!("Connecting to server at: {}", target_addr);
    let call = client
        .connect(target_addr, "localhost")?
        .await;
    let connection = call?;
    println!("connected to the server!");
    receive_json_call(&connection).await?;
    let sending_choice = get_input("Do you want to request a file? (y/n)");
    if sending_choice.await?.to_lowercase() == "y"{
        let code: u8 = 3;

        let mut handles = Vec::new();
        let number_chosen = get_input("Enter the file/s number (split with a comma): ").await?;
        let ids: Vec<usize> = number_chosen.split(',').filter_map(|s| s.trim().parse::<usize>().ok()).collect();
        for id in ids{
            let con = connection.clone();
            let handle = tokio::spawn(async move{
                let (mut send, recv) = match con.open_bi().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        eprintln!("an error happened while opining a connection: {:?}", e);
                        return;
                    }
                };
                if let Err(e) = send.write_all(&[code]).await {
                    eprintln!("failed to write code: {:?}", e);
                    return;
                }
                if let Err(e) = send.write_all(&(id as u64).to_be_bytes()).await {
                    eprintln!("failed to write id: {:?}", e);
                    return;
                }
                println!("Requesting file num: {:?}", id);
                if let Err(e) = handle_recieved_file(send, recv).await {
                    eprintln!("handle_recieved_file error: {:?}", e);
                }
            });
            handles.push(handle);

        }
        for handle in handles{
            handle.await?;
        } 
        println!("Finished all handles successfully.");
    }
    Ok(())
}

async fn filing(file_path: &str, file_send: SendStream) -> Result<u64, AppError> {
    // here we pack the wanted file to a stream fitted for the network
    let file = tokio::fs::File::open(file_path).await?;
    let path_str = file_path;
    let file_metadata = file.metadata().await?;
    let file_size = file_metadata.len();
    let file_name = Path::new(path_str).file_name().and_then(|n| n.to_str()).ok_or(AppError::InvalidFileName)?;
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
    // here we finally send the metadata and in the end the very file with tokio to sends the file in chunks so it doesn't fill the ram!
    let start_time = Instant::now();
    
    
    file_send.write_all(&name_size.to_be_bytes()).await?;
    file_send.write_all(&name_bytes).await?;
    file_send.write_all(&file_size.to_be_bytes()).await?;
    let _ = tokio::io::copy(&mut file, &mut file_send).await?;
    let _ = file_send.finish();

    // network data
    let duration = start_time.elapsed();
    println!("it took: {}s", duration.as_secs_f32());
    println!(
        "the file size is: {}MB",
        file_size as f32 / (1024.0 * 1024.0)
    );
    let size_mb: f32 = file_size as f32 / (1024.0 * 1024.0);
    let speed_mb_s: f32 = size_mb / duration.as_secs_f32();
    println!("The transfer speed is: {}MB/s", speed_mb_s);
    Ok(())
}

async fn handle_recieved_file(mut file_send: quinn::SendStream, mut file_recv: quinn::RecvStream) -> Result<(), AppError> {
    let start_time = Instant::now();

    // here we get the name size or the name length:
    let mut name_size_buf = [0u8; 2];
    file_recv.read_exact(&mut name_size_buf).await?;
    let name_size = u16::from_be_bytes(name_size_buf) as usize;

    //here we read the acctual file name:
    let mut name_buf = vec![0u8; name_size];
    file_recv.read_exact(&mut name_buf).await?;
    let file_name = String::from_utf8(name_buf)?;

    //here we read the file size:
    let mut file_size_buf = [0u8; 8];
    file_recv.read_exact(&mut file_size_buf).await?;
    let file_size = u64::from_be_bytes(file_size_buf);

    //here we write the whole recived file in the dist disk:
    let where_to_write: &str = r"A:\LINUX-WIN\اكواد\RUST\TESTS\";

    // this just for comparison
    let clean_file_name = Path::new(&file_name)
    .file_name()
    .and_then(|n| n.to_str())
    .ok_or(AppError::InvalidFileName)?;

    let mut path = PathBuf::from(r"A:\LINUX-WIN\اكواد\RUST\TESTS");
    path.push(&clean_file_name);
    if std::path::Path::new(&path).exists() == true {
        println!("file already exists");
        file_send.write_all(b"ALREADY_EXISTS").await?;
        let _ = file_send.finish();
        return Ok(());
    } else {
        let mut recived_file = tokio::fs::File::create(format!("{}{}{}", where_to_write, &clean_file_name, ".part"))
            .await?;
        let bytes_copied = tokio::io::copy(&mut file_recv, &mut recived_file)
            .await?;
        recived_file.flush().await?;
        // dropping the file to rename it without getting locked
        drop(recived_file);
        // renaming the file to the correct name after successfully writing
        let previous_file =format!("{}{}{}", where_to_write, &clean_file_name, ".part");
        let final_file = format!("{}{}", where_to_write, &clean_file_name);
        if bytes_copied == file_size{
            fs::rename(&previous_file, &final_file).await?;
            println!("wrote the file successfully in: {}", where_to_write);
                // network data
            let duration = start_time.elapsed();
            println!("it took: {}s", duration.as_secs_f32());
            println!(
                "the file size is: {}MB",
                file_size as f32 / (1024.0 * 1024.0)
            );
            let size_mb: f32 = file_size as f32 / (1024.0 * 1024.0);
            let speed_mb_s: f32 = size_mb / duration.as_secs_f32();
            println!("The transfer speed is: {}MB/s", speed_mb_s);
            }
            else {
                println!("there was an error while writing the file... try again?");
                tokio::fs::remove_file(&previous_file).await?;
                return Err(AppError::IncompleteTransfer { expected: file_size, got: bytes_copied });
            }
        }
    Ok(())
}

async fn _handle_recieved_message(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<(), AppError> {
    let data = recv.read_to_end(1024).await?;
    let message = String::from_utf8(data)?;
    println!("You recevied: {}", message);
    send.write_all("READ".as_bytes()).await?;
    let _ = send.finish();
    Ok(())
}

async fn handle_sending_json(mut send: quinn::SendStream, mut _recv: quinn::RecvStream, json_bytes: Vec<u8>) -> Result<(), AppError> {
    send.write_all(&(json_bytes.len() as u64).to_be_bytes()).await?;
    send.write_all(&json_bytes).await?;
    let _ = send.finish();
    Ok(())
}

async fn handle_sending_requested_file(dev_idx: DeviceIndex, send: quinn::SendStream, _recv: quinn::RecvStream, traget_id: usize) -> Result<(), AppError>{
    let target_file = dev_idx.files.iter().find(|file| file.id == traget_id).ok_or(AppError::FileNotFound(traget_id))?;
    filing(target_file.path.to_str().ok_or(AppError::InvalidFileName)?, send).await?;
    Ok(())
}

async fn receive_json_call(connection: &quinn::Connection) -> Result<(), AppError> {
    // sending the json code to the server to request it
    let (mut send, mut recv) = connection.open_bi().await?;
    let code: u8 = 2;
    send.write_all(&[code]).await?;
    let _ = send.finish();
    //here we start to read the coming data
    // first the json
    let mut json_len_buffer = [0u8; 8];
    recv.read_exact(&mut json_len_buffer).await?;
    let json_len = u64::from_be_bytes(json_len_buffer) as usize;
    let mut json_buffer = vec![0u8; json_len];
    recv.read_exact(&mut json_buffer).await?;

    let device_index: DeviceIndex = serde_json::from_slice(&json_buffer)?;
    for file in &device_index.files{
        println!("{} - File name: {}, File size: {}, File path: {:?}, Is it a folder: {}, Parent folder: {:?}", file.id, file.name, file.size, file.path, file.is_dir, file.parent_dir.as_deref().unwrap_or("None")); 
    }
    Ok(())
}

async fn send_file_call(connection: &quinn::Connection, file_path: &str) -> Result<(), AppError> {
    let (mut send, mut recv) = connection.open_bi().await?;

    let code: u8 = 1;
    send.write_all(&[code]).await?;
    let start_time = Instant::now();
    let file_size = filing(file_path, send).await?;
    let message = String::from_utf8(recv.read_to_end(1024).await?)?;
    println!("{}", message);
    let duration = start_time.elapsed();
    println!("it took: {}s", duration.as_secs_f32());
    println!(
        "the file size is: {}MB",
        file_size as f32 / (1024.0 * 1024.0)
    );
    let size_mb: f32 = file_size as f32 / (1024.0 * 1024.0);
    let speed_mb_s: f32 = size_mb / duration.as_secs_f32();
    println!("The transfer speed is: {}MB/s", speed_mb_s);
    Ok(())
}
async fn file_indexing(
    all_files:&mut Vec<FileIndexing>,
    counter:&mut usize,
    root_path: PathBuf) -> Result<(), AppError>
    {
    let mut dirs_to_scan = vec![root_path];
    while let Some(current_dir) = dirs_to_scan.pop() {
        if let Ok(mut entries) = tokio::fs::read_dir(&current_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                let path = entry.path();
                if is_dir{
                    dirs_to_scan.push(path);
                }
                else{
                    let file = FileIndexing {
                    id: *counter,
                    name: entry.file_name().to_string_lossy().to_string(),
                    size: entry.metadata().await.map(|m| m.len()).unwrap_or(0),
                    path: entry.path(),
                    is_dir: entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false),
                    parent_dir: path.parent().and_then(|p| p.file_name()).map(|name| name.to_string_lossy().to_string()),
                };
                *counter += 1;
                all_files.push(file);
                }
            }
        }
    }
    Ok(())
}
async fn json_retriveing() -> Result<(Vec<u8>, DeviceIndex), AppError> {
    let mut all_files: Vec<FileIndexing> = Vec::new();
    let mut counter: usize = 1;
    let root_path = get_input("Where do you want the index to look?").await?;
    file_indexing(&mut all_files, &mut counter, PathBuf::from(root_path)).await?;
    let device = DeviceIndex { files: all_files };
    let json_bytes = serde_json::to_vec(&device)?;
    return Ok((json_bytes, device));
}



#[tokio::main]
async fn main() -> Result<(), AppError> {
    //(3)
    // here we installed a crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| AppError::NetworkError("Failed to install default crypto provider".to_string()))?;
    let (cert_chain, key) = make_cert_and_key().await?;
    let cert_clone = cert_chain.clone();
    let key_clone = key.clone_key();
    println!("making the file index...");
    let (json_bytes, device_index) = json_retriveing().await?;
    
    println!("Starting server...");
    //(4)
    //sending it to the server
    tokio::spawn(async move {
        if let Err(e) = server(cert_clone.clone(), key_clone, json_bytes, device_index).await {
            eprintln!("Server encountered error: {:?}", e);
        }
    });
    let response = get_input("Do you want to run the client? (y/n)").await?;
    if response.to_lowercase() == "y"{
        println!("Starting client...");
        client(cert_chain, key).await?;
    }else {
        println!("Client not started.");
        let server_life = get_input("Press 'q' to stop the server.").await?;
        if server_life.to_lowercase() == "q" {
            return Ok(());
        }
    }

    Ok(())
}