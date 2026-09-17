use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngExt;
use quinn::{self, Connection, Endpoint, SendStream, ServerConfig};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;

// JSON STRUCT
#[derive(Serialize, Deserialize, Debug)]
struct FileIndexing {
    name: String,
    size: u64,
    path: std::path::PathBuf,
    is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct DeviceIndex {
    files: Vec<FileIndexing>,
}


async fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    
    reader.read_line(&mut line).await.expect("Failed to read input");
    
    line.trim().to_string()
}

// This makes a new certificate and key and send it to main
async fn make_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    //(1)
    // server_name
    let subject_alt_names = vec!["localhost".to_string()];

    // generating a certificate
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.der().clone();
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = vec![cert_der];

    // making the key
    let key_der: PrivatePkcs8KeyDer<'static> =
        PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let key: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(key_der);

    //sending to to main
    //(2)
    (cert_chain, key)
}

// This handles the endpoints

async fn server(
    // this id the listner endpoint
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    json_bytes: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
) {
    //(5)
    //here we configured the server config to the local cert we made and the key
    let config = ServerConfig::with_single_cert(cert_chain, key).unwrap();

    //making the server address
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);

    //here the server boots
    let endpoint = Endpoint::server(config, addr).unwrap();
    // a while loop to listen
    //(5-b) we are opening a broadcast channel to listen for clients
    let listen_socket = tokio::net::UdpSocket::bind("0.0.0.0:8888").await
        .expect("Failed to bind UDP socket");
    tokio::spawn(async move{
        let mut buffer = [0u8; 1024];
        loop{
            match listen_socket.recv_from(&mut buffer).await{
                Ok((bytes_read, client_addr)) => {
                    println!("Received {} bytes from {}", bytes_read, client_addr);
                    // Handle the received data
                    match listen_socket.send_to(b"I AM THE SERVER", client_addr).await{
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
        let s = salt.clone();
        let n = nonce.clone();
        tokio::spawn(async move {
            let call = incoming.await.unwrap();
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
                        let j_stream = j.clone();
                        let s_stream = s.clone();
                        let n_stream = n.clone();
                        
                        tokio::spawn(async move {
                            handle_sending_json(send, recv, j_stream, s_stream, n_stream).await;
                        });
                    }
                    _ => {
                        println!("Uknown code: {:?}", read_code_buf);
                    }
                }
            }
        });
    }
}

async fn client(cert: Vec<CertificateDer<'static>>) {
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut client = Endpoint::client(addr).unwrap();

    // here we took the cert and then stored it
    let mut store = rustls::RootCertStore::empty();
    store.add(cert[0].clone());

    // here we changed the client config so they can trust the cert we created
    // the without client auth means that it's a one way authintcation by the server
    let rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();

    // here we we gave quinn the nedded engine to operate and then passed it to the client
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client.set_default_client_config(client_config);

    // initiated a connection
    //(6-b)
    let broadcast_socket = UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind UDP socket");
    broadcast_socket.set_broadcast(true).expect("Failed to call a server");
    let massage = b"WHO IS THE SERVER?";
    broadcast_socket.send_to(massage, "255.255.255.255:8888").await.expect("Failed to send broadcast message");
    println!("Broadcast message sent, waiting for response...");
    let mut buf = [0u8; 1024];
    let recived_message = broadcast_socket.recv_from(&mut buf).await.expect("Failed to receive response");
    println!("Received response from server: {}", String::from_utf8_lossy(&buf[..recived_message.0]));
    let server_ip = recived_message.1.ip();
    let target_addr = SocketAddr::new(server_ip, 8080);
    println!("Connecting to server at: {}", target_addr);
    let call = client
        .connect(target_addr, "localhost")
        .unwrap()
        .await;
    let connection = call.unwrap();
    println!("connected to the server!");
    receive_json_call(&connection).await;
    let sending_choice = get_input("Do you want to send a file? (y/n)");
    if sending_choice.await.to_lowercase() == "y"{
        let file_path = get_input("Enter the file path: ").await;
        let clean_path = file_path.trim().trim_matches('"').to_string();
        println!("Sending file: {:?}", clean_path);
        send_file_call(&connection, &clean_path).await;
    }
    
}

async fn filing(file_path: &str, file_send: SendStream) -> u64 {
    // here we pack the wanted file to a stream fitted for the network
    let file = tokio::fs::File::open(file_path).await.unwrap();
    let path_str = file_path;
    let file_metadata = file.metadata().await.unwrap();
    let file_size = file_metadata.len();
    let file_name = Path::new(path_str).file_name().unwrap().to_str().unwrap();
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
    // here we finally send the metadata and in the end the very file with tokio to sends the file in chunks so it doesn't fill the ram!

    file_send.write_all(&name_size.to_be_bytes()).await.unwrap();
    file_send.write_all(&name_bytes).await.unwrap();
    file_send.write_all(&file_size.to_be_bytes()).await.unwrap();
    let _ = tokio::io::copy(&mut file, &mut file_send).await;
    let _ = file_send.finish();
}

async fn handle_recieved_file(mut file_send: quinn::SendStream, mut file_recv: quinn::RecvStream) {
    // here we get the name size or the name length:
    let mut name_size_buf = [0u8; 2];
    file_recv.read_exact(&mut name_size_buf).await.unwrap();
    let name_size = u16::from_be_bytes(name_size_buf) as usize;

    //here we read the acctual file name:
    let mut name_buf = vec![0u8; name_size];
    file_recv.read_exact(&mut name_buf).await.unwrap();
    let file_name = String::from_utf8(name_buf).unwrap();

    //here we read the file size:
    let mut file_size_buf = [0u8; 8];
    file_recv.read_exact(&mut file_size_buf).await.unwrap();
    let file_size = u64::from_be_bytes(file_size_buf);

    //here we write the whole recived file in the dist disk:
    let where_to_write: &str = r"A:\LINUX-WIN\اكواد\RUST\TESTS\";

    // this just for comparison
    let mut path = PathBuf::from(r"A:\LINUX-WIN\اكواد\RUST\TESTS");
    path.push(&file_name);
    if std::path::Path::new(&path).exists() == true {
        println!("file already exists");
        file_send.write_all(b"ALREADY_EXISTS").await.unwrap();
        file_send.finish().unwrap();
    } else {
        let mut recived_file = tokio::fs::File::create(format!("{}{}", where_to_write, file_name))
            .await
            .unwrap();
        tokio::io::copy(&mut file_recv, &mut recived_file)
            .await
            .unwrap();
        recived_file.flush().await.unwrap();
        file_send.write_all(b"DONE").await.unwrap();
        file_send.finish().unwrap();
        println!("wrote the file successfully in: {}", where_to_write);
    }
}

async fn _handle_recieved_message(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let data = recv.read_to_end(1024).await.unwrap();
    let message = String::from_utf8(data).unwrap();
    println!("You recevied: {}", message);
    send.write_all("READ".as_bytes()).await.unwrap();
    send.finish().unwrap();
}

async fn handle_sending_json(mut send: quinn::SendStream, mut _recv: quinn::RecvStream, json_bytes: Vec<u8>, salt: Vec<u8>, nonce: Vec<u8>) {
    send.write_all(&(json_bytes.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&json_bytes).await.unwrap();
    send.write_all(&(salt.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&salt).await.unwrap();
    send.write_all(&(nonce.len() as u64).to_be_bytes()).await.unwrap();
    send.write_all(&nonce).await.unwrap();
    send.finish().unwrap();
}

async fn receive_json_call(connection: &quinn::Connection){
    // sending the json code to the server to request it
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let code: u8 = 2;
    send.write_all(&[code]).await.unwrap();
    send.finish().unwrap();
    //here we start to read the coming data
    // first the json
    let mut json_len_buffer = [0u8; 8];
    recv.read_exact(&mut json_len_buffer).await.unwrap();
    let json_len = u64::from_be_bytes(json_len_buffer) as usize;
    let mut encrypted_json = vec![0u8; json_len];
    recv.read_exact(&mut encrypted_json).await.unwrap();
    //then the salt
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
    match decrypt_json(&encrypted_json, &salt, &nonce, &pin){
        Ok(f) => {
            println!("dycrypted successfully.");
            for file in &f.files{
                println!("File name: {}, File size: {}, File path: {:?}, Is it a folder: {}", file.name, file.size, file.path, file.is_dir)
            }
        }
        Err(e) => {
            println!("an error happened while dycrypting: {}", e)
        }
    }
}

async fn send_file_call(connection: &quinn::Connection, file_path: &str) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();

    let code: u8 = 1;
    send.write_all(&[code]).await.unwrap();
    let start_time = Instant::now();
    let file_size = filing(file_path, send).await;
    let message = String::from_utf8(recv.read_to_end(1024).await.unwrap()).unwrap();
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
}

async fn json_retriveing() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut all_files: Vec<FileIndexing> = Vec::new();
    match tokio::fs::read_dir(r"C:\Users\mmood\Documents\exe").await {
        Ok(mut entries) => {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let file = FileIndexing {
                    name: entry.file_name().to_string_lossy().to_string(),
                    size: entry.metadata().await.unwrap().len(),
                    path: entry.path(),
                    is_dir: entry.file_type().await.unwrap().is_dir(),
                };
                all_files.push(file);
            }
            let device = DeviceIndex { files: all_files };
            let json_bytes = serde_json::to_vec(&device).unwrap();
            let (encrypted_json, salt, nonce) = encrypting_json(json_bytes).await;
            return (encrypted_json, salt, nonce);
        }
        Err(e) => {
            println!("couldn't read... {}", e);
            return (Vec::new(), Vec::new(), Vec::new());
        }
    };
}

async fn encrypting_json(json_bytes: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // TO BE DELETED
    let pin = "1234";
    let mut key_bytes = [0u8; 32];

    // 1. توليد الـ Salt
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);


    // 2. اشتقاق المفتاح
    Argon2::default()
        .hash_password_into(pin.as_bytes(), &salt, &mut key_bytes)
        .expect("Couldn't derive it.");

    // 3. تجهيز الـ Cipher
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).unwrap();
    let cipher = Aes256Gcm::new(&key);

    // 4. توليد Nonce بطول 12 بايت
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).unwrap();

    // 5. التشفير
    let encrypted_bytes = cipher
        .encrypt(&nonce, json_bytes.as_ref())
        .expect("couldn't encrypt it...");

    println!("Encrypted successfully! Size: {} bytes", encrypted_bytes.len());
    return (encrypted_bytes, nonce_bytes.to_vec(), salt.to_vec());
}

fn decrypt_json(
    encrypted_bytes: &[u8],
    salt: &[u8],
    nonce_bytes: &[u8],
    pin: &String,
) -> Result<DeviceIndex, Box<dyn std::error::Error>> {
    // 1. إعادة اشتقاق نفس المفتاح باستخدام الـ PIN والـ Salt المستلمين
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(pin.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    // 2. تهيئة الـ Cipher
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice())?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::try_from(nonce_bytes)?;

    // 3. فك التشفير
    let decrypted_bytes = cipher
        .decrypt(&nonce, encrypted_bytes)
        .map_err(|e| format!("Decryption failed (Wrong PIN or corrupted data): {}", e))?;

    // 4. تحويل بايتات الـ JSON النظيفة إلى كائن DeviceIndex
    let device_index: DeviceIndex = serde_json::from_slice(&decrypted_bytes)?;

    Ok(device_index)
}

#[tokio::main]
async fn main() {
    //(3)
    // here we installed a crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");
    let (cert_chain, key) = make_cert_and_key().await;
    let clients_cert = cert_chain.clone();
    
    println!("making the file index...");
    let (encrypted_json, salt, nonce) = json_retriveing().await;
    
    println!("Starting server...");
    //(4)
    //sending it to the server
    tokio::spawn(async move {
        server(cert_chain.clone(), key, encrypted_json, salt, nonce).await;
    });
    let response = get_input("Do you want to run the client? (y/n)").await;
    if response.to_lowercase() == "y"{
        println!("Starting client...");
        client(clients_cert.clone()).await;
    }else {
        println!("Client not started.");
        return;
    }

    
    
}
