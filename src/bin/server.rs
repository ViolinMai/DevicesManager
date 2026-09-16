async fn server(
    // this id the listner endpoint
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) {
    //(5)
    //here we configured the server config to the local cert we made and the key
    let config = ServerConfig::with_single_cert(cert_chain, key).unwrap();

    //making the server address
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);

    //here the server boots
    let endpoint = Endpoint::server(config, addr).unwrap();
    // a while loop to listen
    //(6-a)
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let call = incoming.await.unwrap();
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
                            handle_recieved_file(send, recv).await;
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