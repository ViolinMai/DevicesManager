use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

// هيكل لتجاوز فحص الشهادة محلياً لتجربة الـ self-signed بدون قيود
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_quicctester_MainActivity_runQuicClientNative(
    mut env: JNIEnv,
    _: JClass,
    target_ip: JString,
) -> jstring {
    let host: String = env
        .get_string(&target_ip)
        .expect("Couldn't read host IP string")
        .into();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let output_message = runtime.block_on(async move {
        match execute_quic_test(&host).await {
            Ok(msg) => msg,
            Err(e) => format!("Execution Failed: {}", e),
        }
    });

    env.new_string(output_message).unwrap().into_raw()
}

async fn execute_quic_test(host_and_port: &str) -> Result<String, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // إعداد الـ Client ليقبل شهادة السيرفر المؤقتة
    let mut rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let quic_crypto = QuicClientConfig::try_from(rustls_config)?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let target_addr: SocketAddr = host_and_port.parse()?;
    
    // بدء الاتصال
    let connection = endpoint.connect(target_addr, "localhost")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // إنشاء حزمة بيانات اختبارية بحجم 1 ميجابايت في الذاكرة
    let payload_size = 1024 * 1024; // 1 MB
    let dummy_packet = vec![7u8; payload_size];

    let start_time = Instant::now();
    send.write_all(&dummy_packet).await?;
    send.finish()?;

    let response = recv.read_to_end(1024).await?;
    let duration = start_time.elapsed();

    let response_str = String::from_utf8_lossy(&response);
    let speed_mb_s = (payload_size as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64();

    Ok(format!(
        "Response: {}\nTransferred: 1.0 MB\nDuration: {:.3}s\nSpeed: {:.2} MB/s",
        response_str,
        duration.as_secs_f64(),
        speed_mb_s
    ))
}