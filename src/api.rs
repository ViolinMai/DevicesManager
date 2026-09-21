use std::sync::{Arc, RwLock};
use std::path::PathBuf;
use std::net::SocketAddr;
use tokio::sync::{mpsc, Mutex};
use flutter_rust_bridge::frb;
use crate::frb_generated::StreamSink;
use crate::connection_protocol::{
    self, AppConfig, DeviceInfo as CoreDeviceInfo,
    FileIndexing as CoreFileIndexing, PairingRequest, ServerHandle, PeersStorage
};

static SERVER_HANDLE: Mutex<Option<ServerHandle>> = Mutex::const_new(None);
static CONFIG_STATE: Mutex<Option<Arc<RwLock<AppConfig>>>> = Mutex::const_new(None);
static PAIRING_SINK: Mutex<Option<StreamSink<GuiPairingEvent>>> = Mutex::const_new(None);
static PAIRING_CHANNEL_TX: Mutex<Option<mpsc::Sender<PairingRequest>>> = Mutex::const_new(None);
static LAST_PENDING_PAIRING: Mutex<Option<PairingRequest>> = Mutex::const_new(None);

#[derive(Clone, Debug)]
pub struct GuiDeviceInfo {
    pub index: u8,
    pub name: String,
    pub ip: String,
}

impl From<CoreDeviceInfo> for GuiDeviceInfo {
    fn from(d: CoreDeviceInfo) -> Self {
        Self {
            index: d.index,
            name: d.name,
            ip: d.ip.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuiFileIndexing {
    pub id: usize,
    pub name: String,
    pub size: u64,
    pub path: String,
    pub is_dir: bool,
    pub parent_dir: Option<String>,
}

impl From<CoreFileIndexing> for GuiFileIndexing {
    fn from(f: CoreFileIndexing) -> Self {
        Self {
            id: f.id as usize,
            name: f.name,
            size: f.size,
            path: f.path.to_string_lossy().to_string(),
            is_dir: f.is_dir,
            parent_dir: f.parent_dir,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuiPairingEvent {
    pub device_name: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct GuiDownloadProgress {
    pub file_id: usize,
    pub file_name: String,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub speed_mb_s: f32,
    pub is_finished: bool,
    pub error: Option<String>,
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn start_gui_server(pairing_stream: StreamSink<GuiPairingEvent>) -> Result<String, String> {
    {
        let mut sink_lock = PAIRING_SINK.lock().await;
        *sink_lock = Some(pairing_stream);
    }

    let mut lock = SERVER_HANDLE.lock().await;
    if lock.is_some() {
        let config = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
        return Ok(format!("Server running as: {}", config.device_name));
    }

    let loaded_config = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    let config_arc = Arc::new(RwLock::new(loaded_config));
    {
        let mut cfg_lock = CONFIG_STATE.lock().await;
        *cfg_lock = Some(config_arc.clone());
    }

    let (cert_chain, key) = connection_protocol::make_cert_and_key()
        .await
        .map_err(|e| e.to_string())?;

    let (req_tx, mut req_rx) = mpsc::channel::<PairingRequest>(32);
    {
        let mut tx_lock = PAIRING_CHANNEL_TX.lock().await;
        *tx_lock = Some(req_tx.clone());
    }

    tokio::spawn(async move {
        while let Some(req) = req_rx.recv().await {
            {
                let mut pending = LAST_PENDING_PAIRING.lock().await;
                *pending = Some(req.clone());
            }
            let sink_lock = PAIRING_SINK.lock().await;
            if let Some(ref sink) = *sink_lock {
                let _ = sink.add(GuiPairingEvent {
                    device_name: req.device_name,
                    fingerprint: req.fingerprint,
                });
            }
        }
    });

    let handle = connection_protocol::start_server_with_channel(
        cert_chain,
        key,
        config_arc.clone(),
        Some(req_tx),
    );

    let dev_name = config_arc.read().unwrap().device_name.clone();
    *lock = Some(handle);
    Ok(format!("Server started as: {}", dev_name))
}

pub async fn stop_gui_server() -> Result<(), String> {
    let mut lock = SERVER_HANDLE.lock().await;
    if let Some(handle) = lock.take() {
        handle.stop().await;
    }
    Ok(())
}

pub async fn respond_pairing_decision(accept: bool) {
    let mut pending = LAST_PENDING_PAIRING.lock().await;
    if let Some(req) = pending.take() {
        if accept {
            let _ = PeersStorage::trust_peer(req.device_name, req.fingerprint);
        }
    }
}

pub async fn scan_network_devices() -> Result<Vec<GuiDeviceInfo>, String> {
    let config = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    let active_devices = connection_protocol::discover_network_devices(&config.broadcast_addr)
        .await
        .unwrap_or_default();

    let known_peers = PeersStorage::load().unwrap_or_default();
    let mut result = Vec::new();
    let mut idx = 1u8;

    for dev in active_devices {
        result.push(GuiDeviceInfo {
            index: idx,
            name: dev.name,
            ip: dev.ip.to_string(),
        });
        idx += 1;
    }

    for (peer_name, _) in known_peers {
        if !result.iter().any(|d| d.name == peer_name) {
            result.push(GuiDeviceInfo {
                index: idx,
                name: peer_name,
                ip: "Offline".to_string(),
            });
            idx += 1;
        }
    }

    Ok(result)
}

pub async fn get_remote_device_files(target_ip: String, target_name: String) -> Result<Vec<GuiFileIndexing>, String> {
    let (cert_chain, key) = connection_protocol::make_cert_and_key()
        .await
        .map_err(|e| e.to_string())?;

    let pairing_tx = {
        let tx_lock = PAIRING_CHANNEL_TX.lock().await;
        tx_lock.clone()
    };

    let parsed_addr: SocketAddr = target_ip.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
    let target_quic_addr = SocketAddr::new(parsed_addr.ip(), 8080);

    let connection = connection_protocol::connect_to_server(target_quic_addr, target_name, cert_chain, key, pairing_tx)
        .await
        .map_err(|e| e.to_string())?;

    let index = connection_protocol::fetch_device_index(&connection)
        .await
        .map_err(|e| e.to_string())?;

    Ok(index.files.into_iter().map(GuiFileIndexing::from).collect())
}

pub async fn download_file_from_remote(
    target_ip: String,
    target_name: String,
    file_id: usize,
) -> Result<(), String> {
    let config = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    let (cert_chain, key) = connection_protocol::make_cert_and_key()
        .await
        .map_err(|e| e.to_string())?;

    let pairing_tx = {
        let tx_lock = PAIRING_CHANNEL_TX.lock().await;
        tx_lock.clone()
    };

    let parsed_addr: SocketAddr = target_ip.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
    let target_quic_addr = SocketAddr::new(parsed_addr.ip(), 8080);

    let connection = connection_protocol::connect_to_server(target_quic_addr, target_name, cert_chain, key, pairing_tx)
        .await
        .map_err(|e| e.to_string())?;

    let dl_dir = config.download_dir.clone();
    connection_protocol::download_requested_file(&connection, file_id as u64, dl_dir)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

pub async fn get_share_roots() -> Result<Vec<String>, String> {
    let cfg = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    Ok(cfg.share_roots.into_iter().map(|p| p.to_string_lossy().to_string()).collect())
}

pub async fn update_share_roots(new_roots: Vec<String>) -> Result<(), String> {
    let mut cfg = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    cfg.share_roots = new_roots.into_iter().map(PathBuf::from).collect();
    cfg.save().map_err(|e| e.to_string())?;

    let cfg_state_lock = CONFIG_STATE.lock().await;
    if let Some(ref arc_cfg) = *cfg_state_lock {
        if let Ok(mut writer) = arc_cfg.write() {
            writer.share_roots = cfg.share_roots.clone();
        }
    }
    Ok(())
}

pub async fn get_download_directory() -> Result<String, String> {
    let cfg = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    Ok(cfg.download_dir.to_string_lossy().to_string())
}

pub async fn update_download_directory(new_dir: String) -> Result<(), String> {
    let mut cfg = AppConfig::load_or_create().await.map_err(|e| e.to_string())?;
    cfg.download_dir = PathBuf::from(new_dir);
    cfg.save().map_err(|e| e.to_string())?;

    let cfg_state_lock = CONFIG_STATE.lock().await;
    if let Some(ref arc_cfg) = *cfg_state_lock {
        if let Ok(mut writer) = arc_cfg.write() {
            writer.download_dir = cfg.download_dir.clone();
        }
    }
    Ok(())
}
