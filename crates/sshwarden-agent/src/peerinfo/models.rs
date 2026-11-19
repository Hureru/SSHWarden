use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pid: u32,
    process_name: String,
    is_forwarding: Arc<AtomicBool>,
    host_key: Arc<Mutex<Vec<u8>>>,
    /// Vault item id the user picked for this connection in the key picker.
    picked: Arc<Mutex<Option<String>>>,
}

impl PeerInfo {
    pub fn new(pid: u32, process_name: String) -> Self {
        Self {
            pid,
            process_name,
            is_forwarding: Arc::new(AtomicBool::new(false)),
            host_key: Arc::new(Mutex::new(Vec::new())),
            picked: Arc::new(Mutex::new(None)),
        }
    }

    pub fn unknown() -> Self {
        Self {
            pid: 0,
            process_name: "Unknown application".to_string(),
            is_forwarding: Arc::new(AtomicBool::new(false)),
            host_key: Arc::new(Mutex::new(Vec::new())),
            picked: Arc::new(Mutex::new(None)),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    pub fn is_forwarding(&self) -> bool {
        self.is_forwarding
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_forwarding(&self, value: bool) {
        self.is_forwarding
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_host_key(&self, host_key: Vec<u8>) {
        let mut host_key_lock = self.host_key.lock().expect("Mutex is not poisoned");
        *host_key_lock = host_key;
    }

    pub fn host_key(&self) -> Vec<u8> {
        self.host_key.lock().expect("Mutex is not poisoned").clone()
    }

    pub fn set_picked(&self, cipher_id: Option<String>) {
        *self.picked.lock().expect("Mutex is not poisoned") = cipher_id;
    }

    pub fn picked(&self) -> Option<String> {
        self.picked.lock().expect("Mutex is not poisoned").clone()
    }
}
