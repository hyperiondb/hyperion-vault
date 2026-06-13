use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyperion_vault_core::crypto::Dek;

const MAX_ENTRIES: usize = 16_384;

pub struct DekCache {
    ttl: Duration,
    map: Mutex<HashMap<Vec<u8>, (Instant, Dek)>>,
}

impl DekCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    pub fn get(&self, wrapped: &[u8]) -> Option<Dek> {
        if self.ttl.is_zero() {
            return None;
        }
        let mut map = self.map.lock().expect("dek cache poisoned");
        match map.get(wrapped) {
            Some((stored, dek)) if stored.elapsed() < self.ttl => Some(dek.clone()),
            Some(_) => {
                map.remove(wrapped);
                None
            }
            None => None,
        }
    }

    pub fn put(&self, wrapped: Vec<u8>, dek: Dek) {
        if self.ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut map = self.map.lock().expect("dek cache poisoned");
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, (stored, _)| now.duration_since(*stored) < self.ttl);
        }
        map.insert(wrapped, (now, dek));
    }
}
