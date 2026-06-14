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
        if map.len() >= MAX_ENTRIES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (stored, _))| *stored)
                .map(|(key, _)| key.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(wrapped, (now, dek));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dek(byte: u8) -> Dek {
        hyperion_vault_core::crypto::dek_from_slice(&[byte; 32]).expect("valid dek length")
    }

    #[test]
    fn cap_is_hard_bounded() {
        let cache = DekCache::new(300);
        for i in 0..(MAX_ENTRIES + 50) {
            cache.put(i.to_le_bytes().to_vec(), sample_dek((i % 251) as u8));
        }
        let len = cache.map.lock().expect("poisoned").len();
        assert!(len <= MAX_ENTRIES, "cache exceeded hard cap: {len}");
    }

    #[test]
    fn disabled_cache_stores_nothing() {
        let cache = DekCache::new(0);
        cache.put(vec![1, 2, 3], sample_dek(7));
        assert!(cache.get(&[1, 2, 3]).is_none());
    }
}
