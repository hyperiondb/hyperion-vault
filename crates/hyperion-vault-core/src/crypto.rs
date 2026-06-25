use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub type Dek = Zeroizing<[u8; DEK_LEN]>;

pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system CSPRNG is unavailable");
}

pub fn generate_dek() -> Dek {
    let mut k = [0u8; DEK_LEN];
    fill_random(&mut k);
    Zeroizing::new(k)
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    fill_random(&mut n);
    n
}

pub fn dek_from_slice(bytes: &[u8]) -> Result<Dek> {
    if bytes.len() != DEK_LEN {
        return Err(Error::KeyLength {
            expected: DEK_LEN,
            got: bytes.len(),
        });
    }
    let mut k = [0u8; DEK_LEN];
    k.copy_from_slice(bytes);
    Ok(Zeroizing::new(k))
}

pub fn seal(
    dek: &[u8; DEK_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&dek[..]));
    cipher
        .encrypt(
            XNonce::from_slice(&nonce[..]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encryption)
}

pub fn open(
    dek: &[u8; DEK_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&dek[..]));
    cipher
        .decrypt(
            XNonce::from_slice(&nonce[..]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
}

pub struct DataKey {
    pub plaintext: Dek,
    pub wrapped: Vec<u8>,
    pub key_id: String,
}

pub trait KeyWrapper {
    fn generate_data_key(&self) -> Result<DataKey>;
    fn unwrap_data_key(&self, wrapped: &[u8], key_id: &str) -> Result<Dek>;
}

#[derive(Clone)]
pub struct Envelope {
    pub key_id: String,
    pub wrapped_dek: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn seal_envelope<W: KeyWrapper>(wrapper: &W, aad: &[u8], plaintext: &[u8]) -> Result<Envelope> {
    let dk = wrapper.generate_data_key()?;
    let nonce = generate_nonce();
    let ciphertext = seal(&dk.plaintext, &nonce, aad, plaintext)?;
    Ok(Envelope {
        key_id: dk.key_id,
        wrapped_dek: dk.wrapped,
        nonce,
        ciphertext,
    })
}

pub fn open_envelope<W: KeyWrapper>(
    wrapper: &W,
    env: &Envelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let dek = wrapper.unwrap_data_key(&env.wrapped_dek, &env.key_id)?;
    open(&dek, &env.nonce, aad, &env.ciphertext)
}

const WRAP_AAD: &[u8] = b"pg_vault:dek-wrap:v1";

pub struct LocalKeyWrapper {
    master: Zeroizing<[u8; DEK_LEN]>,
    key_id: String,
}

impl LocalKeyWrapper {
    pub fn new(master: [u8; DEK_LEN], key_id: impl Into<String>) -> Self {
        Self {
            master: Zeroizing::new(master),
            key_id: key_id.into(),
        }
    }

    pub fn random() -> Self {
        let mut master = [0u8; DEK_LEN];
        fill_random(&mut master);
        Self::new(master, "local-dev")
    }

    pub fn from_base64(encoded: &str, key_id: impl Into<String>) -> Result<Self> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::KeyUnwrap)?;
        if raw.len() != DEK_LEN {
            return Err(Error::KeyLength {
                expected: DEK_LEN,
                got: raw.len(),
            });
        }
        let mut master = [0u8; DEK_LEN];
        master.copy_from_slice(&raw);
        Ok(Self::new(master, key_id))
    }

    fn wrap_dek(&self, dek: &[u8; DEK_LEN]) -> Result<Vec<u8>> {
        let nonce = generate_nonce();
        let ct = seal(&self.master, &nonce, WRAP_AAD, dek).map_err(|_| Error::KeyWrap)?;
        let mut wrapped = Vec::with_capacity(NONCE_LEN + ct.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ct);
        Ok(wrapped)
    }

    pub fn rewrap(&self, wrapped: &[u8], key_id: &str) -> Result<(Vec<u8>, String)> {
        let dek = self.unwrap_data_key(wrapped, key_id)?;
        Ok((self.wrap_dek(&dek)?, self.key_id.clone()))
    }
}

impl KeyWrapper for LocalKeyWrapper {
    fn generate_data_key(&self) -> Result<DataKey> {
        let dek = generate_dek();
        let wrapped = self.wrap_dek(&dek)?;
        Ok(DataKey {
            plaintext: dek,
            wrapped,
            key_id: self.key_id.clone(),
        })
    }

    fn unwrap_data_key(&self, wrapped: &[u8], _key_id: &str) -> Result<Dek> {
        if wrapped.len() < NONCE_LEN {
            return Err(Error::KeyUnwrap);
        }
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::KeyUnwrap)?;
        let pt = open(&self.master, nonce, WRAP_AAD, ct).map_err(|_| Error::KeyUnwrap)?;
        dek_from_slice(&pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrap_preserves_dek_and_payload() {
        let wrapper = LocalKeyWrapper::new([7u8; DEK_LEN], "master-1");
        let aad = b"db/password:1";
        let plaintext = b"super-secret-value";

        let env = seal_envelope(&wrapper, aad, plaintext).expect("seal");
        assert_eq!(
            open_envelope(&wrapper, &env, aad).expect("open").as_slice(),
            plaintext
        );

        // Re-wrap the DEK in place (same underlying secret, new wrapping).
        let (rewrapped, key_id) = wrapper.rewrap(&env.wrapped_dek, &env.key_id).expect("rewrap");
        assert_eq!(key_id, "master-1");
        assert_ne!(
            rewrapped, env.wrapped_dek,
            "a fresh wrap nonce makes the wrapped blob differ"
        );

        // The same ciphertext, now with the re-wrapped DEK, still opens to the same value.
        let rewrapped_env = Envelope {
            wrapped_dek: rewrapped,
            ..env.clone()
        };
        assert_eq!(
            open_envelope(&wrapper, &rewrapped_env, aad)
                .expect("open rewrapped")
                .as_slice(),
            plaintext
        );
    }
}
