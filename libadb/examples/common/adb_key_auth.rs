//! Shared `Authenticator` impl reading `~/.android/adbkey{,.pub}`.
//!
//! Included by each binary example via `#[path]`:
//!
//! ```ignore
//! #[path = "common/adb_key_auth.rs"]
//! mod adb_key_auth;
//! use adb_key_auth::AdbKeyAuth;
//! ```

use std::path::PathBuf;
use std::{env, fs};

use libadb::auth::Authenticator;

pub struct AdbKeyAuth {
    private_key: rsa::RsaPrivateKey,
    public_key_bytes: Vec<u8>,
}

impl AdbKeyAuth {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let home = env::var("HOME")?;
        let base = PathBuf::from(home).join(".android");

        let pem = fs::read_to_string(base.join("adbkey"))
            .map_err(|e| format!("~/.android/adbkey: {e}"))?;
        let private_key =
            <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pem)
                .map_err(|e| format!("parse adbkey: {e}"))?;

        let mut public_key_bytes =
            fs::read(base.join("adbkey.pub")).map_err(|e| format!("~/.android/adbkey.pub: {e}"))?;
        if !public_key_bytes.ends_with(b"\0") {
            public_key_bytes.push(0);
        }

        Ok(Self {
            private_key,
            public_key_bytes,
        })
    }
}

impl Authenticator for AdbKeyAuth {
    type Error = String;

    async fn sign(&mut self, token: &[u8]) -> Result<Vec<u8>, String> {
        use signature::hazmat::PrehashSigner;
        use signature::SignatureEncoding;
        let signing_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(self.private_key.clone());
        let sig = signing_key
            .sign_prehash(token)
            .map_err(|e| format!("sign: {e}"))?;
        Ok(sig.to_bytes().into_vec())
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }
}
