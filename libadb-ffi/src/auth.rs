use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::future::Future;

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use signature::hazmat::PrehashSigner;
use signature::SignatureEncoding;

use libadb::base::auth::Authenticator;

use crate::error::AdbStatus;

pub(crate) struct FfiAuthenticator {
    signing_key: SigningKey<Sha1>,
    public_key: Vec<u8>,
}

impl FfiAuthenticator {
    pub(crate) fn from_pkcs8_pem(priv_pem: &str, pub_key: &[u8]) -> Result<Self, String> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(priv_pem)
            .map_err(|e| format!("parse private key: {e}"))?;
        let signing_key = SigningKey::<Sha1>::new(private_key);
        Ok(Self {
            signing_key,
            public_key: normalize_public_key(pub_key),
        })
    }
}

impl Authenticator for FfiAuthenticator {
    type Error = String;

    fn sign(&mut self, token: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        let res = self
            .signing_key
            .sign_prehash(token)
            .map(|sig| sig.to_bytes().into_vec())
            .map_err(|e| format!("sign: {e}"));
        core::future::ready(res)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

fn normalize_public_key(pub_key: &[u8]) -> Vec<u8> {
    let mut v = pub_key.to_vec();
    if !v.ends_with(b"\0") {
        v.push(0);
    }
    v
}

/// C-callable signing callback.
///
/// Implementations must produce a PKCS#1 v1.5 signature of the SHA-1
/// prehash supplied in `token` (always 20 bytes), write up to
/// `out_capacity` bytes of signature into `out_signature`, and store
/// the actual signature length through `out_length`. Returning any
/// non-[`AdbStatus::Ok`] value aborts authentication and is reported
/// to the caller as [`AdbStatus::Auth`].
pub type AdbSignFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    token: *const u8,
    token_len: usize,
    out_signature: *mut u8,
    out_capacity: usize,
    out_length: *mut usize,
) -> AdbStatus;

/// Caller-supplied authenticator passed to [`adb_connect_with_authenticator`].
///
/// `public_key` / `public_key_len` describe the ADB-format public key
/// blob (the contents of `~/.android/adbkey.pub`). The bytes are copied
/// internally on connect, so the buffer only needs to remain valid for
/// the duration of the call. A trailing NUL is appended automatically
/// if not already present.
///
/// `sign` is invoked synchronously during the handshake to produce a
/// signature for the device-issued token. `user_data` is forwarded
/// verbatim to every call and is otherwise opaque to libadb.
///
/// [`adb_connect_with_authenticator`]: crate::adb_connect_with_authenticator
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct adb_authenticator_t {
    pub public_key: *const u8,
    pub public_key_len: usize,
    pub sign: Option<AdbSignFn>,
    pub user_data: *mut c_void,
}

const MAX_SIGNATURE_LEN: usize = 1024;
const ADB_AUTH_TOKEN_LEN: usize = 20;

pub(crate) struct CallbackAuthenticator {
    public_key: Vec<u8>,
    sign_fn: AdbSignFn,
    user_data: *mut c_void,
}

impl CallbackAuthenticator {
    pub(crate) unsafe fn from_ffi(a: &adb_authenticator_t) -> Result<Self, &'static str> {
        let Some(sign_fn) = a.sign else {
            return Err("sign callback is null");
        };
        if a.public_key.is_null() && a.public_key_len > 0 {
            return Err("public_key is null but public_key_len > 0");
        }
        let pub_key_bytes = if a.public_key_len > 0 {
            core::slice::from_raw_parts(a.public_key, a.public_key_len)
        } else {
            &[]
        };
        Ok(Self {
            public_key: normalize_public_key(pub_key_bytes),
            sign_fn,
            user_data: a.user_data,
        })
    }
}

impl Authenticator for CallbackAuthenticator {
    type Error = String;

    fn sign(&mut self, token: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        if token.len() != ADB_AUTH_TOKEN_LEN {
            return core::future::ready(Err(format!(
                "expected {ADB_AUTH_TOKEN_LEN}-byte SHA-1 prehash token, got {}",
                token.len()
            )));
        }
        let mut buf = vec![0u8; MAX_SIGNATURE_LEN];
        let mut out_len: usize = 0;
        let status = unsafe {
            (self.sign_fn)(
                self.user_data,
                token.as_ptr(),
                token.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut out_len,
            )
        };
        let res = match status {
            AdbStatus::Ok if out_len == 0 => {
                Err(String::from("sign callback returned empty signature"))
            }
            AdbStatus::Ok if out_len <= buf.len() => {
                buf.truncate(out_len);
                Ok(buf)
            }
            AdbStatus::Ok => Err(format!(
                "sign callback wrote {out_len} bytes, exceeds capacity {}",
                buf.len()
            )),
            other => Err(format!("sign callback returned status {}", other as i32)),
        };
        core::future::ready(res)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
