use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::future::Future;

use libadb::base::auth::Authenticator;
use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{AdbKey, KeyName};
#[cfg(feature = "tls")]
use libadb::tls::{TlsClientConfig, TlsIdentity};

use crate::error::AdbStatus;

pub(crate) struct FfiAuthenticator {
    key: AdbKey,
    public_key: Vec<u8>,
}

impl FfiAuthenticator {
    pub(crate) fn from_pkcs8_pem(priv_pem: &str, pub_key: &[u8]) -> Result<Self, String> {
        let key = AdbKey::from_pkcs8_pem(priv_pem, &mut OsRng, KeyName::default())
            .map_err(|e| format!("parse private key: {e}"))?;
        Ok(Self {
            key,
            public_key: normalize_public_key(pub_key),
        })
    }

    #[cfg(feature = "tls")]
    pub(crate) fn tls_config(&self) -> Result<TlsClientConfig, String> {
        tls_config_for(&self.key)
    }
}

#[cfg(feature = "tls")]
pub(crate) fn tls_config_for(key: &AdbKey) -> Result<TlsClientConfig, String> {
    let identity = TlsIdentity::from_key(key, &mut OsRng).map_err(|e| format!("tls: {e}"))?;
    TlsClientConfig::adb(&identity).map_err(|e| format!("tls: {e}"))
}

impl Authenticator for FfiAuthenticator {
    type Error = String;

    async fn sign(&mut self, token: &[u8]) -> Result<Vec<u8>, String> {
        self.key.sign(token).await.map_err(|e| format!("sign: {e}"))
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

/// C-callable signing callback, `adb_sign_fn` in `libadb.h`.
///
/// Implementations must store a PKCS#1 v1.5 signature of the 20-byte
/// SHA-1 prehash in `token` through `out_signature` and `out_length`.
///
/// It returns an `adb_status_t`, taken as the integer it is: any value
/// but that of [`AdbStatus::Ok`], one `adb_status_t` names or not, is
/// reported to the caller as [`AdbStatus::Auth`].
pub type AdbSignFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    token: *const u8,
    token_len: usize,
    out_signature: *mut u8,
    out_capacity: usize,
    out_length: *mut usize,
) -> i32;

/// Caller-supplied authenticator passed to [`adb_connect_with_authenticator`].
///
/// [`adb_connect_with_authenticator`]: crate::adb_connect_with_authenticator
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct adb_authenticator_t {
    /// ADB-format public key blob (the contents of
    /// `~/.android/adbkey.pub`). The bytes are copied on connect, so the
    /// buffer only needs to stay valid for the call. A trailing NUL is
    /// appended if not already present.
    pub public_key: *const u8,
    /// Length of [`public_key`](Self::public_key) in bytes.
    pub public_key_len: usize,
    /// Invoked synchronously during the handshake to sign the
    /// device-issued token.
    pub sign: Option<AdbSignFn>,
    /// Forwarded verbatim to every [`sign`](Self::sign) call; otherwise
    /// opaque to libadb.
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
    /// Copy the key out of `a` and keep its callback.
    ///
    /// # Safety
    ///
    /// `a.public_key` must be readable for `a.public_key_len` bytes when
    /// non-null, and `a.sign` must stay safe to call with `a.user_data`
    /// for as long as the authenticator signs.
    pub(crate) unsafe fn from_ffi(a: &adb_authenticator_t) -> Result<Self, &'static str> {
        let Some(sign_fn) = a.sign else {
            return Err("sign callback is null");
        };
        if a.public_key.is_null() && a.public_key_len > 0 {
            return Err("public_key is null but public_key_len > 0");
        }
        let pub_key_bytes = if a.public_key_len > 0 {
            // SAFETY: non-null, as the length is not zero, and readable for it per `# Safety`.
            unsafe { core::slice::from_raw_parts(a.public_key, a.public_key_len) }
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
        // SAFETY: `from_ffi`'s contract covers the callback; the buffers are live locals.
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
        const OK: i32 = AdbStatus::Ok as i32;
        let res = match status {
            OK if out_len == 0 => Err(String::from("sign callback returned empty signature")),
            OK if out_len <= buf.len() => {
                buf.truncate(out_len);
                Ok(buf)
            }
            OK => Err(format!(
                "sign callback wrote {out_len} bytes, exceeds capacity {}",
                buf.len()
            )),
            other => Err(format!("sign callback returned status {other}")),
        };
        core::future::ready(res)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr;

    use super::*;

    unsafe extern "C" fn signs_with_the_status_in_user_data(
        user_data: *mut c_void,
        _token: *const u8,
        _token_len: usize,
        out_signature: *mut u8,
        _out_capacity: usize,
        out_length: *mut usize,
    ) -> i32 {
        // SAFETY: `signed_with` hands over a live i32, and the
        // authenticator its own buffers.
        unsafe {
            *out_signature = 0xA5;
            *out_length = 1;
            *user_data.cast::<i32>()
        }
    }

    fn signed_with(mut status: i32) -> Result<Vec<u8>, String> {
        let authenticator = adb_authenticator_t {
            public_key: ptr::null(),
            public_key_len: 0,
            sign: Some(signs_with_the_status_in_user_data),
            user_data: ptr::from_mut(&mut status).cast(),
        };
        // SAFETY: the callback is a plain function, and `status` lives
        // until the signature is in.
        let mut auth = unsafe { CallbackAuthenticator::from_ffi(&authenticator) }.unwrap();
        crate::block_on::block_on(auth.sign(&[0; ADB_AUTH_TOKEN_LEN]))
    }

    /// The status is whatever integer the C callback returned, one that
    /// `adb_status_t` names or not.
    #[test]
    fn any_status_but_ok_from_the_sign_callback_fails_the_signature() {
        assert_eq!(signed_with(AdbStatus::Ok as i32), Ok(vec![0xA5]));
        for status in [AdbStatus::Auth as i32, 42, 256, -1, i32::MIN, i32::MAX] {
            assert_eq!(
                signed_with(status),
                Err(format!("sign callback returned status {status}"))
            );
        }
    }
}
