use alloc::vec::Vec;

/// Trait for ADB authentication.
///
/// The ADB handshake requires signing a device-provided token with an RSA private key
/// (PKCS#1 v1.5 with SHA-1) and optionally sending the public key for on-device
/// authorization.
///
/// Implement this trait to plug in any RSA library (e.g. `rsa`, `ring`, `openssl`,
/// or a hardware security module). The `keys` feature ships a ready one,
/// `keys::AdbKey`, which also generates a key when there is none.
pub trait Authenticator {
    type Error;

    /// Sign the token received from the device.
    ///
    /// Must produce a PKCS#1 v1.5 / SHA-1 signature.
    /// Returns the raw signature bytes.
    fn sign(&mut self, token: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>>;

    /// Return the RSA public key in the ADB-specific format.
    ///
    /// Format: base64-encoded RSA public key followed by ` user@host\0`.
    fn public_key(&self) -> &[u8];
}

/// A mutable borrow authenticates as whatever it points at, so one key
/// can serve several connections in turn: pass `&mut key` where a
/// connection wants an authenticator of its own, rather than rebuilding
/// the key — or duplicating the secret — for each.
impl<A: Authenticator + ?Sized> Authenticator for &mut A {
    type Error = A::Error;

    fn sign(&mut self, token: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        (**self).sign(token)
    }

    fn public_key(&self) -> &[u8] {
        (**self).public_key()
    }
}

use core::future::Future;
