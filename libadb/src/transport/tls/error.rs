//! [`TlsError`], and how to tell from one that the device refused the
//! key.

/// Why a TLS transport failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError<E> {
    /// The transport underneath failed.
    Io(E),
    /// The TLS session failed: a handshake, a record, or an alert
    /// the device sent.
    Tls(rustls::Error),
    /// The device closed the connection in the middle of the
    /// handshake. Our certificate only goes out once the handshake
    /// is over on our side, so the device had not seen the key.
    HandshakeClosed,
    /// The transport underneath took none of a write. An
    /// `embedded-io` writer may not do that with bytes on offer, so
    /// the connection is taken as gone, not as a device refusing
    /// anything.
    WriteZero,
    /// What was asked cannot be done on this transport: `start_tls`
    /// on USB or on a transport that is no longer plain, keying
    /// material while still in the clear, or a read, write, flush or
    /// split after a handshake that failed or was dropped part way,
    /// which takes the socket with it.
    NotAvailable,
    /// A write came after `shutdown`. rustls would still seal it and
    /// send it behind the `close_notify`, which the peer takes as the
    /// end of what we have to say.
    Closed,
}

impl<E: core::fmt::Display> core::fmt::Display for TlsError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::HandshakeClosed => f.write_str("tls: device closed during the handshake"),
            Self::WriteZero => f.write_str("tls: the transport took none of a write"),
            Self::NotAvailable => f.write_str("tls: not available on this transport"),
            Self::Closed => f.write_str("tls: the session was already shut down"),
        }
    }
}

impl<E> core::error::Error for TlsError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            Self::HandshakeClosed | Self::WriteZero | Self::NotAvailable | Self::Closed => None,
        }
    }
}

impl<E: embedded_io::Error> embedded_io::Error for TlsError<E> {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => e.kind(),
            // Nothing takes a failed session back: every later read and
            // write gets the same failure.
            Self::Tls(_) => embedded_io::ErrorKind::ConnectionAborted,
            Self::HandshakeClosed => embedded_io::ErrorKind::Other,
            Self::WriteZero => embedded_io::ErrorKind::WriteZero,
            Self::NotAvailable => embedded_io::ErrorKind::Unsupported,
            Self::Closed => embedded_io::ErrorKind::BrokenPipe,
        }
    }
}

/// Alerts a device sends when it will not have the key.
///
/// adbd refuses from its certificate callback, which BoringSSL
/// answers with `certificate_unknown`; the rest are the other
/// certificate alerts a TLS stack might pick instead. Generic ones
/// such as `handshake_failure` or `decrypt_error` stay out: they
/// mean the handshake broke for some other reason, and calling that
/// a refusal would send the user off to pair for nothing. So does
/// `certificate_required`, which says no certificate arrived at all.
fn alert_means_rejection(alert: rustls::AlertDescription) -> bool {
    use rustls::AlertDescription as A;
    matches!(
        alert,
        A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::AccessDenied
    )
}

impl<E> TlsError<E> {
    /// Whether this is the device refusing the key, rather than a
    /// connection that went wrong on its own: an alert over the
    /// certificate, such as the `certificate_unknown` adbd sends.
    ///
    /// A device that refuses by just closing is not caught here.
    /// [`Connection::connect_tls`](crate::Connection::connect_tls)
    /// reports that as
    /// [`AuthError::TlsClosedBeforeConnect`](crate::error::AuthError::TlsClosedBeforeConnect).
    pub fn is_key_rejected(&self) -> bool {
        match self {
            Self::Tls(rustls::Error::AlertReceived(a)) => alert_means_rejection(*a),
            // Not `HandshakeClosed`: the key had not gone out yet. A
            // device that refuses by just closing does so after the
            // handshake, and the connect path names that on its own.
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use embedded_io::{Error as _, ErrorKind};

    use super::TlsError;

    /// What the connection goes by to tell a session past saving from a
    /// failure that may pass.
    #[test]
    fn a_failed_session_is_an_aborted_connection() {
        let session = TlsError::<std::io::Error>::Tls(rustls::Error::DecryptError);
        assert_eq!(session.kind(), ErrorKind::ConnectionAborted);

        let timeout = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert_eq!(TlsError::Io(timeout).kind(), ErrorKind::Other);
    }
}
