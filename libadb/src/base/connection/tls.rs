use embedded_io::ErrorType;

use super::handshake::{Handshake, Verdict};
use super::{Connection, ConnectionConfig, HostBanner};
use crate::base::auth::Authenticator;
use crate::base::protocol::command::{AuthKind, Command};
use crate::base::protocol::constant::STLS_VERSION;
use crate::base::protocol::Packet;
use crate::error::{AuthError, Error, ProtocolError};
use crate::tls::TlsClientConfig;
use crate::transport::tls::StartTls;

impl<T> Connection<T>
where
    T: StartTls,
{
    /// Connect, starting TLS if the device asks for it.
    ///
    /// Wireless debugging on Android 11+ answers the handshake with
    /// `STLS`; this carries that through and hands back a connection
    /// running inside TLS. A device on the plain port answers CNXN or
    /// AUTH instead and is served exactly as
    /// [`connect`](Self::connect) would serve it, so one call covers
    /// both.
    ///
    /// `transport` starts in the clear: a socket wrapped in
    /// [`MaybeTls::plain`](crate::transport::tls::MaybeTls::plain), or a
    /// [`Transport`](crate::transport::common::Transport) after
    /// [`tls_ready`](crate::transport::common::Transport::tls_ready).
    /// `auth` answers an AUTH challenge, `banner` goes out in the CNXN
    /// and `config` sets the limits, as they do for `connect`; `tls` is
    /// used only if the device sends `STLS`. Build `auth` and `tls` from
    /// the same key: the certificate in `tls` must carry the key that
    /// authenticates over USB, or the device will not have it.
    ///
    /// The device itself is not authenticated unless `tls` brings a
    /// verifier of your own; see
    /// [`TlsClientConfig::adb`](crate::tls::TlsClientConfig::adb).
    ///
    /// # Errors
    ///
    /// Those of `connect`, except that `STLS` is taken up rather than
    /// refused, and these:
    ///
    /// - [`AuthError::TlsKeyNotTrusted`] when the device refuses the
    ///   key. The cure is one `adb pair`.
    /// - [`AuthError::TlsClosedBeforeConnect`] when the device closes
    ///   the session before its CNXN: it may have refused the key that
    ///   way, or simply gone away.
    /// - [`ProtocolError::DataAfterStls`] when more plaintext came in
    ///   behind the device's `STLS`.
    /// - [`Error::Io`] with the transport's TLS error
    ///   when the handshake itself fails, such as
    ///   [`TlsError::HandshakeClosed`](crate::transport::tls::TlsError::HandshakeClosed)
    ///   when the device hangs up in the middle of it.
    pub async fn connect_tls<A: Authenticator>(
        transport: T,
        auth: A,
        banner: HostBanner<'_>,
        config: ConnectionConfig,
        tls: &TlsClientConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let mut handshake = Handshake::new(transport, auth, banner, config);
        let cnxn = match handshake.open().await? {
            Verdict::Connected(cnxn) => cnxn,
            Verdict::StartTls(offer) => handshake.upgrade(offer, tls).await?,
        };
        handshake.assemble(cnxn)
    }
}

impl<T, A> Handshake<T, A>
where
    T: StartTls,
    A: Authenticator,
{
    async fn upgrade(
        &mut self,
        offer: Packet,
        tls: &TlsClientConfig,
    ) -> Result<Packet, Error<<T as ErrorType>::Error>> {
        if offer.arg0 != STLS_VERSION {
            log::warn!(
                "device offers STLS version {:#010x}, we speak {:#010x}",
                offer.arg0,
                STLS_VERSION
            );
        }

        if !self.recv_buf.is_empty() {
            return Err(ProtocolError::DataAfterStls.into());
        }

        let reply = Packet::new(Command::StartTls, STLS_VERSION, 0, alloc::vec::Vec::new());
        self.send(&reply).await?;

        self.transport.start_tls(tls).await.map_err(Error::Io)?;

        let pkt = self
            .recv()
            .await
            .map_err(|e| self.classify_before_cnxn(e))?;

        match (pkt.command, AuthKind::try_from(pkt.arg0)) {
            (Command::Connect, _) => Ok(pkt),
            (Command::Auth, Ok(AuthKind::Token)) => {
                let verdict = self
                    .do_auth(pkt.data)
                    .await
                    .map_err(|e| self.classify_before_cnxn(e))?;
                match verdict {
                    Verdict::Connected(cnxn) => Ok(cnxn),
                    Verdict::StartTls(_) => {
                        Err(ProtocolError::UnexpectedCommand(Command::StartTls).into())
                    }
                }
            }
            (other, _) => Err(ProtocolError::UnexpectedCommand(other).into()),
        }
    }

    fn classify_tls_error(error: <T as ErrorType>::Error) -> Error<<T as ErrorType>::Error> {
        if T::is_key_rejected(&error) {
            log::debug!("device closed the TLS session over our key: {error:?}");
            AuthError::TlsKeyNotTrusted.into()
        } else {
            Error::Io(error)
        }
    }

    fn classify_before_cnxn(
        &self,
        error: Error<<T as ErrorType>::Error>,
    ) -> Error<<T as ErrorType>::Error> {
        match error {
            Error::UnexpectedEof if self.recv_buf.is_empty() => {
                log::debug!("device closed the TLS session before its CNXN");
                AuthError::TlsClosedBeforeConnect.into()
            }
            Error::Io(e) => Self::classify_tls_error(e),
            other => other,
        }
    }
}
