//! The handshake with a device that wants TLS.
//!
//! Same opening as the plain handshake — a CNXN and whatever the device
//! answers — but where that one gives up on `STLS`, this one takes the
//! offer up: it answers with its own `STLS`, starts the session on the
//! spot, and reads the device's CNXN from inside it.
//!
//! A device that does not ask for TLS gets the ordinary treatment, so a
//! caller does not have to know in advance which kind it is talking to.

use embedded_io::ErrorType;

use super::handshake::{Handshake, Verdict};
use super::{Connection, ConnectionConfig, HostBanner};
use crate::base::auth::Authenticator;
use crate::base::error::{AuthError, Error, ProtocolError};
use crate::base::protocol::command::{AuthKind, Command};
use crate::base::protocol::constant::STLS_VERSION;
use crate::base::protocol::Packet;
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
    /// Answer the device's `STLS`, start the session, and read the CNXN
    /// that arrives inside it.
    async fn upgrade(
        &mut self,
        offer: Packet,
        tls: &TlsClientConfig,
    ) -> Result<Packet, Error<<T as ErrorType>::Error>> {
        if offer.arg0 != STLS_VERSION {
            // Worth knowing, not worth refusing over: AOSP does not negotiate it.
            log::warn!(
                "device offers STLS version {:#010x}, we speak {:#010x}",
                offer.arg0,
                STLS_VERSION
            );
        }

        // A TLS 1.3 server says nothing before our ClientHello, so bytes
        // already here came in the clear behind the STLS. The session
        // would take them for a broken record; name them for what they are.
        if !self.recv_buf.is_empty() {
            return Err(ProtocolError::DataAfterStls.into());
        }

        let reply = Packet::new(Command::StartTls, STLS_VERSION, 0, alloc::vec::Vec::new());
        self.send(&reply).await?;

        // Nothing here is the device refusing our key: the certificate
        // leaves in our last flight, once the handshake is over on our
        // side, so the device has not seen it yet.
        self.transport.start_tls(tls).await.map_err(Error::Io)?;

        // The host does not repeat its CNXN. The device sends one from
        // inside the session, and that is the first thing to arrive.
        let pkt = self.recv().await.map_err(|e| self.verdict_on(e))?;

        match (pkt.command, AuthKind::try_from(pkt.arg0)) {
            (Command::Connect, _) => Ok(pkt),
            // adbd sends no AUTH inside TLS, and adb would ignore one, but
            // answering costs nothing. It only puts the CNXN off, so what
            // fails in it is judged as a failed CNXN read would be.
            (Command::Auth, Ok(AuthKind::Token)) => {
                let verdict = self
                    .do_auth(pkt.data)
                    .await
                    .map_err(|e| self.verdict_on(e))?;
                match verdict {
                    Verdict::Connected(cnxn) => Ok(cnxn),
                    // Inside the session already, where STLS is out of turn.
                    Verdict::StartTls(_) => {
                        Err(ProtocolError::UnexpectedCommand(Command::StartTls).into())
                    }
                }
            }
            (other, _) => Err(ProtocolError::UnexpectedCommand(other).into()),
        }
    }

    /// Turn a transport failure into the reason a caller can act on.
    fn verdict(error: <T as ErrorType>::Error) -> Error<<T as ErrorType>::Error> {
        if T::is_key_rejected(&error) {
            log::debug!("device closed the TLS session over our key: {error:?}");
            AuthError::TlsKeyNotTrusted.into()
        } else {
            Error::Io(error)
        }
    }

    /// The same judgement, for a failure met inside the session before
    /// the device's CNXN, with the receive buffer holding whatever of a
    /// packet had arrived.
    fn verdict_on(&self, error: Error<<T as ErrorType>::Error>) -> Error<<T as ErrorType>::Error> {
        match error {
            // Not a byte of a CNXN. A device that closes over our key looks
            // like this, and so does one that took the key and went away.
            // Part of one means the device let us in, so the end of the
            // stream stays what it is.
            Error::UnexpectedEof if self.recv_buf.is_empty() => {
                log::debug!("device closed the TLS session before its CNXN");
                AuthError::TlsClosedBeforeConnect.into()
            }
            Error::Io(e) => Self::verdict(e),
            other => other,
        }
    }
}
