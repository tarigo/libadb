//! The handshake with a device that wants TLS.
//!
//! Same opening as the plain handshake — a CNXN and whatever the device
//! answers — but where that one gives up on `STLS`, this one takes the
//! offer up: it answers with its own `STLS`, starts the session on the
//! spot, and reads the device's CNXN from inside it.
//!
//! A device that does not ask for TLS gets the ordinary treatment, so a
//! caller does not have to know in advance which kind it is talking to.

use bytes::BytesMut;
use embedded_io::ErrorType;

use super::handshake::{build_host_banner, do_auth, open, recv_handshake_pkt, Verdict};
use super::{Connection, ConnectionConfig};
use crate::base::auth::Authenticator;
use crate::base::error::{AuthError, Error, ProtocolError};
use crate::base::protocol::command::{self, Command};
use crate::base::protocol::constant::STLS_VERSION;
use crate::base::protocol::features::Feature;
use crate::base::protocol::{Checksum, Packet};
use crate::base::wire::{send_pkt, DesyncFlag};
use crate::tls::TlsClientConfig;
use crate::transport::tls::StartTls;

impl<T, const MAX_CHANNELS: usize, const MAX_PROPERTIES: usize, const MAX_FEATURES: usize>
    Connection<T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
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
    /// `auth` answers an AUTH challenge, as it does for `connect`, and
    /// `tls` is used only if the device sends `STLS`. Build both from
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
        features: &[Feature],
        tls: &TlsClientConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        Self::connect_tls_with_config(transport, auth, features, tls, ConnectionConfig::new()).await
    }

    /// [`connect_tls`](Self::connect_tls) with explicit resource limits.
    pub async fn connect_tls_with_config<A: Authenticator>(
        transport: T,
        auth: A,
        features: &[Feature],
        tls: &TlsClientConfig,
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let banner = build_host_banner(features);
        Self::connect_tls_with_raw_banner_and_config(
            transport,
            auth,
            banner.as_slice(),
            tls,
            config,
        )
        .await
    }

    /// [`connect_tls`](Self::connect_tls) with a caller-supplied banner
    /// and explicit resource limits.
    pub async fn connect_tls_with_raw_banner_and_config<A: Authenticator>(
        mut transport: T,
        mut auth: A,
        banner: &[u8],
        tls: &TlsClientConfig,
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let desync = DesyncFlag::new();
        let mut recv_buf = BytesMut::new();
        let verdict = open(
            &mut transport,
            &mut auth,
            banner,
            &config,
            &desync,
            &mut recv_buf,
        )
        .await?;

        let cnxn = match verdict {
            Verdict::Connected(cnxn) => cnxn,
            Verdict::StartTls(offer) => {
                Self::upgrade(
                    &mut transport,
                    &desync,
                    &mut auth,
                    &mut recv_buf,
                    offer,
                    tls,
                    &config,
                )
                .await?
            }
        };

        Self::assemble(transport, desync, recv_buf, banner, config, cnxn)
    }

    /// Answer the device's `STLS`, start the session, and read the CNXN
    /// that arrives inside it.
    async fn upgrade<A: Authenticator>(
        transport: &mut T,
        desync: &DesyncFlag,
        auth: &mut A,
        recv_buf: &mut BytesMut,
        offer: Packet,
        tls: &TlsClientConfig,
        config: &ConnectionConfig,
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
        if !recv_buf.is_empty() {
            return Err(ProtocolError::DataAfterStls.into());
        }

        let reply = Packet::new(Command::StartTls, STLS_VERSION, 0, alloc::vec::Vec::new());
        send_pkt(transport, desync, &reply, Checksum::Compute).await?;

        // Nothing here is the device refusing our key: the certificate
        // leaves in our last flight, once the handshake is over on our
        // side, so the device has not seen it yet.
        transport.start_tls(tls).await.map_err(Error::Io)?;

        // The host does not repeat its CNXN. The device sends one from
        // inside the session, and that is the first thing to arrive.
        let pkt = recv_handshake_pkt(transport, recv_buf, config.max_payload())
            .await
            .map_err(|e| Self::verdict_on(e, recv_buf))?;

        match pkt.command {
            Command::Connect => Ok(pkt),
            // adbd sends no AUTH inside TLS, and adb would ignore one, but
            // answering costs nothing. It only puts the CNXN off, so what
            // fails in it is judged as a failed CNXN read would be.
            Command::Auth if pkt.arg0 == command::AUTH_TOKEN => {
                let verdict = do_auth(transport, desync, auth, recv_buf, pkt.data, config)
                    .await
                    .map_err(|e| Self::verdict_on(e, recv_buf))?;
                match verdict {
                    Verdict::Connected(cnxn) => Ok(cnxn),
                    // Inside the session already, where STLS is out of turn.
                    Verdict::StartTls(_) => {
                        Err(ProtocolError::UnexpectedCommand(Command::StartTls).into())
                    }
                }
            }
            other => Err(ProtocolError::UnexpectedCommand(other).into()),
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
    /// the device's CNXN, with `recv_buf` holding whatever of a packet
    /// had arrived.
    fn verdict_on(
        error: Error<<T as ErrorType>::Error>,
        recv_buf: &BytesMut,
    ) -> Error<<T as ErrorType>::Error> {
        match error {
            // Not a byte of a CNXN. A device that closes over our key looks
            // like this, and so does one that took the key and went away.
            // Part of one means the device let us in, so the end of the
            // stream stays what it is.
            Error::UnexpectedEof if recv_buf.is_empty() => {
                log::debug!("device closed the TLS session before its CNXN");
                AuthError::TlsClosedBeforeConnect.into()
            }
            Error::Io(e) => Self::verdict(e),
            other => other,
        }
    }
}
