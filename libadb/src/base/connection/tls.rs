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

use super::handshake::{build_host_banner, do_auth, recv_handshake_pkt};
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
    /// The certificate in `tls` must carry the same key that
    /// authenticates over USB, or the device will not have it. When it
    /// does not, the failure is
    /// [`crate::error::AuthError::TlsKeyNotTrusted`]
    /// and the cure is one `adb pair`.
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
        let hello = Packet::new(
            Command::Connect,
            command::ADB_VERSION,
            config.max_payload(),
            banner.to_vec(),
        );
        let desync = DesyncFlag::new();
        send_pkt(&mut transport, &desync, &hello, Checksum::Compute).await?;

        let mut recv_buf = BytesMut::new();
        let pkt = recv_handshake_pkt(&mut transport, &mut recv_buf, config.max_payload()).await?;

        let verdict = match pkt.command {
            Command::Auth if pkt.arg0 == command::AUTH_TOKEN => {
                do_auth(
                    &mut transport,
                    &desync,
                    &mut auth,
                    &mut recv_buf,
                    pkt.data,
                    &config,
                )
                .await?
            }
            _ => pkt,
        };

        let cnxn = match verdict.command {
            Command::Connect => verdict,
            Command::StartTls => {
                Self::upgrade(
                    &mut transport,
                    &desync,
                    &mut auth,
                    &mut recv_buf,
                    verdict,
                    tls,
                    &config,
                )
                .await?
            }
            other => return Err(ProtocolError::UnexpectedCommand(other).into()),
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

        let reply = Packet::new(Command::StartTls, STLS_VERSION, 0, alloc::vec::Vec::new());
        send_pkt(transport, desync, &reply, Checksum::Compute).await?;

        // Anything left in the buffer is early ciphertext, not an
        // error. In practice the device waits and it is empty.
        let pending = core::mem::take(recv_buf);
        if !pending.is_empty() {
            log::debug!("{} bytes arrived alongside STLS", pending.len());
        }

        transport
            .start_tls(tls, &pending)
            .await
            .map_err(|e| Self::verdict(e))?;

        // The host does not repeat its CNXN. The device sends one from
        // inside the session, and that is the first thing to arrive.
        let pkt = recv_handshake_pkt(transport, recv_buf, config.max_payload())
            .await
            .map_err(Self::verdict_on)?;

        match pkt.command {
            Command::Connect => Ok(pkt),
            // Not seen on any device so far, but cheap to honour.
            Command::Auth if pkt.arg0 == command::AUTH_TOKEN => {
                let resp = do_auth(transport, desync, auth, recv_buf, pkt.data, config).await?;
                if resp.command == Command::Connect {
                    Ok(resp)
                } else {
                    Err(AuthError::Rejected.into())
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

    /// The same judgement, for a failure already wrapped by the frame
    /// reader.
    fn verdict_on(error: Error<<T as ErrorType>::Error>) -> Error<<T as ErrorType>::Error> {
        match error {
            // Our reader turns a closed stream into this, and right
            // after a handshake a closed stream means one thing.
            Error::UnexpectedEof => {
                log::debug!("device closed before its CNXN: the key is not trusted");
                AuthError::TlsKeyNotTrusted.into()
            }
            Error::Io(e) => Self::verdict(e),
            other => other,
        }
    }
}
