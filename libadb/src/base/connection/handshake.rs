use alloc::vec::Vec;
use bytes::{Bytes, BytesMut};
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::{Connection, ConnectionConfig};
use crate::base::auth::Authenticator;
use crate::base::device_banner::DeviceBanner;
use crate::base::error::{AuthError, Error, ProtocolError};
use crate::base::protocol::command::{self, Command};
use crate::base::protocol::features::{self, Feature};
use crate::base::protocol::Checksum;
use crate::base::protocol::Packet;
use crate::base::wire::{recv_pkt, send_pkt, DesyncFlag};

pub(super) fn build_host_banner(features: &[Feature]) -> Vec<u8> {
    let mut banner = Vec::from(b"host::features=".as_ref());
    for (i, f) in features.iter().enumerate() {
        if i > 0 {
            banner.push(b',');
        }
        banner.extend_from_slice(f.wire_name().as_bytes());
    }
    banner
}

// adbd may emit stream-level packets (CLSE/OKAY/WRTE/OPEN) for channels
// left over from a previous session, typically right after host
// re-attach on USB. Drain them until the CNXN/AUTH response arrives.
async fn recv_handshake_pkt<T: Read>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
) -> Result<Packet, Error<T::Error>> {
    loop {
        let pkt = recv_pkt(t, buf, max_payload).await?;
        match pkt.command {
            Command::Connect | Command::Auth => return Ok(pkt),
            Command::Close | Command::Ready | Command::Write | Command::Open => {
                log::debug!("dropping stale {:?} during handshake", pkt.command);
            }
            other => return Err(ProtocolError::UnexpectedCommand(other).into()),
        }
    }
}

impl<T, const MAX_CHANNELS: usize, const MAX_PROPERTIES: usize, const MAX_FEATURES: usize>
    Connection<T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Connect to an ADB device, performing the CNXN/AUTH handshake.
    ///
    /// * `transport` — an async read/write stream (TCP, USB, etc.)
    /// * `auth` — authenticator providing RSA signing and public key
    /// * `features` — features this host advertises; use
    ///   [`DEFAULT_HOST_FEATURES`](crate::protocol::features::DEFAULT_HOST_FEATURES)
    ///   for the conservative set of features this library implements.
    ///
    /// Builds the identity banner as `host::features=<csv>` from the
    /// supplied list, then delegates to [`connect_with_raw_banner`].
    /// Delayed ACK (credit-based flow control) is enabled only when
    /// [`Feature::DelayedAck`] is in `features` and the device also advertises it.
    ///
    /// [`connect_with_raw_banner`]: Self::connect_with_raw_banner
    pub async fn connect<A: Authenticator>(
        transport: T,
        auth: A,
        features: &[Feature],
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        Self::connect_with_config(transport, auth, features, ConnectionConfig::new()).await
    }

    /// Like [`connect`](Self::connect), but with explicit resource
    /// limits instead of the desktop defaults.
    ///
    /// `config.max_payload()` is what this host advertises to the device
    /// in CNXN, so it directly bounds how large an inbound packet — and
    /// therefore the receive buffer — can get. Use
    /// [`ConnectionConfig::embedded`] as a starting point on memory-tight
    /// targets.
    pub async fn connect_with_config<A: Authenticator>(
        transport: T,
        auth: A,
        features: &[Feature],
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let banner = build_host_banner(features);
        Self::connect_with_raw_banner_and_config(transport, auth, banner.as_slice(), config).await
    }

    /// Connect to an ADB device with a caller-supplied raw identity
    /// banner (e.g. `b"host::features=shell_v2,delayed_ack"`).
    ///
    /// Escape hatch for callers that need properties beyond a plain
    /// feature list; prefer [`connect`](Self::connect) for the common
    /// case.
    pub async fn connect_with_raw_banner<A: Authenticator>(
        transport: T,
        auth: A,
        banner: &[u8],
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        Self::connect_with_raw_banner_and_config(transport, auth, banner, ConnectionConfig::new())
            .await
    }

    /// [`connect_with_raw_banner`](Self::connect_with_raw_banner) with
    /// explicit resource limits.
    pub async fn connect_with_raw_banner_and_config<A: Authenticator>(
        mut transport: T,
        mut auth: A,
        banner: &[u8],
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let pkt = Packet::new(
            Command::Connect,
            command::ADB_VERSION,
            config.max_payload(),
            banner.to_vec(),
        );
        // The device has not told us its version yet, so stay on the
        // conservative side: a pre-0x0100_0001 peer verifies this packet.
        // The flag outlives the handshake: it moves into the
        // `Connection` that this builds, carrying over an abandoned
        // write from the handshake itself.
        let desync = DesyncFlag::new();
        send_pkt(&mut transport, &desync, &pkt, Checksum::Compute).await?;

        let mut recv_buf = BytesMut::new();
        let pkt = recv_handshake_pkt(&mut transport, &mut recv_buf, config.max_payload()).await?;

        let cnxn = match pkt.command {
            Command::Connect => pkt,
            Command::Auth if pkt.arg0 == command::AUTH_TOKEN => {
                Self::do_auth(
                    &mut transport,
                    &desync,
                    &mut auth,
                    &mut recv_buf,
                    pkt.data,
                    &config,
                )
                .await?
            }
            other => return Err(ProtocolError::UnexpectedCommand(other).into()),
        };

        let delayed_ack = features::has_feature(banner, features::DELAYED_ACK)
            && features::has_feature(&cnxn.data, features::DELAYED_ACK);

        let device_banner = Some(DeviceBanner::from_bytes(cnxn.data)?);

        Ok(Self {
            transport,
            channels: core::array::from_fn(|_| None),
            // Bounded by our own encoder, not just by the device's offer.
            max_payload: cnxn.arg1.min(command::MAX_PAYLOAD),
            protocol_version: cnxn.arg0.min(command::ADB_VERSION),
            config,
            device_banner,
            local_id_counter: 1,
            incoming: alloc::collections::VecDeque::new(),
            delayed_ack,
            recv_buf,
            desync,
        })
    }

    async fn do_auth<A: Authenticator>(
        transport: &mut T,
        desync: &DesyncFlag,
        auth: &mut A,
        recv_buf: &mut BytesMut,
        token: Bytes,
        config: &ConnectionConfig,
    ) -> Result<Packet, Error<<T as ErrorType>::Error>> {
        let signature = auth
            .sign(&token)
            .await
            .map_err(|_| Error::Auth(AuthError::SignFailed))?;

        send_pkt(
            transport,
            desync,
            &Packet::auth_signature(signature),
            Checksum::Compute,
        )
        .await?;

        let resp = recv_handshake_pkt(transport, recv_buf, config.max_payload()).await?;
        if resp.command == Command::Connect {
            return Ok(resp);
        }

        if resp.command == Command::Auth && resp.arg0 == command::AUTH_TOKEN {
            let pubkey = auth.public_key();
            send_pkt(
                transport,
                desync,
                &Packet::auth_public_key(pubkey.to_vec()),
                Checksum::Compute,
            )
            .await?;

            let resp = recv_handshake_pkt(transport, recv_buf, config.max_payload()).await?;
            if resp.command == Command::Connect {
                return Ok(resp);
            }
        }

        Err(AuthError::Rejected.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_host_banner_empty_features() {
        assert_eq!(build_host_banner(&[]), b"host::features=");
    }

    #[test]
    fn build_host_banner_single_feature() {
        assert_eq!(
            build_host_banner(&[Feature::ShellV2]),
            b"host::features=shell_v2",
        );
    }

    #[test]
    fn build_host_banner_multiple_features_preserves_order() {
        assert_eq!(
            build_host_banner(&[Feature::ShellV2, Feature::Cmd, Feature::DelayedAck]),
            b"host::features=shell_v2,cmd,delayed_ack",
        );
    }

    #[test]
    fn build_host_banner_matches_default_host_features() {
        let banner = build_host_banner(features::DEFAULT_HOST_FEATURES);
        assert!(banner.starts_with(b"host::features="));
        for f in features::DEFAULT_HOST_FEATURES {
            assert!(
                features::has_feature(banner.as_slice(), f.wire_name().as_bytes()),
                "banner does not advertise {:?}",
                f,
            );
        }
    }
}
