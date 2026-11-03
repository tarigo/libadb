use bytes::{Bytes, BytesMut};
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::{Connection, ConnectionConfig, HostBanner};
use crate::base::auth::Authenticator;
use crate::base::device_banner::DeviceBanner;
use crate::base::error::{AuthError, Error, ProtocolError};
use crate::base::protocol::command::{self, Command};
use crate::base::protocol::features;
use crate::base::protocol::Checksum;
use crate::base::protocol::Packet;
use crate::base::wire::{recv_pkt, send_pkt, DesyncFlag};

// adbd may emit stream-level packets (CLSE/OKAY/WRTE/OPEN) for channels
// left over from a previous session, typically right after host
// re-attach on USB. Drain them until a handshake packet arrives: CNXN,
// AUTH or STLS.
pub(crate) async fn recv_handshake_pkt<T: Read>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
) -> Result<Packet, Error<T::Error>> {
    loop {
        let pkt = recv_pkt(t, buf, max_payload).await?;
        match pkt.command {
            Command::Connect | Command::Auth | Command::StartTls => return Ok(pkt),
            Command::Close | Command::Ready | Command::Write | Command::Open => {
                log::debug!("dropping stale {:?} during handshake", pkt.command);
            }
            other => return Err(ProtocolError::UnexpectedCommand(other).into()),
        }
    }
}

impl<T> Connection<T>
where
    T: Read + Write,
{
    /// Connect to an ADB device, performing the CNXN/AUTH handshake.
    ///
    /// * `transport` — an async read/write stream (TCP, USB, etc.)
    /// * `auth` — authenticator providing RSA signing and public key
    /// * `banner` — what this host sends in its CNXN:
    ///   [`HostBanner::Features`] builds `host::features=<csv>` from a
    ///   list, [`HostBanner::Raw`] sends bytes of your own, and
    ///   [`HostBanner::default()`] advertises
    ///   [`DEFAULT_HOST_FEATURES`](crate::DEFAULT_HOST_FEATURES), the set
    ///   this library implements.
    /// * `config` — resource limits. [`ConnectionConfig::new`] keeps the
    ///   desktop defaults; [`ConnectionConfig::embedded`] is the starting
    ///   point on memory-tight targets. `config.max_payload()` is what
    ///   this host advertises in CNXN, so it bounds how large an inbound
    ///   packet — and therefore the receive buffer — can get.
    ///
    /// Delayed ACK (credit-based flow control) is enabled only when the
    /// banner names [`Feature::DelayedAck`](crate::Feature::DelayedAck)
    /// and the device also advertises it.
    ///
    /// A device that answers with `STLS`, as Android 11+ wireless
    /// debugging does, fails this with [`ProtocolError::TlsRequired`];
    /// with the `tls` feature, `connect_tls` serves both kinds.
    ///
    /// ```ignore
    /// use libadb::{Connection, ConnectionConfig, Feature, HostBanner};
    ///
    /// let conn = Connection::connect(
    ///     transport,
    ///     auth,
    ///     HostBanner::Features(&[Feature::ShellV2]),
    ///     ConnectionConfig::new(),
    /// )
    /// .await?;
    /// ```
    pub async fn connect<A: Authenticator>(
        mut transport: T,
        mut auth: A,
        banner: HostBanner<'_>,
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let banner = banner.to_bytes();
        // The flag outlives the handshake: it moves into the
        // `Connection` that this builds, carrying over an abandoned
        // write from the handshake itself.
        let desync = DesyncFlag::new();
        let mut recv_buf = BytesMut::new();
        let verdict = open(
            &mut transport,
            &mut auth,
            &banner,
            &config,
            &desync,
            &mut recv_buf,
        )
        .await?;

        match verdict {
            Verdict::Connected(cnxn) => {
                Self::assemble(transport, desync, recv_buf, &banner, config, cnxn)
            }
            Verdict::StartTls(offer) => {
                log::debug!("device demands TLS: STLS version {:#010x}", offer.arg0);
                Err(ProtocolError::TlsRequired.into())
            }
        }
    }

    /// Everything after the device's CNXN: negotiate, parse the banner
    /// and build the connection.
    ///
    /// Split out so the TLS path, which reads its CNXN from inside the
    /// session, ends the same way.
    pub(crate) fn assemble(
        transport: T,
        desync: DesyncFlag,
        recv_buf: BytesMut,
        banner: &[u8],
        config: ConnectionConfig,
        cnxn: Packet,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let delayed_ack = features::has_feature(banner, features::DELAYED_ACK)
            && features::has_feature(&cnxn.data, features::DELAYED_ACK);

        let device_banner = Some(DeviceBanner::from_bytes(
            cnxn.data,
            config.max_banner_properties(),
        )?);

        Ok(Self {
            transport,
            channels: (0..config.max_channels()).map(|_| None).collect(),
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
}

/// How the device ended the opening exchange.
pub(crate) enum Verdict {
    /// Its own CNXN: it is satisfied.
    Connected(Packet),
    /// STLS: it will only go on inside TLS.
    StartTls(Packet),
}

impl Verdict {
    /// The verdict `pkt` carries, or `pkt` back if it carries none.
    fn of(pkt: Packet) -> Result<Self, Packet> {
        match pkt.command {
            Command::Connect => Ok(Self::Connected(pkt)),
            Command::StartTls => Ok(Self::StartTls(pkt)),
            _ => Err(pkt),
        }
    }
}

/// The half of the handshake both entry points share: send our CNXN
/// and bring back the device's verdict.
///
/// Authentication happens in here when the device asks for it. A
/// first answer that is none of CNXN, STLS and AUTH fails here, as a
/// protocol error.
pub(crate) async fn open<T: Read + Write, A: Authenticator>(
    transport: &mut T,
    auth: &mut A,
    banner: &Bytes,
    config: &ConnectionConfig,
    desync: &DesyncFlag,
    recv_buf: &mut BytesMut,
) -> Result<Verdict, Error<<T as ErrorType>::Error>> {
    let hello = Packet::new(
        Command::Connect,
        command::ADB_VERSION,
        config.max_payload(),
        banner.clone(),
    );
    // The device has not told us its version yet, so stay on the
    // conservative side: a pre-0x0100_0001 peer verifies this packet.
    send_pkt(transport, desync, &hello, Checksum::Compute).await?;

    let pkt = recv_handshake_pkt(transport, recv_buf, config.max_payload()).await?;
    let pkt = match Verdict::of(pkt) {
        Ok(verdict) => return Ok(verdict),
        Err(pkt) => pkt,
    };
    match pkt.command {
        Command::Auth if pkt.arg0 == command::AUTH_TOKEN => {
            do_auth(transport, desync, auth, recv_buf, pkt.data, config).await
        }
        other => Err(ProtocolError::UnexpectedCommand(other).into()),
    }
}

/// Answer the device's AUTH challenge.
///
/// Returns the verdict the exchange ended on: CNXN once the key is
/// accepted, or STLS if the device switches to TLS midway. Any AUTH but
/// the one token that asks for the key is [`AuthError::Rejected`]; that
/// token is [`AuthError::KeyNotTrusted`] when the authenticator will not
/// offer the key; a command with no place in the handshake, such as
/// SYNC, fails as [`ProtocolError::UnexpectedCommand`].
pub(crate) async fn do_auth<T: Read + Write, A: Authenticator>(
    transport: &mut T,
    desync: &DesyncFlag,
    auth: &mut A,
    recv_buf: &mut BytesMut,
    token: Bytes,
    config: &ConnectionConfig,
) -> Result<Verdict, Error<<T as ErrorType>::Error>> {
    // Checked here rather than in each authenticator: a stray
    // length must not reach a signer that may be someone else's.
    if token.len() != command::AUTH_TOKEN_LEN {
        return Err(ProtocolError::InvalidAuthToken(token.len()).into());
    }

    let signature = auth
        .sign(&token)
        .await
        .map_err(|e| Error::Auth(AuthError::SignFailed(alloc::format!("{e}"))))?;

    send_pkt(
        transport,
        desync,
        &Packet::auth_signature(signature),
        Checksum::Compute,
    )
    .await?;

    let resp = recv_handshake_pkt(transport, recv_buf, config.max_payload()).await?;
    let resp = match Verdict::of(resp) {
        Ok(verdict) => return Ok(verdict),
        Err(resp) => resp,
    };
    match resp.command {
        // A second token: the signature was not enough, offer the key.
        Command::Auth if resp.arg0 == command::AUTH_TOKEN => {}
        _ => return Err(AuthError::Rejected.into()),
    }

    // The key is what brings up the dialog on the device; an
    // authenticator that only asks whether it is trusted stops here.
    if !auth.offer_public_key() {
        return Err(AuthError::KeyNotTrusted.into());
    }

    {
        let pubkey = auth.public_key();
        send_pkt(
            transport,
            desync,
            &Packet::auth_public_key(pubkey.to_vec()),
            Checksum::Compute,
        )
        .await?;

        let resp = recv_handshake_pkt(transport, recv_buf, config.max_payload()).await?;
        if let Ok(verdict) = Verdict::of(resp) {
            return Ok(verdict);
        }
    }

    Err(AuthError::Rejected.into())
}
