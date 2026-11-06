use bytes::{Bytes, BytesMut};
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::{Connection, ConnectionConfig, HostBanner};
use crate::base::auth::Authenticator;
use crate::base::channel_table::ChannelTable;
use crate::base::incoming::IncomingQueue;
use crate::base::negotiated::Negotiated;
use crate::base::protocol::command::{self, AuthKind, Command};
use crate::base::protocol::Checksum;
use crate::base::protocol::Packet;
use crate::base::wire::{recv_pkt, send_pkt, DesyncFlag};
use crate::error::{AuthError, Error, ProtocolError};

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
        transport: T,
        auth: A,
        banner: HostBanner<'_>,
        config: ConnectionConfig,
    ) -> Result<Self, Error<<T as ErrorType>::Error>> {
        let mut handshake = Handshake::new(transport, auth, banner, config);
        match handshake.open().await? {
            Verdict::Connected(cnxn) => handshake.assemble(cnxn),
            Verdict::StartTls(offer) => {
                log::debug!("device demands TLS: STLS version {:#010x}", offer.arg0);
                Err(ProtocolError::TlsRequired.into())
            }
        }
    }
}

pub(crate) enum Verdict {
    Connected(Packet),
    StartTls(Packet),
}

impl Verdict {
    fn of(pkt: Packet) -> Result<Self, Packet> {
        match pkt.command {
            Command::Connect => Ok(Self::Connected(pkt)),
            Command::StartTls => Ok(Self::StartTls(pkt)),
            _ => Err(pkt),
        }
    }
}

pub(super) struct Handshake<T, A> {
    pub(super) transport: T,
    auth: A,
    banner: Bytes,
    delayed_ack: bool,
    config: ConnectionConfig,
    desync: DesyncFlag,
    pub(super) recv_buf: BytesMut,
}

impl<T, A> Handshake<T, A>
where
    T: Read + Write,
    A: Authenticator,
{
    pub(super) fn new(
        transport: T,
        auth: A,
        banner: HostBanner<'_>,
        config: ConnectionConfig,
    ) -> Self {
        Self {
            transport,
            auth,
            banner: banner.to_bytes(),
            delayed_ack: banner.lists(crate::Feature::DelayedAck),
            config,
            desync: DesyncFlag::new(),
            recv_buf: BytesMut::new(),
        }
    }

    pub(super) async fn open(&mut self) -> Result<Verdict, Error<<T as ErrorType>::Error>> {
        let hello = Packet::new(
            Command::Connect,
            command::ADB_VERSION,
            self.config.max_payload(),
            self.banner.clone(),
        );
        self.send(&hello).await?;

        let pkt = match Verdict::of(self.recv().await?) {
            Ok(verdict) => return Ok(verdict),
            Err(pkt) => pkt,
        };
        match (pkt.command, AuthKind::try_from(pkt.arg0)) {
            (Command::Auth, Ok(AuthKind::Token)) => self.do_auth(pkt.data).await,
            (other, _) => Err(ProtocolError::UnexpectedCommand(other).into()),
        }
    }

    pub(super) async fn do_auth(
        &mut self,
        token: Bytes,
    ) -> Result<Verdict, Error<<T as ErrorType>::Error>> {
        if token.len() != command::AUTH_TOKEN_LEN {
            return Err(ProtocolError::InvalidAuthToken(token.len()).into());
        }

        let signature = self
            .auth
            .sign(&token)
            .await
            .map_err(|e| Error::Auth(AuthError::SignFailed(alloc::format!("{e}"))))?;
        self.send(&Packet::auth_signature(signature)).await?;

        let resp = match Verdict::of(self.recv().await?) {
            Ok(verdict) => return Ok(verdict),
            Err(resp) => resp,
        };
        match (resp.command, AuthKind::try_from(resp.arg0)) {
            (Command::Auth, Ok(AuthKind::Token)) => {}
            _ => return Err(AuthError::Rejected.into()),
        }

        if !self.auth.offer_public_key() {
            return Err(AuthError::KeyNotTrusted.into());
        }

        let pubkey = self.auth.public_key().to_vec();
        self.send(&Packet::auth_public_key(pubkey)).await?;

        match Verdict::of(self.recv().await?) {
            Ok(verdict) => Ok(verdict),
            Err(_) => Err(AuthError::Rejected.into()),
        }
    }

    pub(super) fn assemble(
        self,
        cnxn: Packet,
    ) -> Result<Connection<T>, Error<<T as ErrorType>::Error>> {
        let negotiated = Negotiated::new(self.delayed_ack, cnxn, self.config)?;
        Ok(Connection {
            transport: self.transport,
            table: ChannelTable::new(negotiated.config.max_channels(), negotiated.rx_policy()),
            negotiated,
            incoming: IncomingQueue::default(),
            recv_buf: self.recv_buf,
            desync: self.desync,
        })
    }

    pub(super) async fn send(
        &mut self,
        pkt: &Packet,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        send_pkt(&mut self.transport, &self.desync, pkt, Checksum::Compute).await
    }

    pub(super) async fn recv(&mut self) -> Result<Packet, Error<<T as ErrorType>::Error>> {
        loop {
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Connect | Command::Auth | Command::StartTls => return Ok(pkt),
                Command::Close | Command::Ready | Command::Write | Command::Open => {
                    log::debug!("dropping stale {:?} during handshake", pkt.command);
                }
                other => return Err(ProtocolError::UnexpectedCommand(other).into()),
            }
        }
    }
}
