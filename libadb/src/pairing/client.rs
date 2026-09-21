//! Running the pairing exchange over a transport.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use embedded_io_async::{Read, ReadExactError, Write};
use rsa::rand_core::CryptoRngCore;

use super::aead::{AeadError, Cipher, TAG_LEN};
use super::frame::{self, FrameError, PacketType, HEADER_LEN};
use super::peer_info::{self, PeerInfoError, PeerInfoType};
use super::spake2::{Role, Spake2, Spake2Error};
use crate::keys::AdbKey;
use crate::tls::TlsClientConfig;
use crate::transport::tls::{MaybeTls, StartTls, TlsError};

/// The exporter label, NUL and all: AOSP passes `sizeof("adb-label")`.
const EXPORTER_LABEL: &[u8] = b"adb-label\0";

/// How much exporter output goes into the password.
const EXPORTER_LEN: usize = 64;

/// Who we are and who we expect, terminators included.
const CLIENT_NAME: &[u8] = b"adb pair client\0";
const SERVER_NAME: &[u8] = b"adb pair server\0";

/// Why pairing did not go through.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairingError<E> {
    /// The transport or the TLS session underneath failed.
    Transport(TlsError<E>),
    /// The device closed before it had finished answering.
    Closed,
    /// A packet header made no sense.
    Frame(FrameError),
    /// The device's SPAKE2 message was unusable.
    Spake2(Spake2Error),
    /// A message would not decrypt. In pairing this means the code was
    /// wrong: the two sides agreed on different keys and neither can
    /// tell until now.
    WrongCode,
    /// Encrypting or deriving a key failed.
    Aead(AeadError),
    /// The device's `PeerInfo` was not what it should be.
    PeerInfo(PeerInfoError),
}

impl<E: core::fmt::Display> core::fmt::Display for PairingError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "pairing transport: {e}"),
            Self::Closed => f.write_str("device closed the pairing connection"),
            Self::Frame(e) => write!(f, "pairing frame: {e}"),
            Self::Spake2(e) => write!(f, "pairing key agreement: {e}"),
            Self::WrongCode => f.write_str(
                "pairing failed: the code did not match, or the device dropped the attempt",
            ),
            Self::Aead(e) => write!(f, "pairing cipher: {e}"),
            Self::PeerInfo(e) => write!(f, "pairing peer info: {e}"),
        }
    }
}

impl<E> core::error::Error for PairingError<E> where E: core::error::Error + 'static {}

impl<E> From<ReadExactError<TlsError<E>>> for PairingError<E> {
    fn from(e: ReadExactError<TlsError<E>>) -> Self {
        match e {
            ReadExactError::UnexpectedEof => Self::Closed,
            ReadExactError::Other(e) => Self::Transport(e),
        }
    }
}

/// What the device tells us once it has taken the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    /// The device's GUID, which is also the name it advertises its
    /// connect port under.
    pub guid: String,
}

/// Pair with a device: put `key` into its trusted store.
///
/// `transport` must be a fresh connection to the *pairing* port, which
/// the device shows on its "Wireless debugging" pane next to the code.
/// It is not the port a session later uses, and it stops listening as
/// soon as one pairing succeeds.
///
/// `code` is the six digits shown beside it. Everything else this needs
/// it works out for itself.
///
/// On success the device has `key` and will accept it over TLS from
/// then on, exactly as it accepts a key approved at a USB prompt.
///
/// A wrong code cannot be told apart from a device that gave up: both
/// arrive as [`PairingError::WrongCode`], because the protocol offers
/// nothing finer. The device counts attempts and stops serving after
/// twenty.
pub async fn pair<T, R>(
    transport: &mut MaybeTls<T>,
    tls: &TlsClientConfig,
    key: &AdbKey,
    code: &str,
    rng: &mut R,
) -> Result<Paired, PairingError<T::Error>>
where
    T: Read + Write,
    R: CryptoRngCore,
{
    transport
        .start_tls(tls, &[])
        .await
        .map_err(PairingError::Transport)?;

    // The password is not the code. It is the code with this session's
    // exporter output appended, which is what stops the exchange being
    // replayed into another session.
    let mut exported = [0u8; EXPORTER_LEN];
    transport
        .export_keying_material(&mut exported, EXPORTER_LABEL, None)
        .map_err(PairingError::Transport)?;
    let mut password = Vec::with_capacity(code.len() + EXPORTER_LEN);
    password.extend_from_slice(code.as_bytes());
    password.extend_from_slice(&exported);

    // The host is Alice. Both sides write before they read.
    let spake2 = Spake2::new(Role::Alice, CLIENT_NAME, SERVER_NAME, &password, rng);
    send(transport, PacketType::Spake2Msg, spake2.message()).await?;
    let theirs = recv(transport, PacketType::Spake2Msg).await?;

    let key_material = spake2.finish(&theirs).map_err(PairingError::Spake2)?;
    let mut cipher = Cipher::new(&key_material).map_err(PairingError::Aead)?;

    let mine = peer_info::encode(PeerInfoType::RsaPublicKey, key.public_key_line())
        .map_err(PairingError::PeerInfo)?;
    let sealed = cipher.seal(&mine).map_err(PairingError::Aead)?;
    send(transport, PacketType::PeerInfo, &sealed).await?;

    let answer = recv(transport, PacketType::PeerInfo).await?;
    if answer.len() != peer_info::SIZE + TAG_LEN {
        // The device checks our block's size the same way.
        return Err(PairingError::PeerInfo(PeerInfoError::Size(
            answer.len().saturating_sub(TAG_LEN),
        )));
    }
    // The first and only place a wrong code shows itself.
    let opened = cipher.open(&answer).map_err(|_| PairingError::WrongCode)?;
    let (kind, guid) = peer_info::decode(&opened).map_err(PairingError::PeerInfo)?;
    if kind != PeerInfoType::DeviceGuid {
        return Err(PairingError::PeerInfo(PeerInfoError::Unexpected(kind)));
    }

    Ok(Paired { guid })
}

async fn send<T: Read + Write>(
    transport: &mut MaybeTls<T>,
    kind: PacketType,
    payload: &[u8],
) -> Result<(), PairingError<T::Error>> {
    let framed = frame::encode(kind, payload);
    transport
        .write_all(&framed)
        .await
        .map_err(PairingError::Transport)?;
    transport.flush().await.map_err(PairingError::Transport)
}

async fn recv<T: Read + Write>(
    transport: &mut MaybeTls<T>,
    expected: PacketType,
) -> Result<Vec<u8>, PairingError<T::Error>> {
    let mut header = [0u8; HEADER_LEN];
    transport.read_exact(&mut header).await?;
    let (kind, len) = frame::decode(&header).map_err(PairingError::Frame)?;
    if kind != expected {
        return Err(PairingError::Frame(FrameError::Kind(header[1])));
    }
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload).await?;
    Ok(payload)
}
