//! ADB protocol command constants.
//! Each command is the ASCII bytes of its name interpreted as a little-endian u32.
use super::super::error::ProtocolError;

/// Synchronization command (`"SYNC"` as little-endian `u32`).
///
/// Unused in modern ADB, reserved for backwards compatibility.
pub const CMD_SYNC: u32 = u32::from_le_bytes(*b"SYNC");

/// Connection request/response (`"CNXN"` as little-endian `u32`).
///
/// Sent by both sides during the initial handshake to negotiate
/// protocol version, max payload size, and system identity.
pub const CMD_CNXN: u32 = u32::from_le_bytes(*b"CNXN");

/// Authentication step (`"AUTH"` as little-endian `u32`).
///
/// Exchanged during RSA-based device authentication before a
/// connection is allowed.
pub const CMD_AUTH: u32 = u32::from_le_bytes(*b"AUTH");

/// Open a new channel (`"OPEN"` as little-endian `u32`).
///
/// Requests the remote side to open a stream for a given
/// destination (e.g. `shell:`, `sync:`, `tcp:5555`).
pub const CMD_OPEN: u32 = u32::from_le_bytes(*b"OPEN");

/// Acknowledge / ready for more data (`"OKAY"` as little-endian `u32`).
///
/// Confirms that a stream was opened or that the peer is ready
/// to receive the next `WRTE` payload.
pub const CMD_OKAY: u32 = u32::from_le_bytes(*b"OKAY");

/// Close a channel (`"CLSE"` as little-endian `u32`).
///
/// Tears down an existing stream. Either side may send it.
pub const CMD_CLSE: u32 = u32::from_le_bytes(*b"CLSE");

/// Write data to a channel (`"WRTE"` as little-endian `u32`).
///
/// Carries a payload for an open stream. Each `WRTE` must be
/// acknowledged by the peer with an `OKAY` before the next one
/// is sent.
pub const CMD_WRTE: u32 = u32::from_le_bytes(*b"WRTE");

/// TLS upgrade request (`"STLS"` as little-endian `u32`).
///
/// Introduced in Android 9 (ADB protocol v2). Signals that the
/// transport should be wrapped in TLS before further traffic.
pub const CMD_STLS: u32 = u32::from_le_bytes(*b"STLS");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Command {
    Sync = CMD_SYNC,
    Connect = CMD_CNXN,
    Open = CMD_OPEN,
    Ready = CMD_OKAY,
    Close = CMD_CLSE,
    Write = CMD_WRTE,
    Auth = CMD_AUTH,
}

impl Command {
    pub fn magic(self) -> u32 {
        (self as u32) ^ 0xFFFFFFFF
    }
}

impl TryFrom<u32> for Command {
    type Error = ProtocolError;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            CMD_SYNC => Ok(Self::Sync),
            CMD_CNXN => Ok(Self::Connect),
            CMD_OPEN => Ok(Self::Open),
            CMD_OKAY => Ok(Self::Ready),
            CMD_CLSE => Ok(Self::Close),
            CMD_WRTE => Ok(Self::Write),
            CMD_AUTH => Ok(Self::Auth),
            _ => Err(ProtocolError::InvalidCommand(v)),
        }
    }
}

impl From<Command> for u32 {
    fn from(cmd: Command) -> u32 {
        cmd as u32
    }
}

/// Device sends a random token to be signed.
pub const AUTH_TOKEN: u32 = 1;
/// Host responds with RSA signature of the token.
pub const AUTH_SIGNATURE: u32 = 2;
/// Host sends its RSA public key for on-device authorization prompt.
pub const AUTH_RSAPUBLICKEY: u32 = 3;

/// ADB protocol version with feature negotiation.
pub const ADB_VERSION: u32 = 0x0100_0001;

/// Default maximum payload size (bytes).
pub const MAX_PAYLOAD: u32 = 1024 * 1024;

/// Compute the magic value for a command.
#[inline]
pub const fn magic(command: u32) -> u32 {
    command ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::super::error::ProtocolError;
    use super::{
        magic, Command, CMD_AUTH, CMD_CLSE, CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_SYNC, CMD_WRTE,
    };

    const ALL_VARIANTS: [(Command, u32); 7] = [
        (Command::Sync, CMD_SYNC),
        (Command::Connect, CMD_CNXN),
        (Command::Open, CMD_OPEN),
        (Command::Ready, CMD_OKAY),
        (Command::Close, CMD_CLSE),
        (Command::Write, CMD_WRTE),
        (Command::Auth, CMD_AUTH),
    ];

    #[test]
    fn magic_xors_command_with_all_ones() {
        for (command, raw) in ALL_VARIANTS {
            assert_eq!(command.magic(), raw ^ 0xFFFF_FFFF);
        }
    }

    #[test]
    fn free_magic_matches_enum_magic() {
        for (command, raw) in ALL_VARIANTS {
            assert_eq!(magic(raw), command.magic());
        }
    }

    #[test]
    fn try_from_accepts_every_known_command() {
        for (command, raw) in ALL_VARIANTS {
            assert_eq!(Command::try_from(raw), Ok(command));
        }
    }

    #[test]
    fn try_from_rejects_unknown_command_with_the_raw_value() {
        let unknown: u32 = 0xDEAD_BEEF;
        assert_eq!(
            Command::try_from(unknown),
            Err(ProtocolError::InvalidCommand(unknown))
        );
    }

    #[test]
    fn command_roundtrips_through_u32() {
        for (command, raw) in ALL_VARIANTS {
            let as_u32: u32 = command.into();
            assert_eq!(as_u32, raw);
            assert_eq!(Command::try_from(as_u32), Ok(command));
        }
    }

    #[test]
    fn raw_constants_match_ascii_little_endian_names() {
        assert_eq!(CMD_SYNC, u32::from_le_bytes(*b"SYNC"));
        assert_eq!(CMD_CNXN, u32::from_le_bytes(*b"CNXN"));
        assert_eq!(CMD_OPEN, u32::from_le_bytes(*b"OPEN"));
        assert_eq!(CMD_OKAY, u32::from_le_bytes(*b"OKAY"));
        assert_eq!(CMD_CLSE, u32::from_le_bytes(*b"CLSE"));
        assert_eq!(CMD_WRTE, u32::from_le_bytes(*b"WRTE"));
        assert_eq!(CMD_AUTH, u32::from_le_bytes(*b"AUTH"));
    }
}
