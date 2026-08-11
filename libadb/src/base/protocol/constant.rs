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
