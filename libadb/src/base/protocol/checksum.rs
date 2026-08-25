use super::constant::ADB_VERSION_SKIP_CHECKSUM;

pub trait Checksumable {
    type Checksum;

    fn calculate_checksum(&self) -> Self::Checksum;
}

pub(crate) fn payload_checksum(payload: &[u8]) -> u32 {
    let mut sum = 0u32;
    for &b in payload {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

/// Whether an outgoing packet carries a payload checksum.
///
/// Protocol version `0x0100_0001` retired the field: peers at or above
/// it write `data_check = 0` and never validate what they receive, so
/// computing the sum is a wasted pass over every payload.
///
/// The receive path is unaffected: a non-zero `data_check` is still
/// verified, so a legacy peer keeps working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    /// The peer predates `0x0100_0001`, or its version is not known yet.
    Compute,
    Skip,
}

impl Checksum {
    pub const fn for_version(version: u32) -> Self {
        if version >= ADB_VERSION_SKIP_CHECKSUM {
            Self::Skip
        } else {
            Self::Compute
        }
    }

    pub fn of(self, payload: &[u8]) -> u32 {
        match self {
            Self::Skip => 0,
            Self::Compute => payload_checksum(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::protocol::constant::ADB_VERSION;

    #[test]
    fn sum_is_the_byte_total() {
        assert_eq!(payload_checksum(b""), 0);
        assert_eq!(payload_checksum(&[1, 2, 3]), 6);
        assert_eq!(payload_checksum(&[0xFF; 4]), 4 * 255);
    }

    #[test]
    fn sum_wraps_instead_of_overflowing() {
        let payload = [0xFFu8; 0x0100_0000 / 0xFF + 1];
        // Just has to not panic in debug builds.
        let _ = payload_checksum(&payload);
    }

    #[test]
    fn modern_versions_skip() {
        assert_eq!(Checksum::for_version(ADB_VERSION), Checksum::Skip);
        assert_eq!(
            Checksum::for_version(ADB_VERSION_SKIP_CHECKSUM),
            Checksum::Skip
        );
        assert_eq!(Checksum::for_version(0x0100_0009), Checksum::Skip);
    }

    #[test]
    fn legacy_versions_compute() {
        assert_eq!(Checksum::for_version(0x0100_0000), Checksum::Compute);
        assert_eq!(Checksum::for_version(0), Checksum::Compute);
    }

    #[test]
    fn of_honours_the_policy() {
        assert_eq!(Checksum::Skip.of(b"abc"), 0);
        assert_eq!(Checksum::Compute.of(b"abc"), 294);
    }
}
