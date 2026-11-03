//! A slot's receive-side accounting around the READY that names the
//! device's end.

use core::convert::Infallible;

use super::*;

const LOCAL: u32 = 1;
const REMOTE: u32 = 42;

fn opening(ack: AckMode) -> ChannelSlot {
    let policy = RxPolicy {
        ack,
        rx_cap: 1024,
        watermark: 512,
    };
    ChannelSlot::opening(LocalId::from(LOCAL), policy)
}

/// The device's answer to our OPEN, with the credit delayed ACK needs.
fn accept(slot: &mut ChannelSlot) {
    let credit = 4096u32.to_le_bytes();
    slot.accept_open_ready(RemoteId::from(REMOTE), &credit)
        .unwrap();
}

/// Data the device wrote ahead of its READY cannot be read until the
/// READY names the end its OKAY goes to; the first read after it takes
/// the data and acknowledges all of it, leaving nothing owed.
#[test]
fn a_write_before_the_ready_is_read_and_acknowledged_only_after_it() {
    for ack in [AckMode::Delayed, AckMode::Classic] {
        let mut slot = opening(ack);
        assert!(matches!(slot.apply_write(b"early"), Ok(AckDecision::Hold)));

        let mut buf = [0u8; 8];
        assert!(!slot.take_acks(buf.len()), "{ack:?}");
        assert!(
            matches!(slot.take_buffered::<Infallible>(&mut buf), Ok(None)),
            "{ack:?}: read before the READY"
        );
        assert_eq!((slot.buffered(), slot.unacked()), (5, 5), "{ack:?}");

        accept(&mut slot);
        assert!(slot.take_acks(buf.len()), "{ack:?}");
        let (n, owed) = slot.take_buffered::<Infallible>(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"early", "{ack:?}");
        let ids = ChannelIds {
            local: LocalId::from(LOCAL),
            remote: RemoteId::from(REMOTE),
        };
        assert_eq!(owed, Some(PendingAck { ids, len: 5 }), "{ack:?}");
        assert_eq!((slot.buffered(), slot.unacked()), (0, 0), "{ack:?}");
    }
}

/// An OPEN the device refused after writing on it never opened: the
/// read fails rather than hand out data nobody can acknowledge.
#[test]
fn a_write_before_a_refusal_is_never_handed_out() {
    let mut slot = opening(AckMode::Delayed);
    slot.apply_write(b"early").unwrap();
    slot.apply_close();

    let mut buf = [0u8; 8];
    assert!(matches!(
        slot.take_buffered::<Infallible>(&mut buf),
        Err(Error::ChannelClosed)
    ));
}
