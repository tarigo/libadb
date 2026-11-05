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
        let owed = slot.settle_take(buf.len());
        let n = slot.take_buffered::<Infallible>(&mut buf).unwrap().unwrap();
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

/// Settling hands the OKAY over and leaves the bytes where they are, so
/// a read dropped while that OKAY is written has taken nothing.
#[test]
fn settling_a_take_leaves_the_bytes_in_the_buffer() {
    let mut slot = opening(AckMode::Delayed);
    accept(&mut slot);
    slot.apply_write(b"early").unwrap();

    let ack = slot.settle_take(3).expect("three bytes owe an OKAY");
    assert_eq!(ack.len, 3);
    assert_eq!((slot.buffered(), slot.unacked()), (5, 2));

    let mut buf = [0u8; 3];
    assert_eq!(slot.take_buffered::<Infallible>(&mut buf).unwrap(), Some(3));
    assert_eq!((slot.buffered(), slot.unacked()), (2, 2));
}

/// The OKAY for bytes a read is about to take lets the device send as
/// much again, which can land before they have left. That is no
/// overflow: taken first, they would have made the room themselves.
#[test]
fn a_settled_take_makes_room_for_what_its_okay_lets_in() {
    let mut slot = opening(AckMode::Delayed);
    accept(&mut slot);
    slot.apply_write(&[1; 1024]).unwrap();
    assert!(slot.apply_write(&[2]).is_err(), "at the cap");

    slot.settle_take(100).unwrap();
    slot.apply_write(&[2; 100]).unwrap();
    assert!(slot.apply_write(&[3]).is_err(), "no more than it let in");
}

/// The same for the watermark without delayed ACK: the buffer is down
/// to what stays, so the next packet is acknowledged as it lands.
#[test]
fn a_settled_take_is_gone_as_far_as_the_watermark_goes() {
    let mut slot = opening(AckMode::Classic);
    accept(&mut slot);
    slot.apply_write(&[1; 600]).unwrap();
    assert_eq!(slot.unacked(), 600, "past the watermark, so held back");

    slot.settle_take(600).unwrap();
    assert!(matches!(
        slot.apply_write(&[2; 10]),
        Ok(AckDecision::Now(_))
    ));
}

/// What landed behind the bytes settled has an OKAY of its own to come:
/// taken along with them, it would leave the count with none sent.
#[test]
fn a_take_stops_at_what_was_settled() {
    let mut slot = opening(AckMode::Delayed);
    accept(&mut slot);
    slot.apply_write(b"hello").unwrap();
    slot.settle_take(16).unwrap();
    slot.apply_write(b" world").unwrap();

    let mut buf = [0u8; 16];
    assert_eq!(slot.take_buffered::<Infallible>(&mut buf).unwrap(), Some(5));
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(slot.unacked(), 6);

    assert_eq!(slot.settle_take(16).unwrap().len, 6);
    assert_eq!(slot.take_buffered::<Infallible>(&mut buf).unwrap(), Some(6));
    assert_eq!(&buf[..6], b" world");
    assert_eq!((slot.buffered(), slot.unacked()), (0, 0));
}

/// Two reads of one channel: the second finds bytes whose OKAY the first
/// is writing. They owe nothing more, and go to whichever read gets
/// there first, in order, and only they do.
#[test]
fn settled_bytes_owe_a_second_read_nothing() {
    let mut slot = opening(AckMode::Delayed);
    accept(&mut slot);
    slot.apply_write(b"hello").unwrap();
    slot.settle_take(16).unwrap();
    slot.apply_write(b" world").unwrap();

    let mut buf = [0u8; 16];
    assert!(!slot.take_acks(buf.len()));
    assert_eq!(slot.settle_take(buf.len()), None);
    assert_eq!(slot.take_buffered::<Infallible>(&mut buf).unwrap(), Some(5));
    assert_eq!(&buf[..5], b"hello");

    assert!(slot.take_acks(buf.len()), "what is left owes its own");
}

/// adbd has dropped the socket by the time its CLSE arrives, so what it
/// sent before that is read for nothing but the bytes.
#[test]
fn a_channel_the_device_closed_owes_no_okay() {
    for ack in [AckMode::Delayed, AckMode::Classic] {
        let mut slot = opening(ack);
        accept(&mut slot);
        // Past the watermark, so the OKAY waits under either mode.
        slot.apply_write(&[7; 600]).unwrap();
        assert_eq!(slot.unacked(), 600, "{ack:?}: held back for the read");
        slot.apply_close();

        let mut buf = [0u8; 700];
        assert!(!slot.take_acks(buf.len()), "{ack:?}");
        assert_eq!(slot.settle_take(buf.len()), None, "{ack:?}");
        let n = slot.take_buffered::<Infallible>(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], [7; 600], "{ack:?}");
        assert!(matches!(
            slot.take_buffered::<Infallible>(&mut buf),
            Err(Error::ChannelClosed)
        ));
    }
}
