use super::SendQueue;

#[test]
fn cancellation_churn_behind_a_blocked_head_does_not_accumulate() {
    let mut queue = SendQueue::default();
    let _head = queue.enqueue();

    for _ in 0..1_000 {
        let mid = queue.enqueue();
        let tail = queue.enqueue();
        // Dropped mid-queue: a hole, while `tail` still lives...
        assert!(!queue.leave(mid));
        // ...and the leaving tail reclaims itself and the hole.
        assert!(!queue.leave(tail));
    }

    assert!(queue.gone.is_empty());
    assert_eq!(queue.tail, 1);
    assert_eq!(queue.head, 0);
}

/// A place left mid-queue stays a hole until the head passes it,
/// and a hole is no writer waiting.
#[test]
fn the_queue_is_empty_once_every_place_was_served_or_left() {
    let mut queue = SendQueue::default();
    assert!(queue.is_empty());

    queue.enqueue();
    let mid = queue.enqueue();
    let tail = queue.enqueue();
    assert!(!queue.is_empty());

    assert!(!queue.leave(mid));
    assert!(!queue.is_empty(), "the head and the tail still wait");

    queue.serve();
    assert_eq!(queue.turn(), tail, "the head went past the hole");
    assert!(!queue.is_empty(), "the tail still waits");

    queue.serve();
    assert!(queue.is_empty(), "both served, the middle one gone");
}

#[test]
fn a_served_writer_stays_sending_until_it_finishes() {
    let mut queue = SendQueue::default();
    queue.enqueue();
    queue.enqueue();
    assert!(!queue.is_sending());

    queue.serve();
    queue.serve();
    assert!(queue.is_empty(), "a served writer holds no place");
    assert!(queue.is_sending());

    queue.finish();
    assert!(queue.is_sending(), "the second one still sends");
    queue.finish();
    assert!(!queue.is_sending());
}

#[test]
fn leaving_the_queue_unserved_starts_no_send() {
    let mut queue = SendQueue::default();
    let place = queue.enqueue();
    queue.enqueue();
    assert!(queue.leave(place), "the head moved");
    assert!(!queue.is_sending());
}
