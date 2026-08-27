/*
 * libadb — C API for the ADB wire-protocol library.
 *
 * All functions are synchronous and block the calling thread until the
 * underlying async operation completes. Handles are thread-safe: the
 * inner state is guarded by a mutex, so calls from multiple threads
 * serialise (full-duplex from two threads is NOT supported).
 *
 * On error, functions return a non-zero adb_status_t and set a
 * thread-local error string retrievable via adb_last_error().
 */

#ifndef LIBADB_H
#define LIBADB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct adb_connection adb_connection_t;
/* 64-bit: the implementation packs the protocol id and a table slot
 * into one value and writes all eight bytes through out-pointers. */
typedef uint64_t adb_channel_id_t;

/*
 * This list grows in minor releases: new statuses may be appended, and
 * existing values never change. Compare against the constants you
 * know and treat anything else as a generic failure — do not assume
 * the list is exhaustive. (ADB_FEATURE_* below grows under the same
 * contract.)
 */
typedef enum {
    ADB_OK                  = 0,
    ADB_ERR_INVALID_ARG     = 1,
    ADB_ERR_INVALID_URI     = 2,
    ADB_ERR_CONNECT         = 3,
    ADB_ERR_IO              = 4,
    ADB_ERR_AUTH            = 5,
    ADB_ERR_PROTOCOL        = 6,
    ADB_ERR_CHANNEL_CLOSED  = 7,
    ADB_ERR_NO_FREE_CHANNELS = 8,
    ADB_ERR_DESYNCHRONIZED  = 9,
    /* The device's reverse rule service refused the request; the
     * device's own message is in adb_last_error(). */
    ADB_ERR_REVERSE         = 10,
    ADB_ERR_INTERNAL        = 255
} adb_status_t;

/*
 * Connect and perform the CNXN/AUTH handshake.
 *
 *   uri            "tcp://HOST:PORT" or "usb://[VID:PID|serial/SERIAL]"
 *   priv_key_pem   PKCS#8 PEM RSA private key (contents of ~/.android/adbkey)
 *   pub_key        ADB-format public key blob (contents of ~/.android/adbkey.pub)
 *   banner         identity banner, e.g. "host::features=shell_v2,delayed_ack"
 *   out            receives a handle; release with adb_connection_free().
 */
adb_status_t adb_connect(
    const char        *uri,
    const char        *priv_key_pem,
    const char        *pub_key,
    const char        *banner,
    adb_connection_t **out);

/*
 * Caller-supplied signing callback for adb_connect_with_authenticator().
 *
 * The implementation must produce a PKCS#1 v1.5 signature of the SHA-1
 * prehash supplied in `token` (always 20 bytes), write up to
 * `out_capacity` bytes into `out_signature`, and store the actual
 * signature length through `*out_length`. Returning anything other
 * than ADB_OK aborts the handshake; the caller observes ADB_ERR_AUTH.
 *
 * `user_data` is forwarded verbatim from adb_authenticator_t and is
 * otherwise opaque to libadb.
 */
typedef adb_status_t (*adb_sign_fn)(
    void          *user_data,
    const uint8_t *token,
    size_t         token_len,
    uint8_t       *out_signature,
    size_t         out_capacity,
    size_t        *out_length);

/*
 * Caller-supplied authenticator. The public_key bytes are copied
 * internally on connect, so the buffer only needs to remain valid for
 * the duration of the call. The `sign` callback must remain valid for
 * the duration of the call.
 */
typedef struct {
    const uint8_t *public_key;
    size_t         public_key_len;
    adb_sign_fn    sign;
    void          *user_data;
} adb_authenticator_t;

/*
 * Like adb_connect(), but uses a caller-supplied authenticator instead
 * of the built-in RSA/PEM signer. Use this when the private key lives
 * outside the host process (HSM, remote signer, non-PKCS#8 store).
 */
adb_status_t adb_connect_with_authenticator(
    const char                *uri,
    const adb_authenticator_t *authenticator,
    const char                *banner,
    adb_connection_t         **out);

/* Release a handle returned by adb_connect(). NULL is a no-op. */
void adb_connection_free(adb_connection_t *conn);

/* Set receive/send timeouts on a tcp:// connection, in milliseconds;
 * 0 disables the corresponding timeout. USB transports have no such
 * knob and answer ADB_ERR_INVALID_ARG. A read that hits the timeout
 * fails with ADB_ERR_IO and the connection stays usable: bytes of a
 * partially received packet are kept, so the next read continues
 * where this one stopped. This recoverable-read guarantee holds on
 * Unix; on Windows a receive that expires under SO_RCVTIMEO leaves the
 * connection indeterminate (Winsock advises closing it), so there a
 * timed-out read means close, not read again. A write timeout is a
 * harder stop even on Unix: firing mid-packet abandons a write the
 * device has partially seen, so the connection is marked
 * desynchronized and every later channel operation fails with
 * ADB_ERR_DESYNCHRONIZED (metadata queries and this setter still
 * answer). Prefer the read timeout for a recoverable bound. */
adb_status_t adb_connection_set_io_timeout_ms(
    adb_connection_t *conn,
    uint32_t          read_ms,
    uint32_t          write_ms);

/* Negotiated max payload in bytes; 0 if conn is NULL. */
uint32_t adb_connection_max_payload(const adb_connection_t *conn);

/* Whether delayed-ACK flow control was negotiated. */
bool adb_connection_delayed_ack(const adb_connection_t *conn);

/*
 * Copy up to buf_len bytes of the device banner into buf and write the
 * full banner length through *out_len. Either pointer may be NULL.
 *
 * Like adb_connection_has_feature() and adb_connection_features(),
 * never takes the read lock: safe to call while another thread is
 * blocked in adb_read_channel().
 */
adb_status_t adb_connection_device_banner(
    const adb_connection_t *conn,
    uint8_t                *buf,
    size_t                  buf_len,
    size_t                 *out_len);

/*
 * Feature identifiers used with adb_connection_has_feature() and
 * adb_connection_features(). Values are stable across library versions;
 * new features are appended at the end.
 */
typedef uint32_t adb_feature_t;
#define ADB_FEATURE_ABB                            0
#define ADB_FEATURE_ABB_EXEC                       1
#define ADB_FEATURE_APEX                           2
#define ADB_FEATURE_APP_INFO                       3
#define ADB_FEATURE_CMD                            4
#define ADB_FEATURE_DELAYED_ACK                    5
#define ADB_FEATURE_DEVICETRACKER_PROTO_FORMAT     6
#define ADB_FEATURE_DEVRAW                         7
#define ADB_FEATURE_FIXED_PUSH_MKDIR               8
#define ADB_FEATURE_FIXED_PUSH_SYMLINK_TIMESTAMP   9
#define ADB_FEATURE_LS_V2                         10
#define ADB_FEATURE_OPENSCREEN_MDNS               11
#define ADB_FEATURE_REMOUNT_SHELL                 12
#define ADB_FEATURE_SENDRECV_V2                   13
#define ADB_FEATURE_SENDRECV_V2_BROTLI            14
#define ADB_FEATURE_SENDRECV_V2_DRY_RUN_SEND      15
#define ADB_FEATURE_SENDRECV_V2_LZ4               16
#define ADB_FEATURE_SENDRECV_V2_ZSTD              17
#define ADB_FEATURE_SHELL_V2                      18
#define ADB_FEATURE_STAT_V2                       19
#define ADB_FEATURE_TRACK_APP                     20

/*
 * Whether the device advertises `feature`. Returns false if `conn` is
 * NULL, the handshake did not yield a parseable banner, or `feature`
 * is not one of the ADB_FEATURE_* constants above.
 */
bool adb_connection_has_feature(
    const adb_connection_t *conn,
    adb_feature_t           feature);

/*
 * Wire-format name of `feature` (e.g. "shell_v2") as a static
 * null-terminated string, or NULL for unknown values.
 */
const char *adb_feature_name(adb_feature_t feature);

/*
 * Copy up to buf_cap features advertised by the device into buf (in
 * handshake order) and write the full count through *out_len. Either
 * pointer may be NULL.
 *
 * Unknown features the library does not recognise are skipped at parse
 * time, so the returned count covers only known ADB_FEATURE_* values.
 */
adb_status_t adb_connection_features(
    const adb_connection_t *conn,
    adb_feature_t          *buf,
    size_t                  buf_cap,
    size_t                 *out_len);

/*
 * Open a channel to `destination` (e.g. "shell:ls", "tcp:8080", "sync:").
 * `destination` need not be null-terminated; `destination_len` bytes are
 * sent verbatim. *out_id receives the channel ID on success.
 */
adb_status_t adb_open_channel(
    adb_connection_t *conn,
    const uint8_t    *destination,
    size_t            destination_len,
    adb_channel_id_t *out_id);

/*
 * Read from a channel. *out_read receives the number of bytes read.
 * Channel closure is reported as ADB_ERR_CHANNEL_CLOSED; ADB_OK with
 * *out_read == 0 never happens, which is what makes
 *
 *     while (adb_read_channel(...) == ADB_OK) { ... }
 *
 * a correct loop. buf_len == 0 is rejected with ADB_ERR_INVALID_ARG
 * rather than answering with a zero such a loop would spin on, and a
 * zero-length WRTE from the device is read past for the same reason.
 */
adb_status_t adb_read_channel(
    adb_connection_t *conn,
    adb_channel_id_t  id,
    uint8_t          *buf,
    size_t            buf_len,
    size_t           *out_read);

/* Write buf_len bytes; blocks until all bytes are framed and queued. */
adb_status_t adb_write_channel(
    adb_connection_t *conn,
    adb_channel_id_t  id,
    const uint8_t    *buf,
    size_t            buf_len);

/* Close a channel. Subsequent ops on this id return ADB_ERR_CHANNEL_CLOSED. */
adb_status_t adb_close_channel(
    adb_connection_t *conn,
    adb_channel_id_t  id);

/* ---- reverse forwards ---------------------------------------------- */

/*
 * Establish a reverse forward: the device listens on device_spec and
 * opens a channel toward the host per connection, with host_spec as the
 * destination. Receive those channels with adb_accept_channel().
 *
 * The service reply is written to (data, data_cap, out_data_len) with
 * the same truncate-and-report-full-length convention as
 * adb_connection_features(): for a "tcp:" device_spec it is the bound
 * port in decimal ("tcp:0" lets the device choose). Either data-side
 * pointer may be NULL.
 */
adb_status_t adb_reverse_forward(
    adb_connection_t *conn,
    const char       *device_spec,
    const char       *host_spec,
    uint8_t          *data,
    size_t            data_cap,
    size_t           *out_data_len);

/* Remove the reverse rule listening on device_spec. */
adb_status_t adb_reverse_remove(
    adb_connection_t *conn,
    const char       *device_spec);

/* Remove every reverse rule this connection established. */
adb_status_t adb_reverse_remove_all(adb_connection_t *conn);

/*
 * List the device's reverse rules as "<serial> <remote> <local>\n"
 * lines into (buf, buf_len, out_len), same convention as
 * adb_connection_features().
 */
adb_status_t adb_reverse_list(
    adb_connection_t *conn,
    uint8_t          *buf,
    size_t            buf_len,
    size_t           *out_len);

/*
 * Report the staged device-initiated channel (reverse traffic), waiting
 * for one to arrive if none is staged, and copy its destination into
 * (dest, dest_cap, out_dest_len), same convention as
 * adb_connection_features(). The request stays staged on the handle
 * until adb_incoming_accept() or adb_incoming_reject() consumes exactly
 * it — repeated calls report the same request again, so the
 * truncate-and-report convention works here: probe with (NULL, 0,
 * &len), allocate, call again for the bytes.
 *
 * With nothing staged this blocks until a channel arrives, as
 * adb_read_channel() blocks for data, and holds the read lock while
 * waiting. The staged request stays locked for the whole call, so
 * concurrent reports and verdicts serialize against it rather than
 * racing for the queue. There is no way to interrupt it yet; in
 * particular the handle must stay alive until the call returns —
 * adb_connection_free() from another thread while a call is blocked is
 * undefined behaviour, not an interruption mechanism.
 */
adb_status_t adb_accept_channel(
    adb_connection_t *conn,
    uint8_t          *dest,
    size_t            dest_cap,
    size_t           *out_dest_len);

/*
 * Accept the channel staged by adb_accept_channel(), returning its id
 * through out_id.
 */
adb_status_t adb_incoming_accept(
    adb_connection_t *conn,
    adb_channel_id_t *out_id);

/* Reject the channel staged by adb_accept_channel(). */
adb_status_t adb_incoming_reject(adb_connection_t *conn);

/*
 * Thread-local description of the last error, or NULL if none.
 * Valid until the next libadb call on this thread.
 */
const char *adb_last_error(void);

/* ---- shell_v2 ------------------------------------------------------ */

/*
 * Frame ids in the shell_v2 framing protocol; read_frame returns one
 * of these through *out_id.
 */
#define ADB_SHELL_V2_STDIN                0
#define ADB_SHELL_V2_STDOUT               1
#define ADB_SHELL_V2_STDERR               2
#define ADB_SHELL_V2_EXIT                 3
#define ADB_SHELL_V2_CLOSE_STDIN          4
#define ADB_SHELL_V2_WINDOW_SIZE_CHANGE   5

typedef struct adb_shell adb_shell_t;

/*
 * Open a shell_v2 session.
 *
 * `command` must be valid UTF-8 and need not be null-terminated; pass
 * an empty buffer (NULL, 0) for a login shell (only sensible with a pty).
 *
 * `pty` selects shell,v2,pty,... (true) or shell,v2,raw: (false).
 * `term` is the value for the device's TERM env var; may be NULL or
 *   empty to omit it; ignored when `pty` is false.
 * `rows`, `cols` — if `pty` and at least one is non-zero, an initial
 *   WINDOW_SIZE_CHANGE frame is sent right after the channel opens.
 *
 * `conn` must remain alive for as long as any shell handle opened
 * against it. Release the handle with adb_shell_free() (call
 * adb_shell_close() first to tear down the channel gracefully).
 */
adb_status_t adb_shell_open(
    adb_connection_t  *conn,
    const uint8_t     *command,
    size_t             command_len,
    bool               pty,
    const char        *term,
    uint16_t           rows,
    uint16_t           cols,
    adb_shell_t      **out_sh);

/* Release a handle from adb_shell_open(). NULL is a no-op. */
void adb_shell_free(adb_shell_t *sh);

/*
 * Read one decoded frame.
 *
 * *out_id receives the frame id (ADB_SHELL_V2_*). Up to `buf_cap` bytes
 * of payload are copied into `buf`; *out_len (may be NULL) receives
 * the full payload length — a value larger than `buf_cap` means the
 * excess was discarded.
 *
 * Frames whose payload exceeds the internal 64 KiB rx buffer are
 * delivered across multiple calls with the same id; concatenate the
 * chunks to reconstruct the payload.
 *
 * Channel closure is reported as ADB_ERR_CHANNEL_CLOSED.
 */
adb_status_t adb_shell_read_frame(
    adb_shell_t *sh,
    uint8_t     *out_id,
    uint8_t     *buf,
    size_t       buf_cap,
    size_t      *out_len);

/* Send a STDIN frame.
 *
 * Safe to call from several threads on one session: each frame is
 * written whole, never interleaved with another sender's. */
adb_status_t adb_shell_write_stdin(
    adb_shell_t   *sh,
    const uint8_t *data,
    size_t         len);

/* Signal that no more stdin will be sent. */
adb_status_t adb_shell_close_stdin(adb_shell_t *sh);

/* Notify the device PTY of a terminal resize. */
adb_status_t adb_shell_set_window_size(
    adb_shell_t *sh,
    uint16_t     rows,
    uint16_t     cols);

/* Close the underlying channel. Idempotent. */
adb_status_t adb_shell_close(adb_shell_t *sh);

#ifdef __cplusplus
}
#endif

#endif /* LIBADB_H */
