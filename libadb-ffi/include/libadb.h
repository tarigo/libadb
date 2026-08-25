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
typedef uint32_t adb_channel_id_t;

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
