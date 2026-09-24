/*
 * C example for libadb's FFI layer: `adb pair`.
 *
 * Build:
 *   cargo build -p libadb-ffi --features pairing
 *   cc -I libadb-ffi/include -o ffi_pair libadb-ffi/examples/ffi_pair.c \
 *      -L target/debug -ladb -lpthread -ldl -lm
 *
 * Usage:
 *   LD_LIBRARY_PATH=target/debug ./ffi_pair tcp://192.168.1.5:37421 592781
 *
 * Turn on "Wireless debugging" on the device, then "Pair device with
 * pairing code": the address and the six digits are both on that
 * screen. Neither survives — the port changes every time, and the
 * pairing server stops as soon as one host gets through.
 *
 * Reuses ~/.android/adbkey, or generates one there on the first run.
 * Afterwards ffi_shell connects on the device's *connect* port, a
 * different number on the same screen, with the same key, over TLS.
 */

#include "libadb.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *join_home(const char *suffix) {
    const char *home = getenv("HOME");
    if (!home) return NULL;
    size_t n = strlen(home) + strlen(suffix) + 1;
    char *p = malloc(n);
    if (!p) return NULL;
    snprintf(p, n, "%s%s", home, suffix);
    return p;
}

static void die(adb_status_t st, const char *ctx) {
    const char *msg = adb_last_error();
    fprintf(stderr, "%s: status=%d (%s)\n", ctx, (int)st, msg ? msg : "<no message>");
    exit(1);
}

/* Here and not in the library, which also pairs with the password from
 * a QR code. A typo caught now never reaches the device, which would
 * count it against its twenty attempts. */
static int is_six_digits(const char *code) {
    if (strlen(code) != 6) return 0;
    for (const char *p = code; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s tcp://HOST:PORT CODE\n", argv[0]);
        fprintf(stderr, "  both are on the device's \"Pair device with pairing code\" screen\n");
        return 2;
    }
    const char *uri = argv[1];
    const char *code = argv[2];
    if (!is_six_digits(code)) {
        fprintf(stderr, "the pairing code is six digits\n");
        return 2;
    }

    char *key_dir = join_home("/.android");
    if (!key_dir) {
        fprintf(stderr, "HOME is not set; cannot locate ~/.android\n");
        return 1;
    }
    adb_key_t *key = NULL;
    adb_status_t st = adb_key_load_or_generate(key_dir, NULL, &key);
    if (st != ADB_OK) die(st, "adb_key_load_or_generate");
    free(key_dir);

    fprintf(stderr, "[*] pairing with %s ...\n", uri);
    uint8_t guid[256];
    size_t guid_len = 0;
    st = adb_pair(uri, adb_key_private_key_pem(key), adb_key_public_key(key), code,
                  guid, sizeof guid, &guid_len);
    adb_key_free(key);
    if (st != ADB_OK) die(st, "adb_pair");

    /* The device chose these bytes; escaped, they cannot drive the
     * terminal. */
    if (guid_len > sizeof guid) guid_len = sizeof guid;
    fprintf(stderr, "[*] paired. device guid: ");
    for (size_t i = 0; i < guid_len; i++) {
        fputc(isprint(guid[i]) ? guid[i] : '?', stderr);
    }
    fputc('\n', stderr);
    fprintf(stderr, "[*] it now accepts this key on its wireless-debugging port\n");
    return 0;
}
