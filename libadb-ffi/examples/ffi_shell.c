/*
 * C example for libadb's FFI layer.
 *
 * Build:
 *   cargo build --features ffi
 *   cc -I include -o ffi_shell examples/ffi_shell.c \
 *      -L target/debug -llibadb -lpthread -ldl -lm
 *
 * Usage:
 *   # Interactive shell (pty, raw terminal, SIGWINCH-aware):
 *   LD_LIBRARY_PATH=target/debug ./ffi_shell tcp://127.0.0.1:5555
 *
 *   # Run a single command:
 *   LD_LIBRARY_PATH=target/debug ./ffi_shell tcp://127.0.0.1:5555 "ls /sdcard"
 *
 * Requires ~/.android/adbkey and ~/.android/adbkey.pub as produced by
 * the standard `adb` tool.
 */

#include "libadb.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

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

static void get_winsize(uint16_t *rows, uint16_t *cols) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    } else {
        *rows = 24;
        *cols = 80;
    }
}

/* ------------------------------------------------------------------ */
/* Single-command mode                                                */
/* ------------------------------------------------------------------ */

static int run_command(adb_connection_t *conn, const char *command) {
    adb_shell_t *sh = NULL;
    adb_status_t st = adb_shell_open(
        conn,
        (const uint8_t *)command, strlen(command),
        /*pty=*/false, /*term=*/NULL, /*rows=*/0, /*cols=*/0,
        &sh);
    if (st != ADB_OK) die(st, "adb_shell_open");

    st = adb_shell_close_stdin(sh);
    if (st != ADB_OK) die(st, "adb_shell_close_stdin");

    uint8_t exit_code = 0;
    unsigned char buf[16 * 1024];
    for (;;) {
        uint8_t id = 0;
        size_t len = 0;
        st = adb_shell_read_frame(sh, &id, buf, sizeof(buf), &len);
        if (st == ADB_ERR_CHANNEL_CLOSED) break;
        if (st != ADB_OK) die(st, "adb_shell_read_frame");

        size_t copied = len > sizeof(buf) ? sizeof(buf) : len;
        switch (id) {
            case ADB_SHELL_V2_STDOUT: fwrite(buf, 1, copied, stdout); fflush(stdout); break;
            case ADB_SHELL_V2_STDERR: fwrite(buf, 1, copied, stderr); fflush(stderr); break;
            case ADB_SHELL_V2_EXIT:
                exit_code = (copied > 0) ? buf[0] : 0;
                goto done;
            default: break;
        }
    }

done:
    (void)adb_shell_close(sh);
    adb_shell_free(sh);
    fprintf(stderr, "[*] exit code: %u\n", (unsigned)exit_code);
    return (int)exit_code;
}

/* ------------------------------------------------------------------ */
/* Interactive mode                                                   */
/* ------------------------------------------------------------------ */

static struct termios g_orig_termios;
static int g_termios_saved = 0;
static int g_sigwinch_write = -1;

static void restore_termios(void) {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
        g_termios_saved = 0;
    }
}

static void sigwinch_handler(int sig) {
    (void)sig;
    if (g_sigwinch_write >= 0) {
        unsigned char b = 1;
        /* write() is async-signal-safe; ignore short/failed writes. */
        ssize_t n = write(g_sigwinch_write, &b, 1);
        (void)n;
    }
}

struct reader_args {
    adb_shell_t *sh;
    int          done_write;
    uint8_t      exit_code;
    int          saw_exit;
};

static void *reader_loop(void *arg) {
    struct reader_args *a = arg;
    unsigned char buf[16 * 1024];
    for (;;) {
        uint8_t id = 0;
        size_t len = 0;
        adb_status_t st = adb_shell_read_frame(a->sh, &id, buf, sizeof(buf), &len);
        if (st == ADB_ERR_CHANNEL_CLOSED) break;
        if (st != ADB_OK) {
            const char *m = adb_last_error();
            fprintf(stderr, "\r\n[!] read_frame: status=%d (%s)\r\n",
                    (int)st, m ? m : "");
            break;
        }
        size_t copied = len > sizeof(buf) ? sizeof(buf) : len;
        switch (id) {
            case ADB_SHELL_V2_STDOUT: fwrite(buf, 1, copied, stdout); fflush(stdout); break;
            case ADB_SHELL_V2_STDERR: fwrite(buf, 1, copied, stderr); fflush(stderr); break;
            case ADB_SHELL_V2_EXIT:
                a->exit_code = (copied > 0) ? buf[0] : 0;
                a->saw_exit = 1;
                goto done;
            default: break;
        }
    }
done:
    {
        unsigned char b = 1;
        ssize_t n = write(a->done_write, &b, 1);
        (void)n;
    }
    return NULL;
}

static int run_interactive(adb_connection_t *conn) {
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr,
                "[!] stdin is not a tty — interactive mode requires a terminal.\n"
                "    Pass a command as the second argument instead.\n");
        return 2;
    }

    const char *term = getenv("TERM");
    if (!term || !*term) term = "xterm-256color";

    uint16_t rows = 0, cols = 0;
    get_winsize(&rows, &cols);

    adb_shell_t *sh = NULL;
    adb_status_t st = adb_shell_open(
        conn,
        /*command=*/NULL, 0,
        /*pty=*/true,
        term,
        rows, cols,
        &sh);
    if (st != ADB_OK) die(st, "adb_shell_open");

    /* Self-pipes: SIGWINCH handler → main; reader thread → main. */
    int winch_pipe[2];
    int done_pipe[2];
    if (pipe(winch_pipe) < 0 || pipe(done_pipe) < 0) {
        perror("pipe");
        adb_shell_close(sh);
        adb_shell_free(sh);
        return 1;
    }
    fcntl(winch_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(winch_pipe[1], F_SETFL, O_NONBLOCK);
    g_sigwinch_write = winch_pipe[1];

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigwinch_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* let poll() return EINTR so we can re-enter quickly */
    sigaction(SIGWINCH, &sa, NULL);

    /* Enter raw mode; restore on exit. */
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
        g_termios_saved = 1;
        atexit(restore_termios);
        struct termios raw = g_orig_termios;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }

    /* Reader thread prints stdout/stderr and signals done on EXIT. */
    struct reader_args ra = { sh, done_pipe[1], 0, 0 };
    pthread_t reader;
    if (pthread_create(&reader, NULL, reader_loop, &ra) != 0) {
        perror("pthread_create");
        restore_termios();
        adb_shell_close(sh);
        adb_shell_free(sh);
        return 1;
    }

    /* Main loop: forward stdin, handle resize, watch for reader-done. */
    struct pollfd pfds[3];
    pfds[0].fd = STDIN_FILENO;    pfds[0].events = POLLIN;
    pfds[1].fd = winch_pipe[0];   pfds[1].events = POLLIN;
    pfds[2].fd = done_pipe[0];    pfds[2].events = POLLIN;

    for (;;) {
        int r = poll(pfds, 3, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (pfds[2].revents & POLLIN) {
            break; /* reader saw EXIT or channel close */
        }

        if (pfds[1].revents & POLLIN) {
            unsigned char drain[64];
            while (read(winch_pipe[0], drain, sizeof(drain)) > 0) {}
            uint16_t r2, c2;
            get_winsize(&r2, &c2);
            (void)adb_shell_set_window_size(sh, r2, c2);
        }

        if (pfds[0].revents & POLLIN) {
            unsigned char input[4096];
            ssize_t n = read(STDIN_FILENO, input, sizeof(input));
            if (n > 0) {
                adb_status_t ws = adb_shell_write_stdin(sh, input, (size_t)n);
                if (ws == ADB_ERR_CHANNEL_CLOSED) break;
                if (ws != ADB_OK) {
                    const char *m = adb_last_error();
                    fprintf(stderr, "\r\n[!] write_stdin: status=%d (%s)\r\n",
                            (int)ws, m ? m : "");
                    break;
                }
            } else if (n == 0) {
                (void)adb_shell_close_stdin(sh);
                pfds[0].fd = -1; /* stop polling stdin */
            } else if (errno != EAGAIN && errno != EINTR) {
                break;
            }
        } else if (pfds[0].revents & (POLLHUP | POLLERR)) {
            (void)adb_shell_close_stdin(sh);
            pfds[0].fd = -1;
        }
    }

    pthread_join(reader, NULL);
    restore_termios();

    close(winch_pipe[0]); close(winch_pipe[1]);
    close(done_pipe[0]);  close(done_pipe[1]);

    (void)adb_shell_close(sh);
    adb_shell_free(sh);

    fprintf(stderr, "[*] exit code: %u%s\n",
            (unsigned)ra.exit_code,
            ra.saw_exit ? "" : " (channel closed without EXIT)");
    return (int)ra.exit_code;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <uri> [command]\n", argv[0]);
        fprintf(stderr, "  interactive:  %s tcp://127.0.0.1:5555\n", argv[0]);
        fprintf(stderr, "  command:      %s tcp://127.0.0.1:5555 \"ls /sdcard\"\n", argv[0]);
        return 2;
    }

    const char *uri = argv[1];
    const char *command = (argc == 3) ? argv[2] : NULL;

    char *priv_path = join_home("/.android/adbkey");
    char *pub_path  = join_home("/.android/adbkey.pub");
    char *priv_pem  = read_file(priv_path);
    char *pub_key   = read_file(pub_path);
    if (!priv_pem || !pub_key) {
        fprintf(stderr, "failed to read adb keys from ~/.android\n");
        return 1;
    }
    free(priv_path);
    free(pub_path);

    adb_connection_t *conn = NULL;
    adb_status_t st = adb_connect(
        uri, priv_pem, pub_key,
        "host::features=shell_v2,delayed_ack",
        &conn);
    if (st != ADB_OK) die(st, "adb_connect");
    free(priv_pem);
    free(pub_key);

    fprintf(stderr, "[*] connected; max_payload=%u delayed_ack=%s\n",
            adb_connection_max_payload(conn),
            adb_connection_delayed_ack(conn) ? "true" : "false");

    size_t banner_len = 0;
    (void)adb_connection_device_banner(conn, NULL, 0, &banner_len);
    if (banner_len > 0) {
        unsigned char *banner = malloc(banner_len);
        if (banner) {
            adb_connection_device_banner(conn, banner, banner_len, NULL);
            fprintf(stderr, "[*] banner: %.*s\n", (int)banner_len, (char *)banner);
            free(banner);
        }
    }

    int rc;
    if (command) {
        rc = run_command(conn, command);
    } else {
        rc = run_interactive(conn);
    }

    adb_connection_free(conn);
    return rc;
}
