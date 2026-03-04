/*
 * c_stub.c — MoonBit ↔ libssh2 C translation layer
 *
 * All libssh2 public functions that are implemented as macros must be
 * wrapped here as real C functions so that MoonBit `extern "C"` bindings
 * can resolve a concrete symbol at link time.
 *
 * Pointer types are exchanged as int64_t so the MoonBit side always uses
 * Int64, which maps directly to int64_t on both 32-bit and 64-bit targets.
 *
 * Security notes:
 *  - Passwords and passphrases are zeroed with SecureZeroMemory (Win32) or
 *    explicit_bzero (POSIX) immediately after use so they do not linger in
 *    stack / heap memory.
 *  - Buffer lengths are always validated before copying to prevent overrun.
 *  - No static or global buffers hold secret material.
 */

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>   /* SecureZeroMemory */
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <string.h>    /* explicit_bzero / memset */
#endif

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Portable secure-zeroise helper
 * ---------------------------------------------------------------------- */
static void secure_zero(void *ptr, size_t len) {
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__OpenBSD__) || defined(__linux__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

/* -------------------------------------------------------------------------
 * Global init / exit
 * ---------------------------------------------------------------------- */

/* Returns 0 on success */
int32_t stub_libssh2_init(int32_t flags) {
    return libssh2_init(flags);
}

void stub_libssh2_exit(void) {
    libssh2_exit();
}

/* Returns a static C string — caller must NOT free it */
int64_t stub_libssh2_version(void) {
    return (int64_t)(uintptr_t)libssh2_version(0);
}

/* -------------------------------------------------------------------------
 * Session lifecycle
 * ---------------------------------------------------------------------- */

/* Returns LIBSSH2_SESSION* cast to int64_t; 0 on failure */
int64_t stub_session_init(void) {
    return (int64_t)(uintptr_t)libssh2_session_init();
}

void stub_session_set_blocking(int64_t session, int32_t blocking) {
    libssh2_session_set_blocking((LIBSSH2_SESSION *)(uintptr_t)session, blocking);
}

/* sock_fd: on Windows pass the SOCKET value (uintptr_t) as int64_t */
int32_t stub_session_handshake(int64_t session, int64_t sock_fd) {
    return libssh2_session_handshake(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        (libssh2_socket_t)(uintptr_t)sock_fd);
}

/* reason: SSH_DISCONNECT_BY_APPLICATION = 11 */
int32_t stub_session_disconnect(int64_t session, const char *description) {
    return libssh2_session_disconnect_ex(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        SSH_DISCONNECT_BY_APPLICATION,
        description ? description : "Normal Shutdown",
        "");
}

int32_t stub_session_free(int64_t session) {
    return libssh2_session_free((LIBSSH2_SESSION *)(uintptr_t)session);
}

/*
 * Returns the last error message for the session.
 * The returned pointer is valid until the next call on the session.
 * caller_buf/caller_buf_len: optional caller-supplied buffer (may be NULL/0).
 * If NULL, libssh2 returns a pointer to its internal buffer (valid until 
 * next call).  We copy into caller_buf when provided.
 *
 * Returns the error code; the message is placed in *out_msg.
 */
int32_t stub_session_last_error(int64_t session, char *out_buf, int32_t out_buf_len) {
    char   *msg     = NULL;
    int     msg_len = 0;
    int32_t rc = libssh2_session_last_error(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        &msg, &msg_len, 0);
    if (out_buf && out_buf_len > 0 && msg) {
        int copy = msg_len < (out_buf_len - 1) ? msg_len : (out_buf_len - 1);
        memcpy(out_buf, msg, (size_t)copy);
        out_buf[copy] = '\0';
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * Host key / known-hosts
 * ---------------------------------------------------------------------- */

/*
 * Returns the raw fingerprint bytes as int64_t (pointer to internal buffer).
 * hash_type: 1=MD5 (16 bytes), 2=SHA1 (20 bytes), 3=SHA256 (32 bytes)
 */
int64_t stub_hostkey_hash(int64_t session, int32_t hash_type) {
    return (int64_t)(uintptr_t)libssh2_hostkey_hash(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        hash_type);
}

/* Returns LIBSSH2_KNOWNHOSTS* as int64_t */
int64_t stub_knownhosts_init(int64_t session) {
    return (int64_t)(uintptr_t)libssh2_knownhost_init(
        (LIBSSH2_SESSION *)(uintptr_t)session);
}

int32_t stub_knownhosts_readfile(int64_t knownhosts, const char *path) {
    return libssh2_knownhost_readfile(
        (LIBSSH2_KNOWNHOSTS *)(uintptr_t)knownhosts,
        path,
        LIBSSH2_KNOWNHOST_FILE_OPENSSH);
}

/*
 * Check the host key against the known-hosts store.
 * key: raw bytes of the host key
 * key_len: number of bytes
 * key_type: LIBSSH2_KNOWNHOST_KEY_SSHRSA, _ECDSA256, etc.
 *
 * Returns:
 *   LIBSSH2_KNOWNHOST_CHECK_MATCH    (0)  — match found
 *   LIBSSH2_KNOWNHOST_CHECK_MISMATCH (1)  — host known but key differs
 *   LIBSSH2_KNOWNHOST_CHECK_NOTFOUND (2)  — host not in file
 *   LIBSSH2_KNOWNHOST_CHECK_FAILURE  (3)  — internal error
 */
int32_t stub_knownhosts_check(int64_t knownhosts,
                               const char *host,
                               int32_t     port,
                               const char *key,
                               int32_t     key_len,
                               int32_t     key_type) {
    int type_mask = LIBSSH2_KNOWNHOST_TYPE_PLAIN
                  | LIBSSH2_KNOWNHOST_KEYENC_RAW
                  | (key_type << LIBSSH2_KNOWNHOST_KEY_SHIFT);
    return libssh2_knownhost_checkp(
        (LIBSSH2_KNOWNHOSTS *)(uintptr_t)knownhosts,
        host, port,
        key, (size_t)key_len,
        type_mask,
        NULL);
}

void stub_knownhosts_free(int64_t knownhosts) {
    libssh2_knownhost_free((LIBSSH2_KNOWNHOSTS *)(uintptr_t)knownhosts);
}

/* -------------------------------------------------------------------------
 * Authentication
 * ---------------------------------------------------------------------- */

/*
 * Password auth — zeroes the password buffer after use.
 * username / password are null-terminated C strings provided by caller.
 */
int32_t stub_userauth_password(int64_t     session,
                                const char *username,
                                char       *password) {
    int rc = libssh2_userauth_password(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        username, password);
    /* Zeroize regardless of success/failure */
    if (password) secure_zero(password, strlen(password));
    return rc;
}

/*
 * Public key auth from file paths — zeroes passphrase after use.
 * Pass NULL for passphrase if key has no passphrase.
 */
int32_t stub_userauth_pubkey_file(int64_t     session,
                                   const char *username,
                                   const char *pubkey_path,
                                   const char *privkey_path,
                                   char       *passphrase) {
    int rc = libssh2_userauth_publickey_fromfile(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        username, pubkey_path, privkey_path,
        passphrase);
    if (passphrase) secure_zero(passphrase, strlen(passphrase));
    return rc;
}

/*
 * Public key auth from memory buffers — zeroes secret material after use.
 * privkey_data / privkey_len: raw private key PEM bytes
 * passphrase: null-terminated, may be NULL
 */
int32_t stub_userauth_pubkey_memory(int64_t     session,
                                     const char *username,
                                     const char *pubkey_data,
                                     int32_t     pubkey_len,
                                     char       *privkey_data,
                                     int32_t     privkey_len,
                                     char       *passphrase) {
    int rc = libssh2_userauth_publickey_frommemory(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        username, strlen(username),
        pubkey_data,  (size_t)pubkey_len,
        privkey_data, (size_t)privkey_len,
        passphrase);
    if (privkey_data) secure_zero(privkey_data, (size_t)privkey_len);
    if (passphrase)   secure_zero(passphrase, strlen(passphrase));
    return rc;
}

/* -------------------------------------------------------------------------
 * Channel — exec
 * ---------------------------------------------------------------------- */

/* Returns LIBSSH2_CHANNEL* as int64_t; 0 on failure */
int64_t stub_channel_open_session(int64_t session) {
    return (int64_t)(uintptr_t)libssh2_channel_open_session(
        (LIBSSH2_SESSION *)(uintptr_t)session);
}

/* libssh2_channel_exec is a macro — wrap it */
int32_t stub_channel_exec(int64_t channel, const char *command) {
    return libssh2_channel_exec(
        (LIBSSH2_CHANNEL *)(uintptr_t)channel,
        command);
}

/* Returns bytes read (>=0) or negative error code */
int32_t stub_channel_read(int64_t channel, char *buf, int32_t buf_len) {
    return (int32_t)libssh2_channel_read(
        (LIBSSH2_CHANNEL *)(uintptr_t)channel,
        buf, (size_t)buf_len);
}

/* Read from stderr stream (stream_id = SSH_EXTENDED_DATA_STDERR = 1) */
int32_t stub_channel_read_stderr(int64_t channel, char *buf, int32_t buf_len) {
    return (int32_t)libssh2_channel_read_stderr(
        (LIBSSH2_CHANNEL *)(uintptr_t)channel,
        buf, (size_t)buf_len);
}

int32_t stub_channel_write(int64_t channel, const char *buf, int32_t buf_len) {
    return (int32_t)libssh2_channel_write(
        (LIBSSH2_CHANNEL *)(uintptr_t)channel,
        buf, (size_t)buf_len);
}

int32_t stub_channel_send_eof(int64_t channel) {
    return libssh2_channel_send_eof((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

int32_t stub_channel_wait_eof(int64_t channel) {
    return libssh2_channel_wait_eof((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

int32_t stub_channel_close(int64_t channel) {
    return libssh2_channel_close((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

int32_t stub_channel_wait_closed(int64_t channel) {
    return libssh2_channel_wait_closed((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

int32_t stub_channel_get_exit_status(int64_t channel) {
    return libssh2_channel_get_exit_status((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

int32_t stub_channel_free(int64_t channel) {
    return libssh2_channel_free((LIBSSH2_CHANNEL *)(uintptr_t)channel);
}

/* -------------------------------------------------------------------------
 * Channel — port-forward / direct-tcpip
 * ---------------------------------------------------------------------- */

/*
 * Opens a direct-tcpip channel forwarding connections to remote_host:remote_port.
 * Returns LIBSSH2_CHANNEL* as int64_t; 0 on failure.
 */
int64_t stub_channel_direct_tcpip(int64_t     session,
                                   const char *remote_host,
                                   int32_t     remote_port) {
    return (int64_t)(uintptr_t)libssh2_channel_direct_tcpip(
        (LIBSSH2_SESSION *)(uintptr_t)session,
        remote_host, remote_port);
}

/* -------------------------------------------------------------------------
 * SFTP
 * ---------------------------------------------------------------------- */

/* Returns LIBSSH2_SFTP* as int64_t */
int64_t stub_sftp_init(int64_t session) {
    return (int64_t)(uintptr_t)libssh2_sftp_init(
        (LIBSSH2_SESSION *)(uintptr_t)session);
}

int32_t stub_sftp_shutdown(int64_t sftp) {
    return libssh2_sftp_shutdown((LIBSSH2_SFTP *)(uintptr_t)sftp);
}

/*
 * flags: combination of LIBSSH2_FXF_READ(0x1) | LIBSSH2_FXF_WRITE(0x2) |
 *        LIBSSH2_FXF_CREAT(0x8) | LIBSSH2_FXF_TRUNC(0x10)
 * mode:  Unix permission bits e.g. 0644
 * open_type: LIBSSH2_SFTP_OPENFILE(0) or LIBSSH2_SFTP_OPENDIR(1)
 * Returns LIBSSH2_SFTP_HANDLE* as int64_t; 0 on failure.
 */
int64_t stub_sftp_open(int64_t     sftp,
                        const char *path,
                        int32_t     flags,
                        int32_t     mode,
                        int32_t     open_type) {
    return (int64_t)(uintptr_t)libssh2_sftp_open_ex(
        (LIBSSH2_SFTP *)(uintptr_t)sftp,
        path, (unsigned int)strlen(path),
        (unsigned long)flags,
        (long)mode,
        open_type);
}

/* Returns bytes read (>=0) or negative error */
int32_t stub_sftp_read(int64_t handle, char *buf, int32_t buf_len) {
    return (int32_t)libssh2_sftp_read(
        (LIBSSH2_SFTP_HANDLE *)(uintptr_t)handle,
        buf, (size_t)buf_len);
}

/* Returns bytes written (>=0) or negative error */
int32_t stub_sftp_write(int64_t handle, const char *buf, int32_t buf_len) {
    return (int32_t)libssh2_sftp_write(
        (LIBSSH2_SFTP_HANDLE *)(uintptr_t)handle,
        buf, (size_t)buf_len);
}

int32_t stub_sftp_close(int64_t handle) {
    return libssh2_sftp_close((LIBSSH2_SFTP_HANDLE *)(uintptr_t)handle);
}

int64_t stub_sftp_last_error(int64_t sftp) {
    return (int64_t)libssh2_sftp_last_error((LIBSSH2_SFTP *)(uintptr_t)sftp);
}

/* -------------------------------------------------------------------------
 * Buffer / string helpers invoked from MoonBit
 * ---------------------------------------------------------------------- */

/*
 * Allocate a zeroed heap buffer — returned as int64_t (void*).
 * MoonBit calls this to get a raw C buffer for read operations.
 */
int64_t stub_alloc_buf(int32_t size) {
    if (size <= 0) return 0;
    void *p = calloc((size_t)size, 1);
    return (int64_t)(uintptr_t)p;
}

/* Free a buffer allocated by stub_alloc_buf */
void stub_free_buf(int64_t ptr) {
    if (ptr) free((void *)(uintptr_t)ptr);
}

/* Zero and free — for secret material */
void stub_free_secret_buf(int64_t ptr, int32_t size) {
    if (!ptr) return;
    void *p = (void *)(uintptr_t)ptr;
    if (size > 0) secure_zero(p, (size_t)size);
    free(p);
}

/* Copy a C string from a heap buffer into caller-supplied buffer */
int32_t stub_buf_copy_str(int64_t src_ptr, char *dst, int32_t dst_len) {
    const char *src = (const char *)(uintptr_t)src_ptr;
    if (!src || !dst || dst_len <= 0) return 0;
    int32_t slen = (int32_t)strlen(src);
    int32_t copy = slen < (dst_len - 1) ? slen : (dst_len - 1);
    memcpy(dst, src, (size_t)copy);
    dst[copy] = '\0';
    return copy;
}

/* Read a single byte from a C pointer (for fingerprint scanning) */
int32_t stub_buf_get_byte(int64_t ptr, int32_t offset) {
    if (!ptr) return -1;
    return (int32_t)((unsigned char *)(uintptr_t)ptr)[offset];
}

/* Write len bytes of string data into a heap buffer; returns the buffer ptr */
int64_t stub_str_to_buf(const char *str) {
    if (!str) return 0;
    size_t n = strlen(str);
    char  *p = (char *)malloc(n + 1);
    if (!p) return 0;
    memcpy(p, str, n + 1);
    return (int64_t)(uintptr_t)p;
}

/* Write a single byte into a C buffer (used for MoonBit→C string building) */
void stub_write_byte(int64_t ptr, int32_t offset, int32_t byte_val) {
    if (!ptr) return;
    ((unsigned char *)(uintptr_t)ptr)[offset] = (unsigned char)byte_val;
}

/* NUL-terminate a C buffer at the given position */
void stub_nul_terminate(int64_t ptr, int32_t offset) {
    if (!ptr) return;
    ((char *)(uintptr_t)ptr)[offset] = '\0';
}

/* -------------------------------------------------------------------------
 * Winsock helpers (Windows-only convenience wrappers)
 * ---------------------------------------------------------------------- */

#ifdef _WIN32
/* Returns SOCKET as int64_t (INVALID_SOCKET → 0 for easy null-check) */
int64_t stub_tcp_connect(const char *host, int32_t port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)port);

    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        /* Try it as a hostname — minimal getaddrinfo fallback */
        struct addrinfo hints, *res = NULL;
        char port_str[8];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        snprintf(port_str, sizeof(port_str), "%d", port);
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
            closesocket(sock);
            return 0;
        }
        memcpy(&sa, res->ai_addr, sizeof(sa));
        freeaddrinfo(res);
    }

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(sock);
        return 0;
    }
    return (int64_t)(uintptr_t)sock;
}

void stub_tcp_disconnect(int64_t sock) {
    if (sock) closesocket((SOCKET)(uintptr_t)sock);
}

int32_t stub_winsock_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w);
}

void stub_winsock_cleanup(void) {
    WSACleanup();
}
#endif /* _WIN32 */
