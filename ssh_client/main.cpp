// ssh_client/main.cpp
// Basic libssh2 demo on Windows 11
// Build: cmake + vcpkg (x64-windows)

#include <libssh2.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// Configuration — change these to match your target host
// ---------------------------------------------------------------------------
static const char* SSH_HOST = "127.0.0.1";
static const int   SSH_PORT = 22;
static const char* SSH_USER = "your_username";
static const char* SSH_PASS = "your_password";   // nullptr to use pubkey only
static const char* SSH_CMD  = "uname -a || ver"; // works on Linux; 'ver' on Win
// ---------------------------------------------------------------------------

// RAII helper: ensures cleanup order is correct even on exceptions
struct SshContext {
    WSADATA          wsa{};
    SOCKET           sock   = INVALID_SOCKET;
    LIBSSH2_SESSION* session = nullptr;
    LIBSSH2_CHANNEL* channel = nullptr;

    SshContext()  { WSAStartup(MAKEWORD(2, 2), &wsa); }
    ~SshContext() {
        if (channel) {
            libssh2_channel_close(channel);
            libssh2_channel_free(channel);
        }
        if (session) {
            libssh2_session_disconnect(session, "Normal shutdown");
            libssh2_session_free(session);
        }
        if (sock != INVALID_SOCKET) closesocket(sock);
        libssh2_exit();
        WSACleanup();
    }
};

// Print the last libssh2 error and throw
static void ssh_check(int rc, LIBSSH2_SESSION* s, const char* ctx) {
    if (rc == 0) return;
    char* msg = nullptr;
    libssh2_session_last_error(s, &msg, nullptr, 0);
    std::string err = std::string(ctx) + " failed (rc=" + std::to_string(rc) + "): "
                    + (msg ? msg : "unknown");
    throw std::runtime_error(err);
}

int main() {
    std::cout << "libssh2 version: " << libssh2_version(0) << "\n\n";

    // -----------------------------------------------------------------------
    // 1. Init libssh2
    // -----------------------------------------------------------------------
    if (libssh2_init(0) != 0)
        throw std::runtime_error("libssh2_init failed");

    SshContext ctx;

    // -----------------------------------------------------------------------
    // 2. TCP connect
    // -----------------------------------------------------------------------
    ctx.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx.sock == INVALID_SOCKET)
        throw std::runtime_error("socket() failed: " + std::to_string(WSAGetLastError()));

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(static_cast<u_short>(SSH_PORT));
    if (inet_pton(AF_INET, SSH_HOST, &sin.sin_addr) != 1)
        throw std::runtime_error("inet_pton failed — check SSH_HOST");

    std::cout << "Connecting to " << SSH_HOST << ":" << SSH_PORT << " ...\n";
    if (connect(ctx.sock, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) != 0) {
        std::cerr << "TCP connect failed (WSA=" << WSAGetLastError() << ")\n"
                  << "  -> No live host at " << SSH_HOST
                  << " — the rest of the demo is skipped.\n"
                  << "     Edit SSH_HOST/SSH_PORT at the top of main.cpp to test fully.\n";
        return 0;
    }
    std::cout << "TCP connected.\n";

    // -----------------------------------------------------------------------
    // 3. SSH session + handshake
    // -----------------------------------------------------------------------
    ctx.session = libssh2_session_init();
    if (!ctx.session)
        throw std::runtime_error("libssh2_session_init failed");

    libssh2_session_set_blocking(ctx.session, 1);  // blocking I/O

    ssh_check(libssh2_session_handshake(ctx.session, ctx.sock),
              ctx.session, "session_handshake");
    std::cout << "SSH handshake OK.\n";

    // -----------------------------------------------------------------------
    // 4. Host key fingerprint (SHA-1, hex)
    // -----------------------------------------------------------------------
    const char* fingerprint =
        libssh2_hostkey_hash(ctx.session, LIBSSH2_HOSTKEY_HASH_SHA1);
    std::cout << "Host key SHA-1: ";
    for (int i = 0; i < 20; ++i)
        std::cout << std::hex << std::uppercase
                  << ((static_cast<unsigned char>(fingerprint[i]) >> 4) & 0xf)
                  << (static_cast<unsigned char>(fingerprint[i]) & 0xf);
    std::cout << std::dec << "\n";

    // -----------------------------------------------------------------------
    // 5. Authentication — password
    // -----------------------------------------------------------------------
    std::cout << "Authenticating as '" << SSH_USER << "' ...\n";
    ssh_check(libssh2_userauth_password(ctx.session, SSH_USER, SSH_PASS),
              ctx.session, "userauth_password");
    std::cout << "Authenticated.\n";

    // -----------------------------------------------------------------------
    // 6. Open channel + execute command
    // -----------------------------------------------------------------------
    ctx.channel = libssh2_channel_open_session(ctx.session);
    if (!ctx.channel)
        throw std::runtime_error("channel_open_session failed");

    ssh_check(libssh2_channel_exec(ctx.channel, SSH_CMD),
              ctx.session, "channel_exec");
    std::cout << "\n--- Output of `" << SSH_CMD << "` ---\n";

    char buf[4096];
    int  nbytes;
    while ((nbytes = libssh2_channel_read(ctx.channel, buf, sizeof(buf))) > 0)
        std::cout.write(buf, nbytes);

    // stderr
    while ((nbytes = libssh2_channel_read_stderr(ctx.channel, buf, sizeof(buf))) > 0)
        std::cerr.write(buf, nbytes);

    std::cout << "\n--- Done ---\n";

    // SshContext destructor handles all cleanup
    return 0;
}
