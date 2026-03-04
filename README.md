# libssh_mb — MoonBit Wrapper for libssh2

> **⚠️ AI-Generated Project Notice**
> This project was generated with the assistance of AI (GitHub Copilot / Claude). It is intended as a learning resource and proof-of-concept. Review all code carefully before using it in any production or security-sensitive context. The SSH session layer enforces a cryptographic algorithm allow-list and mandates host-key verification, but no independent security audit has been performed.

---

## Overview

`libssh_mb` is a safe, idiomatic [MoonBit](https://www.moonbitlang.com/) wrapper around the [libssh2](https://libssh2.org/) C library. It provides:

| Feature | Description |
|---|---|
| **Session management** | TCP connect, SSH handshake, host-key verification, graceful disconnect |
| **Algorithm allow-list** | Blocks weak KEX, cipher, MAC, and host-key algorithms at compile policy |
| **Password auth** | `session.auth_password(user, pass)` — secret zeroed in C immediately after use |
| **Public-key auth** | File-based (`auth_pubkey_file`) and in-memory (`auth_pubkey_memory`) |
| **Remote exec** | `channel.exec(cmd)` → collect stdout/stderr + exit code |
| **SFTP** | Upload, download, append; `read_all` / `write_all` convenience methods |
| **Port forwarding** | `session.direct_tcpip(host, port)` for TCP tunnel via SSH |
| **Audit log** | All events written to stderr with `[SSH][LEVEL]` prefix |

---

## Prerequisites

- **OS**: Windows 11 (x64)
- **MoonBit toolchain**: `v0.1.x` or later — [install guide](https://www.moonbitlang.com/download/)
- **C compiler**: [Build Tools for Visual Studio 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) (standalone) **or** the full VS 2022 IDE — install the **"C++ build tools"** workload (Build Tools) or **"Desktop development with C++"** (IDE)
- **vcpkg** + **libssh2** (see below)

---

## 1 — Install vcpkg

[vcpkg](https://vcpkg.io/) is Microsoft's open-source C/C++ package manager.

```powershell
# 1. Clone vcpkg to a convenient location (e.g. <Your_Projects>\vcpkg)
git clone https://github.com/microsoft/vcpkg.git <Your_Projects>\vcpkg
cd <Your_Projects>\vcpkg

# 2. Bootstrap (builds the vcpkg executable)
.\bootstrap-vcpkg.bat

# 3. (Optional but recommended) Integrate with Visual Studio / MSBuild
.\vcpkg integrate install
```

> **Tip**: Add `<Your_Projects>\vcpkg` to your `PATH` so you can run `vcpkg` from any terminal.

---

## 2 — Install libssh2 via vcpkg

```powershell
cd <Your_Projects>\vcpkg

# Install the 64-bit libraries for libssh2
vcpkg install libssh2:x64-windows

# Verify the installation
vcpkg list libssh2
```

After installation, the headers and import libraries appear under:

```
<Your_Projects>\vcpkg\installed\x64-windows\
├── include\
│   ├── libssh2.h
│   └── libssh2_sftp.h
└── lib\
    └── libssh2.lib
```

> **Note**: `src/main/moon.pkg.json` is **not committed to git** — it is generated
> by `setup.ps1` with the correct local paths for your machine.  See step 3 below.

---

## 3 — Run setup.ps1

`setup.ps1` does two things in one command:
1. Generates `src/main/moon.pkg.json` from the committed template (`moon.pkg.json.template`) with the correct vcpkg paths for your machine.
2. Compiles `src/ffi/c_stub.c` → `src/ffi/c_stub.lib` via MSVC.

Open a Developer PowerShell with the MSVC environment loaded, then:

**Option A — Full VS 2022 IDE install**: search the Start menu for **"Developer PowerShell for VS 2022"**.

**Option B — Build Tools for Visual Studio 2022** (standalone, installed at `<Your_Visual_Studio_2022>\BuildTools`): there is no dedicated Start-menu entry; run the launcher instead:
```powershell
& "<Your_Visual_Studio_2022>\BuildTools\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64
```
Then, in that same shell:

```powershell
# Option A — set VCPKG_ROOT in your environment (recommended, set it once permanently)
$env:VCPKG_ROOT = "<Your_Projects>\vcpkg"

cd <Your_Projects>\libssh_mb\openssh_adaption
.\setup.ps1

# Option B — pass the path directly
.\setup.ps1 -VcpkgRoot "<Your_Projects>\vcpkg"
```

The script produces:
- `src/main/moon.pkg.json` — linker config with your local vcpkg paths (gitignored)
- `src/ffi/c_stub.lib` — compiled C stub (gitignored)

---

## 4 — Build & run the demo

```powershell
cd <Your_Projects>\libssh_mb\openssh_adaption

# Build the native release binary
moon build --target native

# Run the demo (edit the CONFIG block in src/main/main.mbt first!)
.\target\native\release\build\main\main.exe
```

Before running, edit the configuration block near the top of
[src/main/main.mbt](src/main/main.mbt):

```moonbit
let demo_host        : String = "127.0.0.1"       // SSH server address
let demo_port        : Int    = 22
let demo_user        : String = "your_username"
let demo_password    : String = "your_password"
let demo_known_hosts : String = "<SSH_CONFIG>/.ssh/known_hosts"
```

---

## 5 — Run the unit tests

No live SSH server is required — the tests cover pure logic (error formatting,
algorithm allow-list, SFTP flag constants, buffer math, etc.).

```powershell
cd <Your_Projects>\libssh_mb\openssh_adaption

# Run tests for the library packages (ssh + lib).
# The main/ package is a demo executable and does not contain tests.
moon test --target native \
  -p libssh_mb/openssh/ssh \
  -p libssh_mb/openssh/lib
# Expected: Total tests: 61, passed: 61, failed: 0
```

> **Note**: Running `moon test --target native` without `-p` will fail because
> the `main/` package requires MSVC-specific link flags (`/link /LIBPATH:...`)
> that are incompatible with MoonBit's bundled TCC linker.  Use the `-p` form
> above to test only the library packages.

---

## 6 — Project structure

```
openssh_adaption/
├── moon.mod.json              # Module manifest (name: libssh_mb/openssh)
├── README.md                  # This file
└── src/
    ├── ffi/                   # Low-level C ↔ MoonBit FFI layer
    │   ├── c_stub.c           # C stubs (wraps libssh2 macros → real symbols)
    │   ├── raw.mbt            # extern "C" declarations + buffer helpers
    │   ├── types.mbt          # Opaque pointer wrappers + constants
    │   └── moon.pkg.json
    ├── ssh/                   # Safe MoonBit API (import this package)
    │   ├── error.mbt          # SshError enum + session_last_err (package-private)
    │   ├── session.mbt        # Session: connect / verify / auth / disconnect
    │   ├── channel.mbt        # Channel: exec / read_stdout / read_stderr / write
    │   ├── sftp.mbt           # Sftp + SftpHandle: open / read / write / close
    │   ├── port_forward.mbt   # Session::direct_tcpip (TCP port tunnel)
    │   ├── session_test.mbt   # Unit tests — allow-list, error formatting
    │   ├── channel_test.mbt   # Unit tests — channel error semantics
    │   ├── sftp_test.mbt      # Unit tests — SFTP flag constants, write_all logic
    │   └── moon.pkg.json
    └── main/                  # Demo executable
        ├── main.mbt           # Five self-contained demos
        └── moon.pkg.json      # Link flags: libssh2.lib, ws2_32.lib, crypt32.lib
```

---

## Security model

1. **Host key verification is mandatory** — `auth_*` methods return `Err(HostKeyCheckFailed)` if `verify_host_key()` has not been called and passed first.
2. **Algorithm allow-list** — weak KEX (`diffie-hellman-group1-sha1`, `group14-sha1`), weak ciphers (CBC modes, 3DES), weak MACs (`hmac-md5`, plain `hmac-sha1`) and `ssh-rsa` (SHA-1) are blocked. Only modern algorithms (Curve25519, AES-GCM, ChaCha20-Poly1305, ETM MACs, Ed25519) are permitted.
3. **Secret zeroing** — passwords and passphrases are zeroed in C (`SecureZeroMemory` on Windows, `explicit_bzero` on Linux) immediately after the libssh2 call; they do not linger in heap or stack memory.
4. **Audit log** — every security-relevant event (connect, fingerprint, verify outcome, auth outcome, disconnect) is written to stderr with a `[SSH][LEVEL]` prefix.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
