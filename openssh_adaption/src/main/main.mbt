// main.mbt — libssh2 MoonBit wrapper · API usage demo
//
// Compile:  moon build --target native
// Run:      .\target\native\release\build\main\main.exe
//
// This file demonstrates every API group exposed by the wrapper:
//
//   demo_session_lifecycle  — connect → verify → auth → disconnect
//   demo_exec               — execute a remote command, collect output
//   demo_sftp_read          — download a remote file over SFTP
//   demo_sftp_write         — upload content to a remote file over SFTP
//   demo_port_forward       — open a direct-tcpip TCP tunnel
//
// Each demo function is self-contained and annotated.
// Edit the CONFIG block below to point at a real server.

// ═══════════════════════════════════════════════════════════════════
//  CONFIG — edit before running
// ═══════════════════════════════════════════════════════════════════

///|
let demo_host : String = "127.0.0.1"

///|
let demo_port : Int = 22

///|
let demo_user : String = "your_username"

///|
let demo_password : String = "your_password"

///|
let demo_known_hosts : String = "C:/Users/you/.ssh/known_hosts"

// Public-key auth paths (used by demo_session_lifecycle pubkey variant)

///|
let demo_pubkey_file : String = "C:/Users/you/.ssh/id_<key_name>.pub"

///|
let demo_privkey_file : String = "C:/Users/you/.ssh/id_<key_name>"

// Remote paths/commands used by exec/SFTP demos

///|
let demo_command : String = "uname -a && uptime"

///|
let demo_sftp_remote : String = "/etc/hostname"

///|
let demo_sftp_upload : String = "/tmp/moonbit_demo.txt"

// Port-forward target (e.g. an HTTP service running on the remote)

///|
let demo_fwd_host : String = "localhost"

///|
let demo_fwd_port : Int = 8080

// Set true to run the pubkey auth demo instead of skipping it

///|
let run_pubkey_demo : Bool = false

// ═══════════════════════════════════════════════════════════════════
//  Pretty-print helpers
// ═══════════════════════════════════════════════════════════════════

///|
fn hdr(title : String) -> Unit {
  println("")
  println(
    "┌─────────────────────────────────────────────",
  )
  println("│  \{title}")
  println(
    "└─────────────────────────────────────────────",
  )
}

///|
fn ok_line(label : String, value : String) -> Unit {
  println("  ✔  \{label}: \{value}")
}

///|
fn err_line(label : String, msg : String) -> Unit {
  println("  ✘  \{label}: \{msg}")
}

// bytes_to_str converts a raw Bytes value to a printable String.

///|
fn bytes_to_str(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i in 0..<b.length() {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

// ═══════════════════════════════════════════════════════════════════
//  DEMO 1 — Session lifecycle
//
//  API calls shown:
//    Session::connect(host, port)         → Result[Session, SshError]
//    session.verify_host_key(path)        → Result[Unit,    SshError]
//    session.auth_password(user, pass)    → Result[Unit,    SshError]
//    session.auth_pubkey_file(user, pub,  → Result[Unit,    SshError]
//                             priv, pass)
//    session.is_host_verified()           → Bool
//    session.is_authenticated()           → Bool
//    session.disconnect()
// ═══════════════════════════════════════════════════════════════════

///|
/// Returns a connected + authenticated Session, or None on failure.
/// Other demos call this to get a ready session.
fn get_session() -> @ssh.Session? {
  // ── Step 1: TCP connect + SSH handshake ─────────────────────────
  // Session::connect performs the TCP connection and negotiates the
  // SSH transport layer (key exchange, cipher selection).
  // The wrapper enforces an algorithm allow-list at this point,
  // rejecting insecure ciphers / kex methods automatically.
  let session = match @ssh.Session::connect(demo_host, demo_port) {
    Err(e) => {
      err_line("connect", e.to_string())
      return None
    }
    Ok(s) => s
  }
  ok_line("TCP + handshake", "\{demo_host}:\{demo_port}")

  // ── Step 2: Host-key verification ───────────────────────────────
  // verify_host_key checks the server's public key fingerprint
  // against a known_hosts file using SHA-256 hashing.
  //
  // Return values:
  //   Ok(())              — key matches known_hosts  ✔
  //   Err(HostKeyMismatch)  — MITM suspected! must abort.
  //   Err(HostKeyNotFound)  — first-connect; add to known_hosts.
  //   Err(KnownHostsReadFailed) — file missing / not readable.
  match session.verify_host_key(demo_known_hosts) {
    Err(@ssh.SshError::HostKeyMismatch(h)) => {
      // CRITICAL — this is a potential MITM attack. Always abort.
      err_line("host key MISMATCH", h)
      session.disconnect()
      return None
    }
    Err(@ssh.SshError::HostKeyNotFound(h)) => {
      // First-time connection: add server to known_hosts manually,
      // then re-run. We continue here for demo convenience only.
      err_line("host key not found", h)
      println("     ↳ add it to known_hosts and retry in production")
    }
    Err(e) =>
      // File I/O error — continue for demo purposes.
      err_line("known_hosts", e.to_string())
    Ok(_) => ok_line("host key", "verified (\{demo_known_hosts})")
  }

  // ── Step 3: Authentication — password ───────────────────────────
  // auth_password sends the password over the encrypted channel.
  // The wrapper zeroes the password buffer via SecureZeroMemory
  // immediately after the libssh2 call.
  match session.auth_password(demo_user, demo_password) {
    Err(e) => {
      err_line("auth (password)", e.to_string())
      session.disconnect()
      return None
    }
    Ok(_) => ok_line("auth (password)", "ok — user '\{demo_user}'")
  }

  // ── Introspection helpers ────────────────────────────────────────
  ok_line("is_host_verified", "\{session.is_host_verified()}")
  ok_line("is_authenticated", "\{session.is_authenticated()}")
  Some(session)
}

///|
/// Shows the pubkey-file auth alternative (skipped when not configured).
fn demo_pubkey_auth() -> Unit {
  hdr("DEMO 1b — Pubkey file authentication")
  let session = match @ssh.Session::connect(demo_host, demo_port) {
    Err(e) => {
      err_line("connect", e.to_string())
      return
    }
    Ok(s) => s
  }
  // auth_pubkey_file reads the private key from disk.
  // The passphrase is zeroed by SecureZeroMemory after use.
  match
    session.auth_pubkey_file(demo_user, demo_pubkey_file, demo_privkey_file, "") {
    Err(e) => err_line("pubkey auth", e.to_string())
    Ok(_) => ok_line("pubkey auth", "ok — '\{demo_user}'")
  }
  session.disconnect()
}

// ═══════════════════════════════════════════════════════════════════
//  DEMO 2 — Remote command execution
//
//  API calls shown:
//    session.open_channel()               → Result[Channel, SshError]
//    channel.exec(cmd)                    → Result[Unit,    SshError]
//    channel.read_stdout(buf_size)        → Result[String,  SshError]
//    channel.read_stderr(buf_size)        → Result[String,  SshError]
//    channel.exit_status()                → Int
//    channel.close()
//
//  OR the convenience method:
//    channel.run(cmd) → Result[(stdout, stderr, exit_code), SshError]
// ═══════════════════════════════════════════════════════════════════

///|
fn demo_exec(session : @ssh.Session) -> Unit {
  hdr("DEMO 2 — Remote command execution")
  println("  Command: \{demo_command}")

  // ── High-level: run() bundles exec + read + close ────────────────
  // Use run() for simple fire-and-collect use cases.
  // Each call requires a new channel (SSH channels are single-use).
  let ch = match session.open_channel() {
    Err(e) => {
      err_line("open_channel", e.to_string())
      return
    }
    Ok(c) => c
  }
  match ch.run(demo_command) {
    Err(e) => err_line("run", e.to_string())
    Ok((stdout, stderr, code)) => {
      ok_line("exit code", "\{code}")
      ok_line("stdout", stdout.trim_end().to_string())
      if stderr.length() > 0 {
        ok_line("stderr", stderr.trim_end().to_string())
      }
    }
  }

  // ── Low-level: manual exec + incremental read ───────────────────
  // Use this path when you need streaming or partial reads.
  println("")
  println("  --- low-level path ---")
  let ch2 = match session.open_channel() {
    Err(e) => {
      err_line("open_channel", e.to_string())
      return
    }
    Ok(c) => c
  }
  match ch2.exec("echo low-level") {
    Err(e) => {
      err_line("exec", e.to_string())
      return
    }
    Ok(_) => ()
  }
  // read_stdout(0) uses the default 32 KiB internal buffer.
  // Pass a positive value to set a custom maximum byte count.
  match ch2.read_stdout(0) {
    Err(e) => err_line("read_stdout", e.to_string())
    Ok(s) => ok_line("stdout", s.trim_end().to_string())
  }
  ok_line("exit code", "\{ch2.exit_status()}")
  ch2.close()
}

// ═══════════════════════════════════════════════════════════════════
//  DEMO 3 — SFTP file operations
//
//  API calls shown:
//    session.open_sftp()                  → Result[Sftp,       SshError]
//    sftp.open_read(path)                 → Result[SftpHandle, SshError]
//    sftp.open_write(path)                → Result[SftpHandle, SshError]
//    sftp.open_append(path)               → Result[SftpHandle, SshError]
//    handle.read(max_bytes)               → Result[Bytes, SshError]
//    handle.read_all()                    → Result[Bytes, SshError]
//    handle.write(data)                   → Result[Int,  SshError]
//    handle.write_all(data)               → Result[Unit, SshError]
//    handle.close()
//    sftp.shutdown()
// ═══════════════════════════════════════════════════════════════════

///|
fn demo_sftp_read(session : @ssh.Session) -> Unit {
  hdr("DEMO 3a — SFTP download")
  println("  Remote file: \{demo_sftp_remote}")

  // open_sftp() initialises the SFTP subsystem on the session.
  // One Sftp instance can open multiple handles sequentially.
  let sftp = match session.open_sftp() {
    Err(e) => {
      err_line("open_sftp", e.to_string())
      return
    }
    Ok(s) => s
  }

  // open_read opens a remote file for reading.
  let fh = match sftp.open_read(demo_sftp_remote) {
    Err(e) => {
      err_line("open_read", e.to_string())
      sftp.shutdown()
      return
    }
    Ok(h) => h
  }

  // read_all() accumulates chunks until EOF; returns raw Bytes.
  match fh.read_all() {
    Err(e) => err_line("read_all", e.to_string())
    Ok(b) => {
      ok_line("bytes read", "\{b.length()}")
      ok_line("content", bytes_to_str(b).trim_end().to_string())
    }
  }
  fh.close() // always close handles before shutdown
  sftp.shutdown()
}

///|
fn demo_sftp_write(session : @ssh.Session) -> Unit {
  hdr("DEMO 3b — SFTP upload")
  println("  Remote path: \{demo_sftp_upload}")
  let sftp = match session.open_sftp() {
    Err(e) => {
      err_line("open_sftp", e.to_string())
      return
    }
    Ok(s) => s
  }

  // open_write creates/truncates the remote file (WRITE|CREAT|TRUNC).
  // open_append would use WRITE|CREAT|APPEND instead.
  let fh = match sftp.open_write(demo_sftp_upload) {
    Err(e) => {
      err_line("open_write", e.to_string())
      sftp.shutdown()
      return
    }
    Ok(h) => h
  }

  // Build payload as Bytes.
  let payload = "Hello from MoonBit libssh2 wrapper!\n"
  let raw_arr : FixedArray[Byte] = FixedArray::make(payload.length(), b'\x00')
  for pi in 0..<payload.length() {
    raw_arr[pi] = payload[pi].to_int().to_byte()
  }
  let raw = Bytes::from_array(raw_arr)

  // write_all loops internally until all bytes are sent.
  match fh.write_all(raw) {
    Err(e) => err_line("write_all", e.to_string())
    Ok(_) => ok_line("written", "\{raw.length()} bytes → \{demo_sftp_upload}")
  }
  fh.close()
  sftp.shutdown()
}

// ═══════════════════════════════════════════════════════════════════
//  DEMO 4 — Port forwarding (direct-tcpip)
//
//  API calls shown:
//    session.direct_tcpip(remote_host, remote_port)
//                                         → Result[Channel, SshError]
//    channel.write(data)                  → Result[Int,  SshError]
//    channel.read_stdout(max_bytes)       → Result[String, SshError]
//    channel.close()
//
//  direct_tcpip opens a forwarded TCP channel to (remote_host, port)
//  as seen from the SSH server.  You can then read/write raw bytes
//  through the tunnel — useful for proxying database or HTTP traffic.
// ═══════════════════════════════════════════════════════════════════

///|
fn demo_port_forward(session : @ssh.Session) -> Unit {
  hdr("DEMO 4 — Port forwarding (direct-tcpip)")
  println("  Forwarding to: \{demo_fwd_host}:\{demo_fwd_port}")

  // direct_tcpip instructs the SSH server to open a TCP connection
  // to (demo_fwd_host, demo_fwd_port) on the server's local network.
  let ch = match session.direct_tcpip(demo_fwd_host, demo_fwd_port) {
    Err(e) => {
      err_line("direct_tcpip", e.to_string())
      println("     ↳ (service may not be running on the remote)")
      return
    }
    Ok(c) => c
  }
  ok_line("tunnel", "open to \{demo_fwd_host}:\{demo_fwd_port}")

  // Send a minimal HTTP/1.0 request through the tunnel.
  let req = "GET / HTTP/1.0\r\nHost: \{demo_fwd_host}\r\n\r\n"
  let req_arr : FixedArray[Byte] = FixedArray::make(req.length(), b'\x00')
  for ri in 0..<req.length() {
    req_arr[ri] = req[ri].to_int().to_byte()
  }
  let req_bytes = Bytes::from_array(req_arr)
  match ch.write(req_bytes) {
    Err(e) => {
      err_line("write", e.to_string())
      ch.close()
      return
    }
    Ok(n) => ok_line("sent", "\{n} bytes")
  }

  // Read the first chunk of the response.
  match ch.read_stdout(4096) {
    Err(e) => err_line("read_stdout", e.to_string())
    Ok(s) => {
      // Show only the HTTP status line for brevity.
      let sb2 = StringBuilder::new()
      let mut fi = 0
      while fi < s.length() {
        let c = Int::unsafe_to_char(s[fi].to_int())
        if c == '\r' || c == '\n' {
          break
        }
        sb2.write_char(c)
        fi = fi + 1
      }
      ok_line("response", sb2.to_string())
    }
  }
  ch.close()
}

// ═══════════════════════════════════════════════════════════════════
//  MAIN — orchestrate all demos
// ═══════════════════════════════════════════════════════════════════

///|
fn main {
  // Print the libssh2 version we linked against.
  let ver = @ffi.raw_buf_to_string(@ffi.raw_libssh2_version(), 64)
  println("libssh2 version: \{ver}")
  println("Target: \{demo_host}:\{demo_port}  user: \{demo_user}")

  // ── Demo 1: session lifecycle (connect + verify + auth) ──────────
  hdr("DEMO 1 — Session lifecycle")
  let session = match get_session() {
    None => {
      println("\nCould not establish an authenticated session.")
      println("Edit the CONFIG block at the top of main.mbt and re-run.")
      return
    }
    Some(s) => s
  }

  // ── Demo 1b: pubkey auth (skipped by default — set run_pubkey_demo=true)
  if run_pubkey_demo {
    demo_pubkey_auth()
  }

  // ── Demo 2: remote exec ─────────────────────────────────────────
  demo_exec(session)

  // ── Demo 3a: SFTP download ──────────────────────────────────────
  demo_sftp_read(session)

  // ── Demo 3b: SFTP upload ────────────────────────────────────────
  demo_sftp_write(session)

  // ── Demo 4: port forwarding ─────────────────────────────────────
  demo_port_forward(session)

  // ── Teardown ─────────────────────────────────────────────────────
  hdr("Teardown")
  session.disconnect()
  ok_line("session", "disconnected cleanly")
  println("")
}
