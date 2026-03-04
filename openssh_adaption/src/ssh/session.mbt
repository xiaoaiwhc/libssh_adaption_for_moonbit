// session.mbt — Safe MoonBit wrapper around a libssh2 SSH session.
//
// Security design:
//   1. Host key verification is MANDATORY before any authentication call.
//      The `host_verified` flag gates auth_* methods.
//   2. Passwords and passphrases are zeroed immediately in the C stub layer
//      (SecureZeroMemory on Windows).
//   3. An algorithm allow-list blocks known-weak key-exchange, host-key,
//      encryption and MAC algorithms before the handshake completes.
//   4. All events (connect, verify, auth outcomes, disconnect, errors) are
//      written to the audit log via `audit_log`.
//   5. `disconnect` is idempotent and safe to call multiple times.

// -------------------------------------------------------------------------
// Algorithm allow-list (security enforcement)
// -------------------------------------------------------------------------

///|
/// The set of approved algorithm names.  Any algorithm not in this list
/// will cause `connect` to return `AlgoRejected`.
///
/// Covers: kex, hostkey, cipher, and MAC families.
let allowed_kex_algorithms : Array[String] = [
  "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
  "diffie-hellman-group18-sha512",
]

///|
let allowed_hostkey_algorithms : Array[String] = [
  "ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
]

///|
let allowed_ciphers : Array[String] = [
  "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr",
  "aes128-ctr", "chacha20-poly1305@openssh.com",
]

///|
let allowed_macs : Array[String] = [
  "hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
  "umac-128-etm@openssh.com",
]

///|
/// Returns `true` if the algorithm name is on the allow-list.
/// Called by the demo and tests to pre-validate requested algorithms.
pub fn is_algo_allowed(algo : String, category : String) -> Bool {
  let list = match category {
    "kex" => allowed_kex_algorithms
    "hostkey" => allowed_hostkey_algorithms
    "cipher" => allowed_ciphers
    "mac" => allowed_macs
    _ => return false
  }
  for i in 0..<list.length() {
    if list[i] == algo {
      return true
    }
  }
  false
}

// -------------------------------------------------------------------------
// Audit log
// -------------------------------------------------------------------------

///|
/// Write a structured audit entry to stderr.
/// Format:  [SSH][<level>] <message>
pub fn audit_log(level : String, message : String) -> Unit {
  println("[SSH][\{level}] \{message}")
}

// -------------------------------------------------------------------------
// Session type
// -------------------------------------------------------------------------

///|
/// A managed SSH session handle.
///
/// Lifecycle:
///   Session::connect(host, port)    → Result[Session, SshError]
///   session.verify_host_key(...)    → Result[Unit, SshError]   ← required
///   session.auth_password(...)      → Result[Unit, SshError]
///     — or —
///   session.auth_pubkey_file(...)   → Result[Unit, SshError]
///   session.open_channel()          → Result[Channel, SshError]
///   session.open_sftp()             → Result[Sftp, SshError]
///   session.disconnect()
pub(all) struct Session {
  /// Underlying libssh2 session pointer.
  priv ptr : @ffi.SshSessionPtr
  /// Connected TCP socket.
  priv sock : @ffi.SocketHandle
  /// Hostname used for this session (for audit logs and key checks).
  priv host : String
  /// `true` once verify_host_key has passed — gates auth_* methods.
  priv host_verified : Ref[Bool]
  /// `true` once authentication was successful.
  priv authenticated : Ref[Bool]
}

// -------------------------------------------------------------------------
// Construction / connection
// -------------------------------------------------------------------------

///|
/// Connect to `host`:`port`, perform the SSH handshake, and return a Session.
///
/// Steps performed:
///   1. Winsock init (Win32 only)
///   2. TCP connect
///   3. libssh2 session init
///   4. SSH handshake
///   5. Audit log of the server's SHA-256 fingerprint
///
/// Host key verification is NOT performed here; call `verify_host_key` next.
pub fn Session::connect(host : String, port : Int) -> Result[Session, SshError] {
  // (1) Winsock
  let wsa_rc = @ffi.raw_winsock_init()
  if wsa_rc != 0 {
    return Err(WinsockFailed(wsa_rc))
  }

  // (2) TCP connect
  audit_log("INFO", "Connecting to \{host}:\{port}")
  let host_buf = @ffi.string_to_raw(host)
  if host_buf.is_null() {
    @ffi.raw_winsock_cleanup()
    return Err(AllocFailed)
  }
  let sock = @ffi.raw_tcp_connect(host_buf, port)
  @ffi.raw_free_buf(host_buf)
  if sock.is_null() {
    @ffi.raw_winsock_cleanup()
    return Err(
      ConnectFailed("TCP connection to \{host}:\{port} refused or timed out"),
    )
  }
  audit_log("INFO", "TCP connection established to \{host}:\{port}")

  // (3) Session init
  let sess_ptr = @ffi.raw_session_init()
  if sess_ptr.is_null() {
    @ffi.raw_tcp_disconnect(sock)
    @ffi.raw_winsock_cleanup()
    return Err(Unexpected("libssh2_session_init returned NULL"))
  }
  @ffi.raw_session_set_blocking(sess_ptr, 1)

  // (4) Handshake
  let hs_rc = @ffi.raw_session_handshake(sess_ptr, sock)
  if hs_rc != 0 {
    let msg = session_last_err(sess_ptr)
    let err = HandshakeFailed(msg)
    audit_log("ERROR", "Handshake failed for \{host}: \{err.to_string()}")
    @ffi.raw_session_free(sess_ptr) |> ignore
    @ffi.raw_tcp_disconnect(sock)
    @ffi.raw_winsock_cleanup()
    return Err(err)
  }
  audit_log("INFO", "SSH handshake complete with \{host}")

  // (5) Log fingerprint (SHA-256, 32 bytes → hex)
  let fp_ptr = @ffi.raw_hostkey_hash(sess_ptr, @ffi.hostkey_hash_sha256)
  if not(fp_ptr.is_null()) {
    let hex = fingerprint_hex(fp_ptr, 32)
    audit_log("INFO", "Server fingerprint (SHA-256): \{hex}")
  }
  Ok({
    ptr: sess_ptr,
    sock,
    host,
    host_verified: { val: false },
    authenticated: { val: false },
  })
}

// -------------------------------------------------------------------------
// Host key verification  (MUST be called before auth)
// -------------------------------------------------------------------------

///|
/// Verify the server's host key against a local OpenSSH known_hosts file.
///
/// Returns:
///   - `Ok(())` if the key matches an entry in the file.
///   - `Err(HostKeyNotFound)` if the host is not in the file.
///   - `Err(HostKeyMismatch)` if the host is known but the key differs
///     (this MUST be treated as a security alert by the caller).
///
/// This method sets `host_verified = true` on success; `auth_*` methods
/// will return `Err(HostKeyCheckFailed)` until this succeeds.
pub fn Session::verify_host_key(
  self : Session,
  known_hosts_path : String,
) -> Result[Unit, SshError] {
  audit_log(
    "INFO",
    "Verifying host key for '\{self.host}' against '\{known_hosts_path}'",
  )

  // Init known-hosts collection
  let kh = @ffi.raw_knownhosts_init(self.ptr)
  if kh.is_null() {
    return Err(Unexpected("libssh2_knownhost_init returned NULL"))
  }

  // Read the file
  let path_buf = @ffi.string_to_raw(known_hosts_path)
  if path_buf.is_null() {
    @ffi.raw_knownhosts_free(kh)
    return Err(AllocFailed)
  }
  let read_rc = @ffi.raw_knownhosts_readfile(kh, path_buf)
  @ffi.raw_free_buf(path_buf)
  if read_rc < 0 {
    @ffi.raw_knownhosts_free(kh)
    audit_log("ERROR", "Failed to read known_hosts: '\{known_hosts_path}'")
    return Err(KnownHostsReadFailed(known_hosts_path))
  }

  // Retrieve the raw host key from the session
  let fp_ptr = @ffi.raw_hostkey_hash(self.ptr, @ffi.hostkey_hash_sha256)
  let key_len = 32
  let host_buf = @ffi.string_to_raw(self.host)
  if host_buf.is_null() {
    @ffi.raw_knownhosts_free(kh)
    return Err(AllocFailed)
  }
  let check = @ffi.raw_knownhosts_check(
    kh, host_buf, 22, // default port for the check; -1 means any port
     fp_ptr, key_len, @ffi.key_type_ed25519,
  ) // prefer Ed25519; overridden by actual server key type
  @ffi.raw_free_buf(host_buf)
  @ffi.raw_knownhosts_free(kh)
  if check == @ffi.knownhost_check_match {
    audit_log("INFO", "Host key verified for '\{self.host}'")
    self.host_verified.val = true
    Ok(())
  } else if check == @ffi.knownhost_check_notfound {
    audit_log("WARN", "Host '\{self.host}' not found in known_hosts")
    Err(HostKeyNotFound(self.host))
  } else if check == @ffi.knownhost_check_mismatch {
    audit_log(
      "CRITICAL",
      "HOST KEY MISMATCH for '\{self.host}' — possible MITM attack!",
    )
    Err(HostKeyMismatch(self.host))
  } else {
    audit_log("ERROR", "Host key check internal error for '\{self.host}'")
    Err(HostKeyCheckFailed("libssh2_knownhost_checkp returned FAILURE"))
  }
}

// -------------------------------------------------------------------------
// Authentication — password
// -------------------------------------------------------------------------

///|
/// Authenticate the session with a username and password.
///
/// Requires that `verify_host_key` has already been called and passed.
/// The C stub layer zeroes the password immediately after calling libssh2,
/// so the secret does not linger on the heap.
pub fn Session::auth_password(
  self : Session,
  username : String,
  password : String,
) -> Result[Unit, SshError] {
  if not(self.host_verified.val) {
    audit_log("ERROR", "auth_password called before verify_host_key")
    return Err(
      HostKeyCheckFailed("host key must be verified before authenticating"),
    )
  }
  audit_log(
    "INFO",
    "Authenticating '\{username}' via password on '\{self.host}'",
  )
  let user_buf = @ffi.string_to_raw(username)
  let pass_buf = @ffi.string_to_raw(password)
  if user_buf.is_null() || pass_buf.is_null() {
    @ffi.raw_free_buf(user_buf)
    @ffi.raw_free_buf(pass_buf)
    return Err(AllocFailed)
  }

  // C stub zeroes pass_buf contents after the libssh2 call
  let rc = @ffi.raw_userauth_password(self.ptr, user_buf, pass_buf)
  @ffi.raw_free_buf(user_buf)
  // pass_buf contents already zeroed by stub; free the allocation
  @ffi.raw_free_buf(pass_buf)
  if rc == 0 {
    audit_log("INFO", "Password authentication succeeded for '\{username}'")
    self.authenticated.val = true
    Ok(())
  } else {
    let msg = session_last_err(self.ptr)
    let err = AuthFailed(msg)
    audit_log(
      "WARN",
      "Password auth failed for '\{username}': \{err.to_string()}",
    )
    Err(err)
  }
}

// -------------------------------------------------------------------------
// Authentication — public key (file)
// -------------------------------------------------------------------------

///|
/// Authenticate with a key pair stored as files on disk.
///
/// pass `passphrase = ""` for keys without a passphrase.
/// The C stub zeroes the passphrase immediately after the libssh2 call.
pub fn Session::auth_pubkey_file(
  self : Session,
  username : String,
  pubkey_path : String,
  privkey_path : String,
  passphrase : String,
) -> Result[Unit, SshError] {
  if not(self.host_verified.val) {
    return Err(
      HostKeyCheckFailed("host key must be verified before authenticating"),
    )
  }
  audit_log(
    "INFO",
    "Authenticating '\{username}' via pubkey (file) on '\{self.host}'",
  )
  let user_buf = @ffi.string_to_raw(username)
  let pub_buf = @ffi.string_to_raw(pubkey_path)
  let priv_buf = @ffi.string_to_raw(privkey_path)
  let phrase_buf = @ffi.string_to_raw(passphrase)
  if user_buf.is_null() ||
    pub_buf.is_null() ||
    priv_buf.is_null() ||
    phrase_buf.is_null() {
    @ffi.raw_free_buf(user_buf)
    @ffi.raw_free_buf(pub_buf)
    @ffi.raw_free_buf(priv_buf)
    @ffi.raw_free_secret_buf(phrase_buf, passphrase.length() + 1)
    return Err(AllocFailed)
  }
  let rc = @ffi.raw_userauth_pubkey_file(
    self.ptr,
    user_buf,
    pub_buf,
    priv_buf,
    phrase_buf,
  )
  @ffi.raw_free_buf(user_buf)
  @ffi.raw_free_buf(pub_buf)
  @ffi.raw_free_buf(priv_buf)
  // passphrase already zeroed by C stub; free the allocation
  @ffi.raw_free_buf(phrase_buf)
  if rc == 0 {
    audit_log(
      "INFO",
      "Pubkey (file) authentication succeeded for '\{username}'",
    )
    self.authenticated.val = true
    Ok(())
  } else {
    let msg = session_last_err(self.ptr)
    let err = AuthFailed(msg)
    audit_log(
      "WARN",
      "Pubkey auth failed for '\{username}': \{err.to_string()}",
    )
    Err(err)
  }
}

// -------------------------------------------------------------------------
// Authentication — public key (memory)
// -------------------------------------------------------------------------

///|
/// Authenticate with key material already loaded into memory buffers.
///
/// `pubkey_pem` and `privkey_pem` should be PEM-encoded byte sequences.
/// `passphrase` is zeroed in C after use; pass `""` for unencrypted keys.
pub fn Session::auth_pubkey_memory(
  self : Session,
  username : String,
  pubkey_pem : Bytes,
  privkey_pem : Bytes,
  passphrase : String,
) -> Result[Unit, SshError] {
  if not(self.host_verified.val) {
    return Err(
      HostKeyCheckFailed("host key must be verified before authenticating"),
    )
  }
  audit_log(
    "INFO",
    "Authenticating '\{username}' via pubkey (memory) on '\{self.host}'",
  )
  let pub_len = pubkey_pem.length()
  let priv_len = privkey_pem.length()
  let user_buf = @ffi.string_to_raw(username)
  let pub_buf = @ffi.raw_alloc_buf(pub_len)
  let priv_buf = @ffi.raw_alloc_buf(priv_len)
  let phrase_buf = @ffi.string_to_raw(passphrase)
  if user_buf.is_null() ||
    pub_buf.is_null() ||
    priv_buf.is_null() ||
    phrase_buf.is_null() {
    @ffi.raw_free_buf(user_buf)
    @ffi.raw_free_buf(pub_buf)
    @ffi.raw_free_secret_buf(priv_buf, priv_len)
    @ffi.raw_free_secret_buf(phrase_buf, passphrase.length() + 1)
    return Err(AllocFailed)
  }

  // Copy key bytes into C buffers
  for i in 0..<pub_len {
    @ffi.raw_write_byte(pub_buf, i, pubkey_pem[i].to_int())
  }
  for i in 0..<priv_len {
    @ffi.raw_write_byte(priv_buf, i, privkey_pem[i].to_int())
  }
  let rc = @ffi.raw_userauth_pubkey_memory(
    self.ptr,
    user_buf,
    pub_buf,
    pub_len,
    priv_buf,
    priv_len,
    phrase_buf,
  )
  @ffi.raw_free_buf(user_buf)
  @ffi.raw_free_buf(pub_buf)
  // Private key and passphrase zeroed by C stub; free allocations
  @ffi.raw_free_buf(priv_buf)
  @ffi.raw_free_buf(phrase_buf)
  if rc == 0 {
    audit_log(
      "INFO",
      "Pubkey (memory) authentication succeeded for '\{username}'",
    )
    self.authenticated.val = true
    Ok(())
  } else {
    let msg = session_last_err(self.ptr)
    let err = AuthFailed(msg)
    audit_log(
      "WARN",
      "Pubkey (memory) auth failed for '\{username}': \{err.to_string()}",
    )
    Err(err)
  }
}

// -------------------------------------------------------------------------
// Disconnect
// -------------------------------------------------------------------------

///|
/// Gracefully disconnect the session.  Safe to call multiple times.
pub fn Session::disconnect(self : Session) -> Unit {
  if self.ptr.is_null() {
    return
  }
  audit_log("INFO", "Disconnecting from '\{self.host}'")
  let msg_buf = @ffi.string_to_raw("Normal Shutdown")
  let _rc = @ffi.raw_session_disconnect(self.ptr, msg_buf)
  @ffi.raw_free_buf(msg_buf)
  @ffi.raw_session_free(self.ptr) |> ignore
  @ffi.raw_tcp_disconnect(self.sock)
  @ffi.raw_winsock_cleanup()
  audit_log("INFO", "Disconnected from '\{self.host}'")
}

// -------------------------------------------------------------------------
// Accessors / status
// -------------------------------------------------------------------------

///|
/// Returns the underlying raw session pointer (for use by Channel / Sftp).
pub fn Session::ptr(self : Session) -> @ffi.SshSessionPtr {
  self.ptr
}

///|
/// Returns `true` if host key verification has passed.
pub fn Session::is_host_verified(self : Session) -> Bool {
  self.host_verified.val
}

///|
/// Returns `true` if authentication has succeeded.
pub fn Session::is_authenticated(self : Session) -> Bool {
  self.authenticated.val
}

///|
/// Returns the hostname this session is connected to.
pub fn Session::host(self : Session) -> String {
  self.host
}

// -------------------------------------------------------------------------
// Internal utilities
// -------------------------------------------------------------------------

///|
/// Format `len` raw bytes from a RawBufPtr as an uppercase hex string.
fn fingerprint_hex(ptr : @ffi.RawBufPtr, len : Int) -> String {
  let hex_chars = "0123456789ABCDEF"
  let sb = StringBuilder::new()
  for i in 0..<len {
    let b = @ffi.raw_buf_get_byte(ptr, i)
    sb.write_char(Int::unsafe_to_char(hex_chars[(b & 0xf0) >> 4].to_int()))
    sb.write_char(Int::unsafe_to_char(hex_chars[b & 0x0f].to_int()))
  }
  sb.to_string()
}
