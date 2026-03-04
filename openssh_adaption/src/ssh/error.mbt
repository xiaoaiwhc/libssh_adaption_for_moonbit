// error.mbt — SshError: the unified error type for the ssh wrapper package.
//
// Every public function in this package that can fail returns
// Result[T, SshError], letting callers pattern-match on the exact failure
// category rather than interpreting raw integer codes.

///|
/// All error conditions that can be returned by the ssh wrapper.
pub(all) enum SshError {
  /// libssh2_init returned non-zero.
  InitFailed(String)
  /// Winsock initialization failed.
  WinsockFailed(Int)
  /// TCP-level connection to the target host failed.
  ConnectFailed(String)
  /// SSH protocol handshake failed after TCP connect.
  HandshakeFailed(String)
  /// Host key does not match any entry in the known-hosts file.
  HostKeyNotFound(String)
  /// Host key is listed in known-hosts but the value no longer matches
  /// (possible man-in-the-middle attack).
  HostKeyMismatch(String)
  /// Host-key check encountered an internal error.
  HostKeyCheckFailed(String)
  /// Could not read / parse the known-hosts file.
  KnownHostsReadFailed(String)
  /// SSH algorithm is not on the allowed list.
  AlgoRejected(String)
  /// Authentication failed (wrong credentials or method not accepted).
  AuthFailed(String)
  /// A channel could not be opened or an operation on a channel failed.
  ChannelError(String)
  /// An SFTP subsystem error occurred.
  SftpError(String)
  /// Memory allocation failed in the C layer.
  AllocFailed
  /// Any unexpected internal error with a description.
  Unexpected(String)
} derive(Eq)

///|
/// Human-readable representation of an SshError.
pub fn SshError::to_string(self : SshError) -> String {
  match self {
    InitFailed(msg) => "SSH init failed: \{msg}"
    WinsockFailed(code) => "Winsock init failed (code \{code})"
    ConnectFailed(msg) => "TCP connect failed: \{msg}"
    HandshakeFailed(msg) => "SSH handshake failed: \{msg}"
    HostKeyNotFound(host) =>
      "Unknown host key for '\{host}' — add to known_hosts first"
    HostKeyMismatch(host) =>
      "HOST KEY MISMATCH for '\{host}' — possible MITM attack!"
    HostKeyCheckFailed(msg) => "Host key check error: \{msg}"
    KnownHostsReadFailed(p) => "Could not read known_hosts file '\{p}'"
    AlgoRejected(algo) => "Algorithm blocked by allow-list: '\{algo}'"
    AuthFailed(msg) => "Authentication failed: \{msg}"
    ChannelError(msg) => "Channel error: \{msg}"
    SftpError(msg) => "SFTP error: \{msg}"
    AllocFailed => "Memory allocation failed"
    Unexpected(msg) => "Unexpected error: \{msg}"
  }
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

///|
/// Retrieve the session's last error message as a String.
fn session_last_err(session : @ffi.SshSessionPtr) -> String {
  let buf = @ffi.raw_alloc_buf(512)
  if buf.is_null() {
    return "(could not retrieve error message)"
  }
  let _ = @ffi.raw_session_last_error(session, buf, 512)
  let msg = @ffi.raw_buf_to_string(buf, 512)
  @ffi.raw_free_buf(buf)
  msg
}
