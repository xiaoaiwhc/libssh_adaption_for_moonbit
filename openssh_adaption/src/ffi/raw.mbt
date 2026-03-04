// raw.mbt — `extern "C"` bindings that map directly to symbols in c_stub.c.
//
// Every function here corresponds 1-to-1 with a real C symbol (no macros).
// These are intentionally low-level and unsafe: they do no bounds checking,
// no error handling, and no lifetime management.  The `ssh` package wraps
// these into safe MoonBit abstractions.
//
// Naming convention:  raw_<stub_name> to avoid shadowing stdlib names.

// -------------------------------------------------------------------------
// Global init / exit
// -------------------------------------------------------------------------

///|
/// Initialize the libssh2 library.  Must be called once before any other
/// libssh2 function.  flags = 0 for standard initialization.
/// Returns 0 on success.
pub extern "C" fn raw_libssh2_init(flags : Int) -> Int = "stub_libssh2_init"

///|
/// Tear down the libssh2 library.  Call once when finished.
pub extern "C" fn raw_libssh2_exit() -> Unit = "stub_libssh2_exit"

///|
/// Returns a pointer to the libssh2 version string (static C string).
/// Use raw_buf_get_byte / build a String from this address.
pub extern "C" fn raw_libssh2_version() -> RawBufPtr = "stub_libssh2_version"

// -------------------------------------------------------------------------
// Session lifecycle
// -------------------------------------------------------------------------

///|
/// Allocate and initialize a new SSH session.
/// Returns a null SshSessionPtr on failure.
pub extern "C" fn raw_session_init() -> SshSessionPtr = "stub_session_init"

///|
/// Set blocking/non-blocking mode.  blocking = 1 → blocking (default).
pub extern "C" fn raw_session_set_blocking(
  session : SshSessionPtr,
  blocking : Int,
) -> Unit = "stub_session_set_blocking"

///|
/// Perform the SSH protocol handshake over an already-connected TCP socket.
/// Returns 0 on success.
pub extern "C" fn raw_session_handshake(
  session : SshSessionPtr,
  sock : SocketHandle,
) -> Int = "stub_session_handshake"

///|
/// Send an SSH disconnect message and close the session gracefully.
/// description is a raw C string pointer (use stub_str_to_buf or a literal).
pub extern "C" fn raw_session_disconnect(
  session : SshSessionPtr,
  description : RawBufPtr,
) -> Int = "stub_session_disconnect"

///|
/// Free all resources associated with a session.
pub extern "C" fn raw_session_free(session : SshSessionPtr) -> Int = "stub_session_free"

///|
/// Retrieve the last error message for the session into out_buf (max out_len bytes).
/// Returns the libssh2 error code.
pub extern "C" fn raw_session_last_error(
  session : SshSessionPtr,
  out_buf : RawBufPtr,
  out_len : Int,
) -> Int = "stub_session_last_error"

// -------------------------------------------------------------------------
// Host key / known-hosts
// -------------------------------------------------------------------------

///|
/// Returns a raw pointer to the host key hash bytes.
/// hash_type: HOSTKEY_HASH_MD5 (16 bytes), SHA1 (20 bytes), SHA256 (32 bytes).
pub extern "C" fn raw_hostkey_hash(
  session : SshSessionPtr,
  hash_type : Int,
) -> RawBufPtr = "stub_hostkey_hash"

///|
/// Allocate a new LIBSSH2_KNOWNHOSTS collection.
pub extern "C" fn raw_knownhosts_init(
  session : SshSessionPtr,
) -> SshKnownHostsPtr = "stub_knownhosts_init"

///|
/// Read an OpenSSH known_hosts file into the collection.
/// Returns >= 0 (number of entries) on success, negative on error.
pub extern "C" fn raw_knownhosts_readfile(
  kh : SshKnownHostsPtr,
  path : RawBufPtr,
) -> Int = "stub_knownhosts_readfile"

///|
/// Check a host+key against the known-hosts collection.
/// Returns one of the KNOWNHOST_CHECK_* constants.
pub extern "C" fn raw_knownhosts_check(
  kh : SshKnownHostsPtr,
  host : RawBufPtr,
  port : Int,
  key : RawBufPtr,
  key_len : Int,
  key_type : Int,
) -> Int = "stub_knownhosts_check"

///|
/// Free a known-hosts collection.
pub extern "C" fn raw_knownhosts_free(kh : SshKnownHostsPtr) -> Unit = "stub_knownhosts_free"

// -------------------------------------------------------------------------
// Authentication
// -------------------------------------------------------------------------

///|
/// Authenticate with a password.
/// username / password are raw C string pointers (use stub_str_to_buf).
/// The C stub zeroes the password immediately after calling libssh2.
/// Returns 0 on success.
pub extern "C" fn raw_userauth_password(
  session : SshSessionPtr,
  username : RawBufPtr,
  password : RawBufPtr,
) -> Int = "stub_userauth_password"

///|
/// Authenticate with a key pair stored in files.
/// The C stub zeroes the passphrase immediately after calling libssh2.
pub extern "C" fn raw_userauth_pubkey_file(
  session : SshSessionPtr,
  username : RawBufPtr,
  pubkey_path : RawBufPtr,
  privkey_path : RawBufPtr,
  passphrase : RawBufPtr,
) -> Int = "stub_userauth_pubkey_file"

///|
/// Authenticate with key material held in memory buffers.
/// The C stub zeroes privkey_data and passphrase after use.
pub extern "C" fn raw_userauth_pubkey_memory(
  session : SshSessionPtr,
  username : RawBufPtr,
  pubkey_data : RawBufPtr,
  pubkey_len : Int,
  privkey_data : RawBufPtr,
  privkey_len : Int,
  passphrase : RawBufPtr,
) -> Int = "stub_userauth_pubkey_memory"

// -------------------------------------------------------------------------
// Channel — exec / read / write
// -------------------------------------------------------------------------

///|
/// Open a new session channel.  Returns null on failure.
pub extern "C" fn raw_channel_open_session(
  session : SshSessionPtr,
) -> SshChannelPtr = "stub_channel_open_session"

///|
/// Execute a command on the channel.  command is a raw C string pointer.
/// Returns 0 on success.
pub extern "C" fn raw_channel_exec(
  channel : SshChannelPtr,
  command : RawBufPtr,
) -> Int = "stub_channel_exec"

///|
/// Read stdout from the channel into buf.  Returns bytes read or negative error.
pub extern "C" fn raw_channel_read(
  channel : SshChannelPtr,
  buf : RawBufPtr,
  buf_len : Int,
) -> Int = "stub_channel_read"

///|
/// Read stderr from the channel into buf.
pub extern "C" fn raw_channel_read_stderr(
  channel : SshChannelPtr,
  buf : RawBufPtr,
  buf_len : Int,
) -> Int = "stub_channel_read_stderr"

///|
/// Write data to the channel.  Returns bytes written or negative error.
pub extern "C" fn raw_channel_write(
  channel : SshChannelPtr,
  buf : RawBufPtr,
  buf_len : Int,
) -> Int = "stub_channel_write"

///|
pub extern "C" fn raw_channel_send_eof(channel : SshChannelPtr) -> Int = "stub_channel_send_eof"

///|
pub extern "C" fn raw_channel_wait_eof(channel : SshChannelPtr) -> Int = "stub_channel_wait_eof"

///|
pub extern "C" fn raw_channel_close(channel : SshChannelPtr) -> Int = "stub_channel_close"

///|
pub extern "C" fn raw_channel_wait_closed(channel : SshChannelPtr) -> Int = "stub_channel_wait_closed"

///|
pub extern "C" fn raw_channel_get_exit_status(channel : SshChannelPtr) -> Int = "stub_channel_get_exit_status"

///|
pub extern "C" fn raw_channel_free(channel : SshChannelPtr) -> Int = "stub_channel_free"

// -------------------------------------------------------------------------
// Channel — port-forwarding
// -------------------------------------------------------------------------

///|
/// Open a forwarded TCP connection to remote_host:remote_port through the session.
/// Returns a channel that can be used like a bidirectional socket.
pub extern "C" fn raw_channel_direct_tcpip(
  session : SshSessionPtr,
  remote_host : RawBufPtr,
  remote_port : Int,
) -> SshChannelPtr = "stub_channel_direct_tcpip"

// -------------------------------------------------------------------------
// SFTP
// -------------------------------------------------------------------------

///|
/// Initialize the SFTP subsystem.  Returns null on failure.
pub extern "C" fn raw_sftp_init(session : SshSessionPtr) -> SshSftpPtr = "stub_sftp_init"

///|
/// Shut down the SFTP subsystem.
pub extern "C" fn raw_sftp_shutdown(sftp : SshSftpPtr) -> Int = "stub_sftp_shutdown"

///|
/// Open a remote file or directory.
/// flags: combination of SFTP_FXF_* constants.
/// mode: Unix permission bits (e.g., 0o644).
/// open_type: SFTP_OPENFILE or SFTP_OPENDIR.
pub extern "C" fn raw_sftp_open(
  sftp : SshSftpPtr,
  path : RawBufPtr,
  flags : Int,
  mode : Int,
  open_type : Int,
) -> SshSftpHandlePtr = "stub_sftp_open"

///|
/// Read up to buf_len bytes into buf.  Returns bytes read or negative error.
pub extern "C" fn raw_sftp_read(
  handle : SshSftpHandlePtr,
  buf : RawBufPtr,
  buf_len : Int,
) -> Int = "stub_sftp_read"

///|
/// Write buf_len bytes from buf.  Returns bytes written or negative error.
pub extern "C" fn raw_sftp_write(
  handle : SshSftpHandlePtr,
  buf : RawBufPtr,
  buf_len : Int,
) -> Int = "stub_sftp_write"

///|
/// Close an SFTP file/dir handle.
pub extern "C" fn raw_sftp_close(handle : SshSftpHandlePtr) -> Int = "stub_sftp_close"

///|
/// Returns the last SFTP subsystem error code.
pub extern "C" fn raw_sftp_last_error(sftp : SshSftpPtr) -> Int64 = "stub_sftp_last_error"

// -------------------------------------------------------------------------
// Buffer / memory helpers
// -------------------------------------------------------------------------

///|
/// Allocate a zeroed C heap buffer of `size` bytes.
/// Returns a RawBufPtr (null on allocation failure).
pub extern "C" fn raw_alloc_buf(size : Int) -> RawBufPtr = "stub_alloc_buf"

///|
/// Free a buffer allocated with raw_alloc_buf.
pub extern "C" fn raw_free_buf(ptr : RawBufPtr) -> Unit = "stub_free_buf"

///|
/// Zero-then-free a secret buffer.
pub extern "C" fn raw_free_secret_buf(ptr : RawBufPtr, size : Int) -> Unit = "stub_free_secret_buf"

///|
/// Read a single byte from a raw pointer at the given offset.
pub extern "C" fn raw_buf_get_byte(ptr : RawBufPtr, offset : Int) -> Int = "stub_buf_get_byte"

///|
/// Copy a C string from src_ptr into dst (at most dst_len-1 chars + NUL).
/// Returns number of bytes copied.
pub extern "C" fn raw_buf_copy_str(
  src_ptr : RawBufPtr,
  dst : RawBufPtr,
  dst_len : Int,
) -> Int = "stub_buf_copy_str"

///|
/// Allocate a C string copy of str.  Free with raw_free_buf when done.
pub extern "C" fn raw_str_to_buf(str : RawBufPtr) -> RawBufPtr = "stub_str_to_buf"

// -------------------------------------------------------------------------
// Windows TCP helpers
// -------------------------------------------------------------------------

///|
/// Initialize Winsock.  Must be called before any socket operation on Windows.
/// Returns 0 on success.
pub extern "C" fn raw_winsock_init() -> Int = "stub_winsock_init"

///|
/// Finalize Winsock.
pub extern "C" fn raw_winsock_cleanup() -> Unit = "stub_winsock_cleanup"

///|
/// Create a TCP connection to host:port.
/// Returns a SocketHandle (null on failure).
pub extern "C" fn raw_tcp_connect(host : RawBufPtr, port : Int) -> SocketHandle = "stub_tcp_connect"

///|
/// Close a TCP socket.
pub extern "C" fn raw_tcp_disconnect(sock : SocketHandle) -> Unit = "stub_tcp_disconnect"

// -------------------------------------------------------------------------
// String/buffer interop helpers
// -------------------------------------------------------------------------

///|
/// Write a single byte into a raw C buffer at the given offset.
pub extern "C" fn raw_write_byte(
  ptr : RawBufPtr,
  offset : Int,
  value : Int,
) -> Unit = "stub_write_byte"

///|
/// NUL-terminate a C buffer at offset.
pub extern "C" fn raw_nul_terminate(ptr : RawBufPtr, offset : Int) -> Unit = "stub_nul_terminate"

///|
/// Allocate a C string buffer from a MoonBit String (UTF-8 encoded).
/// The caller MUST free the result with raw_free_buf when done.
/// Returns a null RawBufPtr on allocation failure.
pub fn string_to_raw(s : String) -> RawBufPtr {
  // @utf8.encode produces UTF-8 encoded bytes
  let bytes = @utf8.encode(s)
  let n = bytes.length()
  let buf = raw_alloc_buf(n + 1)
  if buf.is_null() {
    return buf
  }
  for i in 0..<n {
    raw_write_byte(buf, i, bytes[i].to_int())
  }
  raw_nul_terminate(buf, n)
  buf
}

///|
/// Read a null-terminated C string from a raw pointer into a MoonBit String.
/// max_len: safety cap on how many bytes to scan.
pub fn raw_buf_to_string(ptr : RawBufPtr, max_len : Int) -> String {
  if ptr.is_null() {
    return ""
  }
  let sb = StringBuilder::new()
  for i in 0..<max_len {
    let b = raw_buf_get_byte(ptr, i)
    if b <= 0 {
      break
    }
    sb.write_char(Int::unsafe_to_char(b))
  }
  sb.to_string()
}

///|
/// Copy raw C buffer bytes into a MoonBit Bytes value (len bytes).
pub fn raw_buf_to_bytes(ptr : RawBufPtr, len : Int) -> Bytes {
  let arr : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i in 0..<len {
    arr[i] = raw_buf_get_byte(ptr, i).to_byte()
  }
  Bytes::from_array(arr)
}
