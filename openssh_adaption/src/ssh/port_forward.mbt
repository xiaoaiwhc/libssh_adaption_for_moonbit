// port_forward.mbt — TCP port-forwarding via SSH (direct-tcpip).
//
// Opens a direct-tcpip channel that the caller reads/writes like a plain
// TCP stream, forwarded to remote_host:remote_port through the SSH session.
//
// Usage:
//   let fwd = session.direct_tcpip("database.internal", 5432)?
//   fwd.write(query_bytes)?
//   let resp = fwd.read_stdout(0)?
//   fwd.close()

///|
/// Open a forwarded TCP channel to `remote_host`:`remote_port` through
/// the authenticated session.
///
/// The returned `Channel` can be used for bidirectional I/O exactly like
/// a raw TCP socket — use `write` to send data and `read_stdout` to receive.
pub fn Session::direct_tcpip(
  self : Session,
  remote_host : String,
  remote_port : Int,
) -> Result[Channel, SshError] {
  if not(self.is_authenticated()) {
    return Err(
      ChannelError("must authenticate before opening a port-forward channel"),
    )
  }
  audit_log(
    "INFO",
    "Opening direct-tcpip to \{remote_host}:\{remote_port} via '\{self.host()}'",
  )
  let host_buf = @ffi.string_to_raw(remote_host)
  if host_buf.is_null() {
    return Err(AllocFailed)
  }
  let ch_ptr = @ffi.raw_channel_direct_tcpip(self.ptr(), host_buf, remote_port)
  @ffi.raw_free_buf(host_buf)
  if ch_ptr.is_null() {
    let msg = session_last_err(self.ptr())
    let err = ChannelError(msg)
    audit_log(
      "ERROR",
      "direct_tcpip to \{remote_host}:\{remote_port} failed: \{err.to_string()}",
    )
    return Err(err)
  }
  audit_log(
    "INFO",
    "direct-tcpip channel open to \{remote_host}:\{remote_port}",
  )
  Ok({ ptr: ch_ptr, session: self })
}
