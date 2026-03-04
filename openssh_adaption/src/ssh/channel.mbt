// channel.mbt — Safe wrapper around a libssh2 session channel.
//
// A Channel represents one SSH channel (session channel for exec/shell,
// or a direct-tcpip forwarding channel).  After exec() the caller reads
// stdout / stderr through read_stdout / read_stderr.  close() sends EOF,
// waits for the server to close, then frees the channel.

// bytes_to_string — treat each byte as a Unicode code point (correct for
// ASCII and Latin-1; sufficient for typical SSH command output).

///|
fn bytes_to_string(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i in 0..<b.length() {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// Default read buffer size (16 KiB).
let default_read_buf_size : Int = 16384

///|
/// Represents an open SSH channel.
pub(all) struct Channel {
  priv ptr : @ffi.SshChannelPtr
  priv session : Session
}

// -------------------------------------------------------------------------
// Opening a channel
// -------------------------------------------------------------------------

///|
/// Open a new session channel on the given (authenticated) Session.
pub fn Session::open_channel(self : Session) -> Result[Channel, SshError] {
  if not(self.is_authenticated()) {
    return Err(ChannelError("must authenticate before opening a channel"))
  }
  let ch_ptr = @ffi.raw_channel_open_session(self.ptr())
  if ch_ptr.is_null() {
    let msg = session_last_err(self.ptr())
    let err = ChannelError(msg)
    audit_log("ERROR", "channel_open_session failed: \{err.to_string()}")
    return Err(err)
  }
  audit_log("INFO", "Channel opened on '\{self.host()}'")
  Ok({ ptr: ch_ptr, session: self })
}

// -------------------------------------------------------------------------
// Exec
// -------------------------------------------------------------------------

///|
/// Execute a command on the remote host via this channel.
///
/// A channel can only exec one command; open a new channel for each command.
pub fn Channel::exec(self : Channel, cmd : String) -> Result[Unit, SshError] {
  audit_log("INFO", "Executing remote command: \{cmd}")
  let cmd_buf = @ffi.string_to_raw(cmd)
  if cmd_buf.is_null() {
    return Err(AllocFailed)
  }
  let rc = @ffi.raw_channel_exec(self.ptr, cmd_buf)
  @ffi.raw_free_buf(cmd_buf)
  if rc != 0 {
    let msg = session_last_err(self.session.ptr())
    let err = ChannelError(msg)
    audit_log("ERROR", "channel_exec failed: \{err.to_string()}")
    return Err(err)
  }
  Ok(())
}

// -------------------------------------------------------------------------
// Read / write
// -------------------------------------------------------------------------

///|
/// Private: drain one channel stream until EOF and return the data as a String.
///
/// use_stderr = false → stdout (stream 0); true → stderr.
/// LIBSSH2_ERROR_EAGAIN (-37) would appear only in non-blocking mode;
/// in blocking mode any negative return value is a real error.
fn Channel::read_stream(
  self : Channel,
  use_stderr : Bool,
  buf_size : Int,
) -> Result[String, SshError] {
  let chunk = if buf_size > 0 { buf_size } else { default_read_buf_size }
  let buf = @ffi.raw_alloc_buf(chunk)
  if buf.is_null() {
    return Err(AllocFailed)
  }
  let acc = StringBuilder::new()
  let mut running = true
  while running {
    let n = if use_stderr {
      @ffi.raw_channel_read_stderr(self.ptr, buf, chunk)
    } else {
      @ffi.raw_channel_read(self.ptr, buf, chunk)
    }
    if n > 0 {
      acc.write_string(bytes_to_string(@ffi.raw_buf_to_bytes(buf, n)))
    } else if n == 0 {
      running = false
    } else {
      @ffi.raw_free_buf(buf)
      let label = if use_stderr { "stderr " } else { "" }
      return Err(ChannelError("\{label}read error (rc=\{n})"))
    }
  }
  @ffi.raw_free_buf(buf)
  Ok(acc.to_string())
}

///|
/// Read all available stdout data from the channel into a String.
///
/// Drains the channel until EOF or error.  buf_size controls the read
/// chunk size; 0 uses the default (16 KiB).
pub fn Channel::read_stdout(
  self : Channel,
  buf_size : Int,
) -> Result[String, SshError] {
  self.read_stream(false, buf_size)
}

///|
/// Read all available stderr data from the channel into a String.
pub fn Channel::read_stderr(
  self : Channel,
  buf_size : Int,
) -> Result[String, SshError] {
  self.read_stream(true, buf_size)
}

///|
/// Write data to the channel's stdin.
/// Returns the number of bytes actually sent.
pub fn Channel::write(self : Channel, data : Bytes) -> Result[Int, SshError] {
  let n = data.length()
  if n == 0 {
    return Ok(0)
  }
  let buf = @ffi.raw_alloc_buf(n)
  if buf.is_null() {
    return Err(AllocFailed)
  }
  for i in 0..<n {
    @ffi.raw_write_byte(buf, i, data[i].to_int())
  }
  let rc = @ffi.raw_channel_write(self.ptr, buf, n)
  @ffi.raw_free_buf(buf)
  if rc < 0 {
    return Err(ChannelError("write error (rc=\{rc})"))
  }
  Ok(rc)
}

// -------------------------------------------------------------------------
// Close / exit status
// -------------------------------------------------------------------------

///|
/// Returns the remote process exit status.  Only valid after close().
pub fn Channel::exit_status(self : Channel) -> Int {
  @ffi.raw_channel_get_exit_status(self.ptr)
}

///|
/// Close the channel: send EOF, wait for server close, free resources.
pub fn Channel::close(self : Channel) -> Unit {
  let _eof = @ffi.raw_channel_send_eof(self.ptr)
  let _wait_eof = @ffi.raw_channel_wait_eof(self.ptr)
  let _close = @ffi.raw_channel_close(self.ptr)
  let _wait_closed = @ffi.raw_channel_wait_closed(self.ptr)
  let exit_rc = @ffi.raw_channel_get_exit_status(self.ptr)
  audit_log("INFO", "Channel closed (exit status: \{exit_rc})")
  @ffi.raw_channel_free(self.ptr) |> ignore
}

// ------------------------------------------------------------------------
// Convenience: exec + collect output in one call
// -------------------------------------------------------------------------

///|
/// Execute `cmd` and return `(stdout, stderr, exit_code)`.
pub fn Channel::run(
  self : Channel,
  cmd : String,
) -> Result[(String, String, Int), SshError] {
  match self.exec(cmd) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let stdout = match self.read_stdout(0) {
    Err(e) => return Err(e)
    Ok(s) => s
  }
  let stderr = match self.read_stderr(0) {
    Err(e) => return Err(e)
    Ok(s) => s
  }
  let code = self.exit_status()
  self.close()
  Ok((stdout, stderr, code))
}
