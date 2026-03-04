// sftp.mbt — Safe SFTP subsystem wrapper.
//
// Provides file upload and download over an authenticated Session.
// All resource management is explicit: open → read/write → close → shutdown.

///|
/// Unix permission bits for regular files (rw-r--r--).
pub let file_mode_644 : Int = 0o644

///|
/// Unix permission bits for regular files (rw-rw-r--).
pub let file_mode_664 : Int = 0o664

///|
/// Default SFTP I/O buffer size (32 KiB).
let sftp_buf_size : Int = 32768

///|
/// An active SFTP subsystem handle.
pub(all) struct Sftp {
  priv ptr : @ffi.SshSftpPtr
  priv session : Session
}

///|
/// An open SFTP file handle.
pub(all) struct SftpHandle {
  priv ptr : @ffi.SshSftpHandlePtr
  priv sftp : Sftp
}

// -------------------------------------------------------------------------
// Open / shutdown SFTP subsystem
// -------------------------------------------------------------------------

///|
/// Initialize the SFTP subsystem on an authenticated session.
pub fn Session::open_sftp(self : Session) -> Result[Sftp, SshError] {
  if not(self.is_authenticated()) {
    return Err(SftpError("must authenticate before using SFTP"))
  }
  let sftp_ptr = @ffi.raw_sftp_init(self.ptr())
  if sftp_ptr.is_null() {
    let msg = session_last_err(self.ptr())
    let err = SftpError(msg)
    audit_log("ERROR", "sftp_init failed: \{err.to_string()}")
    return Err(err)
  }
  audit_log("INFO", "SFTP subsystem initialized on '\{self.host()}'")
  Ok({ ptr: sftp_ptr, session: self })
}

///|
/// Shut down the SFTP subsystem.
pub fn Sftp::shutdown(self : Sftp) -> Unit {
  let _rc = @ffi.raw_sftp_shutdown(self.ptr)
  audit_log("INFO", "SFTP subsystem shut down on '\{self.session.host()}'")
}

// -------------------------------------------------------------------------
// File open
// -------------------------------------------------------------------------

///|
/// Open a remote file for reading.
pub fn Sftp::open_read(
  self : Sftp,
  path : String,
) -> Result[SftpHandle, SshError] {
  self.open_file(path, @ffi.sftp_fxf_read, 0, @ffi.sftp_openfile)
}

///|
/// Open (or create) a remote file for writing.  Truncates if it exists.
pub fn Sftp::open_write(
  self : Sftp,
  path : String,
) -> Result[SftpHandle, SshError] {
  let flags = @ffi.sftp_fxf_write | @ffi.sftp_fxf_creat | @ffi.sftp_fxf_trunc
  self.open_file(path, flags, file_mode_644, @ffi.sftp_openfile)
}

///|
/// Open (or create) a remote file for appending.
pub fn Sftp::open_append(
  self : Sftp,
  path : String,
) -> Result[SftpHandle, SshError] {
  let flags = @ffi.sftp_fxf_write | @ffi.sftp_fxf_creat | @ffi.sftp_fxf_append
  self.open_file(path, flags, file_mode_644, @ffi.sftp_openfile)
}

///|
fn Sftp::open_file(
  self : Sftp,
  path : String,
  flags : Int,
  mode : Int,
  open_type : Int,
) -> Result[SftpHandle, SshError] {
  let path_buf = @ffi.string_to_raw(path)
  if path_buf.is_null() {
    return Err(AllocFailed)
  }
  let handle_ptr = @ffi.raw_sftp_open(
    self.ptr,
    path_buf,
    flags,
    mode,
    open_type,
  )
  @ffi.raw_free_buf(path_buf)
  if handle_ptr.is_null() {
    let sftp_err = @ffi.raw_sftp_last_error(self.ptr)
    audit_log("ERROR", "sftp_open failed for '\{path}' (sftp_err=\{sftp_err})")
    return Err(SftpError("sftp_open '\{path}' failed (code \{sftp_err})"))
  }
  audit_log("INFO", "SFTP file opened: '\{path}'")
  Ok({ ptr: handle_ptr, sftp: self })
}

// -------------------------------------------------------------------------
// Read
// -------------------------------------------------------------------------

///|
/// Read up to `max_bytes` bytes from the file handle.
/// Returns an empty Bytes when EOF is reached.
pub fn SftpHandle::read(
  self : SftpHandle,
  max_bytes : Int,
) -> Result[Bytes, SshError] {
  let chunk = if max_bytes > 0 { max_bytes } else { sftp_buf_size }
  let buf = @ffi.raw_alloc_buf(chunk)
  if buf.is_null() {
    return Err(AllocFailed)
  }
  let n = @ffi.raw_sftp_read(self.ptr, buf, chunk)
  if n < 0 {
    let sftp_err = @ffi.raw_sftp_last_error(self.sftp.ptr)
    @ffi.raw_free_buf(buf)
    return Err(SftpError("sftp_read failed (rc=\{n}, sftp_err=\{sftp_err})"))
  }
  let result = @ffi.raw_buf_to_bytes(buf, n)
  @ffi.raw_free_buf(buf)
  Ok(result)
}

///|
/// Read the entire remote file into a Bytes value.
pub fn SftpHandle::read_all(self : SftpHandle) -> Result[Bytes, SshError] {
  let parts : Array[Bytes] = []
  let mut total = 0
  let mut running = true
  while running {
    match self.read(sftp_buf_size) {
      Err(e) => return Err(e)
      Ok(chunk) => {
        let n = chunk.length()
        if n == 0 {
          running = false
        } else {
          parts.push(chunk)
          total = total + n
        }
      }
    }
  }
  // Concatenate all chunks
  let result : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for chunk in parts {
    for i in 0..<chunk.length() {
      result[offset] = chunk[i]
      offset = offset + 1
    }
  }
  Ok(Bytes::from_array(result))
}

// -------------------------------------------------------------------------
// Write
// -------------------------------------------------------------------------

///|
/// Private: write `length` bytes from `data` starting at `offset`.
/// Uses self.sftp.ptr for richer SFTP error codes on failure.
fn SftpHandle::write_slice(
  self : SftpHandle,
  data : Bytes,
  offset : Int,
  length : Int,
) -> Result[Int, SshError] {
  if length == 0 {
    return Ok(0)
  }
  let buf = @ffi.raw_alloc_buf(length)
  if buf.is_null() {
    return Err(AllocFailed)
  }
  for i in 0..<length {
    @ffi.raw_write_byte(buf, i, data[offset + i].to_int())
  }
  let rc = @ffi.raw_sftp_write(self.ptr, buf, length)
  let sftp_err = @ffi.raw_sftp_last_error(self.sftp.ptr)
  @ffi.raw_free_buf(buf)
  if rc < 0 {
    return Err(SftpError("sftp_write failed (rc=\{rc}, sftp_err=\{sftp_err})"))
  }
  Ok(rc)
}

///|
/// Write `data` to the file handle.
/// Returns bytes actually written.
pub fn SftpHandle::write(
  self : SftpHandle,
  data : Bytes,
) -> Result[Int, SshError] {
  self.write_slice(data, 0, data.length())
}

///|
/// Convenience: write an entire Bytes in a loop until all bytes are sent.
pub fn SftpHandle::write_all(
  self : SftpHandle,
  data : Bytes,
) -> Result[Unit, SshError] {
  let total = data.length()
  let mut sent = 0
  while sent < total {
    match self.write_slice(data, sent, total - sent) {
      Err(e) => return Err(e)
      Ok(n) => sent = sent + n
    }
  }
  Ok(())
}

// -------------------------------------------------------------------------
// Close
// -------------------------------------------------------------------------

///|
/// Close the file handle.
pub fn SftpHandle::close(self : SftpHandle) -> Unit {
  let _rc = @ffi.raw_sftp_close(self.ptr)
  audit_log("INFO", "SFTP handle closed")
}
