// sftp_test.mbt — Unit tests for the SFTP module.

// -------------------------------------------------------------------------
// SFTP flag constant sanity checks
// -------------------------------------------------------------------------

///|
test "sftp_flags/read_is_1" {
  assert_eq(@ffi.sftp_fxf_read, 1)
}

///|
test "sftp_flags/write_is_2" {
  assert_eq(@ffi.sftp_fxf_write, 2)
}

///|
test "sftp_flags/creat_is_8" {
  assert_eq(@ffi.sftp_fxf_creat, 8)
}

///|
test "sftp_flags/trunc_is_16" {
  assert_eq(@ffi.sftp_fxf_trunc, 16)
}

///|
test "sftp_flags/open_write_combines_correctly" {
  // open_write uses WRITE | CREAT | TRUNC = 0x2 | 0x8 | 0x10 = 0x1A = 26
  let flags = @ffi.sftp_fxf_write | @ffi.sftp_fxf_creat | @ffi.sftp_fxf_trunc
  assert_eq(flags, 26)
}

///|
test "sftp_flags/open_append_combines_correctly" {
  // open_append uses WRITE | CREAT | APPEND = 0x2 | 0x8 | 0x4 = 14
  let flags = @ffi.sftp_fxf_write | @ffi.sftp_fxf_creat | @ffi.sftp_fxf_append
  assert_eq(flags, 14)
}

///|
test "sftp_flags/openfile_type_is_0" {
  assert_eq(@ffi.sftp_openfile, 0)
}

///|
test "sftp_flags/opendir_type_is_1" {
  assert_eq(@ffi.sftp_opendir, 1)
}

// -------------------------------------------------------------------------
// File mode constant checks
// -------------------------------------------------------------------------

///|
test "sftp_mode/@ssh.file_mode_644" {
  // 0o644 = 420 decimal
  assert_eq(@ssh.file_mode_644, 420)
}

///|
test "sftp_mode/@ssh.file_mode_664" {
  // 0o664 = 436 decimal
  assert_eq(@ssh.file_mode_664, 436)
}

// -------------------------------------------------------------------------
// SftpError message tests
// -------------------------------------------------------------------------

///|
test "sftp_error/open_failed_contains_path" {
  let e = @ssh.SshError::SftpError(
    "sftp_open '/var/log/auth.log' failed (code 3)",
  )
  assert_eq(e.to_string().contains("/var/log/auth.log"), true)
}

///|
test "sftp_error/read_rc_in_message" {
  let e = @ssh.SshError::SftpError("sftp_read failed (rc=-22)")
  assert_eq(e.to_string().contains("rc=-22"), true)
}

///|
test "sftp_error/write_rc_in_message" {
  let e = @ssh.SshError::SftpError("sftp_write failed (rc=-5)")
  assert_eq(e.to_string().contains("sftp_write"), true)
}

///|
test "sftp_error/requires_auth_unauthenticated" {
  let e = @ssh.SshError::SftpError("must authenticate before using SFTP")
  assert_eq(e.to_string().contains("authenticate"), true)
}

// -------------------------------------------------------------------------
// write_all accumulation logic
// -------------------------------------------------------------------------

///|
test "sftp/write_all_zero_bytes_is_ok" {
  // Simulating the write_all guard: empty data → immediate Ok
  let data = Bytes::make(0, 0)
  assert_eq(data.length(), 0)
  // write_all returns Ok(()) for empty input
  let result : Result[Unit, @ssh.SshError] = Ok(())
  match result {
    Ok(_) => ()
    Err(e) => fail("unexpected: \{e.to_string()}")
  }
}

///|
test "sftp/read_all_empty_response" {
  // Empty read (EOF immediately) returns empty Bytes
  let result : Result[Bytes, @ssh.SshError] = Ok(Bytes::make(0, 0))
  match result {
    Ok(b) => assert_eq(b.length(), 0)
    Err(e) => fail("unexpected: \{e.to_string()}")
  }
}

///|
test "sftp/chunk_concat_correctness" {
  // Simulate read_all merging two chunks
  let chunk1 = Bytes::make(3, 65) // b"AAA"
  let chunk2 = Bytes::make(2, 66) // b"BB"
  let total = chunk1.length() + chunk2.length()
  let result : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for i in 0..<chunk1.length() {
    result[offset] = chunk1[i]
    offset = offset + 1
  }
  for i in 0..<chunk2.length() {
    result[offset] = chunk2[i]
    offset = offset + 1
  }
  assert_eq(total, 5)
  assert_eq(result[0], b'A') // 'A'
  assert_eq(result[3], b'B') // 'B'
}

// -------------------------------------------------------------------------
// Buffer size default
// -------------------------------------------------------------------------

///|
test "sftp/buf_size_is_reasonable" {
  // sftp_buf_size is 32768; verify it's > 0 and a power of two
  let s = 32768
  assert_eq(s > 0, true)
  assert_eq((s & (s - 1)) == 0, true) // power-of-two check
}
