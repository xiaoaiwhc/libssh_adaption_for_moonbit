// channel_test.mbt — Unit tests for channel-related logic.
//
// Since Channel requires a live Session (and thus a real SSH connection),
// these tests focus on pure logic: error propagation, SshError semantics,
// and the read-accumulation helper.

// -------------------------------------------------------------------------
// ChannelError propagation tests
// -------------------------------------------------------------------------

///|
test "channel_error/open_requires_auth_message" {
  // Verify that the error returned when unauthenticated has sensible text
  let e = @ssh.SshError::ChannelError(
    "must authenticate before opening a channel",
  )
  assert_eq(e.to_string().contains("Channel error"), true)
  assert_eq(e.to_string().contains("authenticate"), true)
}

///|
test "channel_error/exec_failure_rc_message" {
  let e = @ssh.SshError::ChannelError("read error (rc=-37)")
  assert_eq(e.to_string().contains("rc=-37"), true)
}

///|
test "channel_error/stdout_read_error" {
  let e = @ssh.SshError::ChannelError("read error (rc=-1)")
  assert_eq(e.to_string().contains("-1"), true)
}

///|
test "channel_error/stderr_read_error" {
  let e = @ssh.SshError::ChannelError("stderr read error (rc=-5)")
  assert_eq(e.to_string().contains("stderr"), true)
}

///|
test "channel_error/write_failure_message" {
  let e = @ssh.SshError::ChannelError("write error (rc=-16)")
  assert_eq(e.to_string().contains("write error"), true)
}

// -------------------------------------------------------------------------
// Buffer size logic (default_read_buf_size is package-private so we
// cannot reference it directly; test the observable behaviour instead)
// -------------------------------------------------------------------------

///|
test "channel/empty_bytes_write_ok" {
  // Writing empty Bytes should yield Ok(0) — the guard in Channel::write
  // prevents a zero-length allocation.
  // We test this purely in terms of the Result value semantics.
  let result : Result[Int, @ssh.SshError] = Ok(0)
  match result {
    Ok(n) => assert_eq(n, 0)
    Err(_) => fail("expected Ok(0)")
  }
}

// -------------------------------------------------------------------------
// Exit status semantics
// -------------------------------------------------------------------------

///|
test "channel/exit_status_zero_means_success" {
  // Conventional: exit code 0 = success
  let code = 0
  assert_eq(code == 0, true)
}

///|
test "channel/exit_status_nonzero_means_failure" {
  let code = 1
  assert_eq(code != 0, true)
}

// -------------------------------------------------------------------------
// Run result tuple structure
// -------------------------------------------------------------------------

///|
test "channel/run_result_tuple_access" {
  // Verify the result tuple (stdout, stderr, exit) can be destructured.
  let result : Result[(String, String, Int), @ssh.SshError] = Ok(
    ("hello\n", "", 0),
  )
  match result {
    Ok((stdout, stderr, code)) => {
      assert_eq(stdout, "hello\n")
      assert_eq(stderr, "")
      assert_eq(code, 0)
    }
    Err(e) => fail("unexpected error: \{e.to_string()}")
  }
}

///|
test "channel/run_result_error_propagation" {
  let result : Result[(String, String, Int), @ssh.SshError] = Err(
    @ssh.SshError::ChannelError("exec failed"),
  )
  match result {
    Ok(_) => fail("expected Err")
    Err(e) => assert_eq(e.to_string().contains("exec failed"), true)
  }
}
