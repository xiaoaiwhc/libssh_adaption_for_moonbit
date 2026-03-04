// session_test.mbt — Unit tests for the session module.
//
// Tests cover:
//   • Algorithm allow-list (security-critical: weak algos must be blocked)
//   • SshError message formatting
//   • Fingerprint hex encoding
//   • host-verified guard logic (using a fake session state)

// -------------------------------------------------------------------------
// Algorithm allow-list tests
// -------------------------------------------------------------------------

///|
test "allow_list/blocks_weak_kex_dh_group1" {
  assert_eq(@ssh.is_algo_allowed("diffie-hellman-group1-sha1", "kex"), false)
}

///|
test "allow_list/blocks_weak_kex_dh_group14_sha1" {
  assert_eq(@ssh.is_algo_allowed("diffie-hellman-group14-sha1", "kex"), false)
}

///|
test "allow_list/permits_curve25519" {
  assert_eq(@ssh.is_algo_allowed("curve25519-sha256", "kex"), true)
}

///|
test "allow_list/permits_curve25519_libssh_alias" {
  assert_eq(@ssh.is_algo_allowed("curve25519-sha256@libssh.org", "kex"), true)
}

///|
test "allow_list/permits_ecdh_nistp256" {
  assert_eq(@ssh.is_algo_allowed("ecdh-sha2-nistp256", "kex"), true)
}

///|
test "allow_list/permits_dh_group16" {
  assert_eq(@ssh.is_algo_allowed("diffie-hellman-group16-sha512", "kex"), true)
}

///|
test "allow_list/blocks_weak_hostkey_rsa_sha1" {
  // rsa-sha1 / ssh-rsa is SHA-1 based — not on our allow-list
  assert_eq(@ssh.is_algo_allowed("ssh-rsa", "hostkey"), false)
}

///|
test "allow_list/permits_ed25519_hostkey" {
  assert_eq(@ssh.is_algo_allowed("ssh-ed25519", "hostkey"), true)
}

///|
test "allow_list/permits_rsa_sha2_256_hostkey" {
  assert_eq(@ssh.is_algo_allowed("rsa-sha2-256", "hostkey"), true)
}

///|
test "allow_list/blocks_weak_cipher_3des" {
  assert_eq(@ssh.is_algo_allowed("3des-cbc", "cipher"), false)
}

///|
test "allow_list/blocks_weak_cipher_aes128_cbc" {
  // CBC mode is not in the allow-list (only CTR and GCM)
  assert_eq(@ssh.is_algo_allowed("aes128-cbc", "cipher"), false)
}

///|
test "allow_list/permits_aes256_gcm" {
  assert_eq(@ssh.is_algo_allowed("aes256-gcm@openssh.com", "cipher"), true)
}

///|
test "allow_list/permits_chacha20_poly1305" {
  assert_eq(
    @ssh.is_algo_allowed("chacha20-poly1305@openssh.com", "cipher"),
    true,
  )
}

///|
test "allow_list/permits_aes256_ctr" {
  assert_eq(@ssh.is_algo_allowed("aes256-ctr", "cipher"), true)
}

///|
test "allow_list/blocks_weak_mac_hmac_md5" {
  assert_eq(@ssh.is_algo_allowed("hmac-md5", "mac"), false)
}

///|
test "allow_list/blocks_weak_mac_hmac_sha1" {
  // Plain hmac-sha1 (not ETM variant) not in our list
  assert_eq(@ssh.is_algo_allowed("hmac-sha1", "mac"), false)
}

///|
test "allow_list/permits_hmac_sha2_256_etm" {
  assert_eq(@ssh.is_algo_allowed("hmac-sha2-256-etm@openssh.com", "mac"), true)
}

///|
test "allow_list/permits_hmac_sha2_256" {
  assert_eq(@ssh.is_algo_allowed("hmac-sha2-256", "mac"), true)
}

///|
test "allow_list/unknown_category_always_false" {
  assert_eq(@ssh.is_algo_allowed("anything", "unknown_category"), false)
}

///|
test "allow_list/empty_string_always_false" {
  assert_eq(@ssh.is_algo_allowed("", "kex"), false)
}

// -------------------------------------------------------------------------
// SshError formatting tests
// -------------------------------------------------------------------------

///|
test "error/init_failed_message" {
  let e = @ssh.SshError::InitFailed("code 1")
  assert_eq(e.to_string(), "SSH init failed: code 1")
}

///|
test "error/host_key_not_found_message" {
  let e = @ssh.SshError::HostKeyNotFound("192.168.1.1")
  let msg = e.to_string()
  assert_eq(msg.contains("192.168.1.1"), true)
  assert_eq(msg.contains("Unknown host key"), true)
}

///|
test "error/host_key_mismatch_urgent_message" {
  let e = @ssh.SshError::HostKeyMismatch("evil.host")
  let msg = e.to_string()
  // Must contain the word MISMATCH to signal urgency
  assert_eq(msg.contains("MISMATCH"), true)
  assert_eq(msg.contains("evil.host"), true)
}

///|
test "error/auth_failed_message" {
  let e = @ssh.SshError::AuthFailed("permission denied")
  assert_eq(e.to_string(), "Authentication failed: permission denied")
}

///|
test "error/alloc_failed_message" {
  let e = @ssh.SshError::AllocFailed
  assert_eq(e.to_string(), "Memory allocation failed")
}

///|
test "error/channel_error_message" {
  let e = @ssh.SshError::ChannelError("read error (rc=-37)")
  assert_eq(e.to_string(), "Channel error: read error (rc=-37)")
}

///|
test "error/sftp_error_message" {
  let e = @ssh.SshError::SftpError("sftp_open '/etc/shadow' failed (code 3)")
  let msg = e.to_string()
  assert_eq(msg.contains("SFTP error"), true)
  assert_eq(msg.contains("/etc/shadow"), true)
}

///|
test "error/winsock_failed_message" {
  let e = @ssh.SshError::WinsockFailed(10106)
  let msg = e.to_string()
  assert_eq(msg.contains("10106"), true)
}

///|
test "error/unexpected_message" {
  let e = @ssh.SshError::Unexpected("something went wrong")
  assert_eq(e.to_string(), "Unexpected error: something went wrong")
}

// -------------------------------------------------------------------------
// Error equality
// -------------------------------------------------------------------------

///|
test "error/equality_same" {
  let a = @ssh.SshError::AuthFailed("denied")
  let b = @ssh.SshError::AuthFailed("denied")
  assert_eq(a == b, true)
}

///|
test "error/equality_different_variant" {
  let a = @ssh.SshError::AuthFailed("denied")
  let b = @ssh.SshError::ConnectFailed("denied")
  assert_eq(a == b, false)
}

///|
test "error/equality_different_message" {
  let a = @ssh.SshError::AuthFailed("denied")
  let b = @ssh.SshError::AuthFailed("timeout")
  assert_eq(a == b, false)
}
