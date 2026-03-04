// types.mbt — Opaque type aliases used across the FFI boundary.
//
// All C pointer types are represented as Int64 so the MoonBit-to-C calling
// convention is unambiguous on 64-bit targets.  The newtype wrappers provide
// nominal typing so Session, Channel, Sftp etc. cannot be mixed up.
//
// A value of 0 (zero) represents NULL / an invalid handle.

///|
/// Raw LIBSSH2_SESSION* handle.
pub(all) struct SshSessionPtr(Int64) derive(Eq)

///|
/// Raw LIBSSH2_CHANNEL* handle.
pub(all) struct SshChannelPtr(Int64) derive(Eq)

///|
/// Raw LIBSSH2_SFTP* handle.
pub(all) struct SshSftpPtr(Int64) derive(Eq)

///|
/// Raw LIBSSH2_SFTP_HANDLE* handle.
pub(all) struct SshSftpHandlePtr(Int64) derive(Eq)

///|
/// Raw LIBSSH2_KNOWNHOSTS* handle.
pub(all) struct SshKnownHostsPtr(Int64) derive(Eq)

///|
/// A raw heap-allocated C buffer (returned by stub_alloc_buf).
pub(all) struct RawBufPtr(Int64) derive(Eq)

///|
/// Platform socket descriptor (SOCKET on Win32, int file-descriptor on POSIX).
pub(all) struct SocketHandle(Int64) derive(Eq)

// --- Null-check helpers ---

///|
pub fn SshSessionPtr::is_null(self : SshSessionPtr) -> Bool {
  self.0 == 0L
}

///|
pub fn SshChannelPtr::is_null(self : SshChannelPtr) -> Bool {
  self.0 == 0L
}

///|
pub fn SshSftpPtr::is_null(self : SshSftpPtr) -> Bool {
  self.0 == 0L
}

///|
pub fn SshSftpHandlePtr::is_null(self : SshSftpHandlePtr) -> Bool {
  self.0 == 0L
}

///|
pub fn SshKnownHostsPtr::is_null(self : SshKnownHostsPtr) -> Bool {
  self.0 == 0L
}

///|
pub fn RawBufPtr::is_null(self : RawBufPtr) -> Bool {
  self.0 == 0L
}

///|
pub fn SocketHandle::is_null(self : SocketHandle) -> Bool {
  self.0 == 0L
}

// --- Known-host check result constants (mirror libssh2 defines) ---

///|
/// Host key matches a known-hosts entry — safe to proceed.
pub let knownhost_check_match : Int = 0

///|
/// Host is known but the key has changed — possible MITM.
pub let knownhost_check_mismatch : Int = 1

///|
/// Host is not listed in the known-hosts file.
pub let knownhost_check_notfound : Int = 2

///|
/// Internal error during the check.
pub let knownhost_check_failure : Int = 3

// --- Hash type constants ---

///|
pub let hostkey_hash_md5 : Int = 1

///|
pub let hostkey_hash_sha1 : Int = 2

///|
pub let hostkey_hash_sha256 : Int = 3

// --- SFTP open flag constants ---

///|
pub let sftp_fxf_read : Int = 1

///|
pub let sftp_fxf_write : Int = 2

///|
pub let sftp_fxf_append : Int = 4

///|
pub let sftp_fxf_creat : Int = 8

///|
pub let sftp_fxf_trunc : Int = 16

///|
pub let sftp_fxf_excl : Int = 32

// --- SFTP open type ---

///|
pub let sftp_openfile : Int = 0

///|
pub let sftp_opendir : Int = 1

// --- Key type constants (for known-hosts checks) ---

///|
pub let key_type_rsa : Int = 1

///|
pub let key_type_dss : Int = 2

///|
pub let key_type_ecdsa256 : Int = 3

///|
pub let key_type_ecdsa384 : Int = 4

///|
pub let key_type_ecdsa521 : Int = 5

///|
pub let key_type_ed25519 : Int = 6
