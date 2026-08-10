#![no_std]

use core::mem::size_of;

/// Maximum length of a path carried in an [`Event`], including the NUL
/// terminator. Must be a multiple of 8 so the ring-buffer records stay
/// 8-byte aligned.
pub const PATH_BUF_SIZE: usize = 256;

/// Directories whose file operations are reported to user space.
pub const MONITORED_DIRS: [&str; 3] = ["/opt/protected", "/var/secure", "/home/secure_area"];

/// The directory designated as protected: any write/create/delete under it
/// terminates the offending process.
pub const ENFORCED_DIR: &str = "/var/secure";

/// A file operation observed by the eBPF probes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Create = 1,
    Write = 2,
    Delete = 3,
}

impl FileOp {
    pub fn from_u8(value: u8) -> Option<FileOp> {
        match value {
            1 => Some(FileOp::Create),
            2 => Some(FileOp::Write),
            3 => Some(FileOp::Delete),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FileOp::Create => "create",
            FileOp::Write => "write",
            FileOp::Delete => "delete",
        }
    }
}

/// Event record produced in kernel space and consumed in user space.
///
/// `#[repr(C)]` guarantees both sides agree on the byte layout. The kernel
/// writes the header fields at their exact offsets and the path buffers are
/// NUL-terminated strings. Events are emitted only when the complete path
/// fits in the buffer, so a partial path is never mistaken for a real one.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub op: u8,
    pub pid: u32,
    pub ppid: u32,
    pub cgroup_id: u64,
    pub exe_path: [u8; PATH_BUF_SIZE],
    pub file_path: [u8; PATH_BUF_SIZE],
}

impl Event {
    pub const SIZE: usize = size_of::<Event>();

    pub fn from_bytes(bytes: &[u8]) -> Option<Event> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let mut event = Event {
            op: 0,
            pid: 0,
            ppid: 0,
            cgroup_id: 0,
            exe_path: [0; PATH_BUF_SIZE],
            file_path: [0; PATH_BUF_SIZE],
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut event as *mut Event as *mut u8,
                Self::SIZE,
            )
        };
        Some(event)
    }
}

/// Length of a NUL-terminated string stored in `bytes` (bounded by its size).
pub fn cstr_len(bytes: &[u8]) -> usize {
    bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
}

/// Return the NUL-terminated portion of `bytes`.
pub fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[..cstr_len(bytes)]
}

/// Interpret a NUL-terminated byte string as UTF-8.
///
/// Linux paths are arbitrary bytes. User-space display should use
/// `String::from_utf8_lossy(cstr_bytes(...))` when it needs to preserve a
/// readable representation of non-UTF-8 names.
pub fn cstr(bytes: &[u8]) -> &str {
    core::str::from_utf8(cstr_bytes(bytes)).unwrap_or("")
}

/// Returns `true` if `path` is `dir` itself or is nested under it.
///
/// Matches on component boundaries only: `/var/secure_2` does **not** match
/// `/var/secure`.
pub fn is_under(path: &str, dir: &str) -> bool {
    if path == dir {
        return true;
    }
    match path.strip_prefix(dir) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// Returns `true` if `path` is under any of [`MONITORED_DIRS`].
pub fn is_monitored(path: &str) -> bool {
    MONITORED_DIRS.iter().any(|dir| is_under(path, dir))
}

/// Returns `true` if `path` is under [`ENFORCED_DIR`].
pub fn is_enforced(path: &str) -> bool {
    is_under(path, ENFORCED_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_op_round_trip() {
        for op in [FileOp::Create, FileOp::Write, FileOp::Delete] {
            assert_eq!(FileOp::from_u8(op as u8), Some(op));
            assert_eq!(op.label().len() > 0, true);
        }
        assert_eq!(FileOp::from_u8(0), None);
        assert_eq!(FileOp::from_u8(42), None);
    }

    #[test]
    fn event_round_trip() {
        let mut event = Event {
            op: FileOp::Delete as u8,
            pid: 4242,
            ppid: 1,
            cgroup_id: 0xdead_beef_cafe,
            exe_path: [0; PATH_BUF_SIZE],
            file_path: [0; PATH_BUF_SIZE],
        };
        let exe = b"/usr/bin/touch";
        let file = b"/var/secure/gone";
        event.exe_path[..exe.len()].copy_from_slice(exe);
        event.file_path[..file.len()].copy_from_slice(file);

        let bytes = unsafe {
            core::slice::from_raw_parts(&event as *const Event as *const u8, Event::SIZE)
        };
        let decoded = Event::from_bytes(bytes).unwrap();
        assert_eq!(decoded, event);
        assert_eq!(decoded.op, FileOp::Delete as u8);
        assert_eq!(decoded.pid, 4242);
        assert_eq!(decoded.ppid, 1);
        assert_eq!(decoded.cgroup_id, 0xdead_beef_cafe);
        assert_eq!(cstr(&decoded.exe_path), "/usr/bin/touch");
        assert_eq!(cstr(&decoded.file_path), "/var/secure/gone");
    }

    #[test]
    fn event_decode_rejects_wrong_size() {
        assert!(Event::from_bytes(&[]).is_none());
        assert!(Event::from_bytes(&[0u8; Event::SIZE - 1]).is_none());
        assert!(Event::from_bytes(&[0u8; Event::SIZE + 1]).is_none());
    }

    #[test]
    fn cstr_handles_no_terminator() {
        let buf = [b'a'; PATH_BUF_SIZE];
        assert_eq!(cstr_len(&buf), PATH_BUF_SIZE);
        assert_eq!(cstr_bytes(&buf), &buf);
    }

    #[test]
    fn is_under_boundaries() {
        assert!(is_under("/var/secure", "/var/secure"));
        assert!(is_under("/var/secure/x", "/var/secure"));
        assert!(is_under("/var/secure/sub/dir/f", "/var/secure"));
        assert!(is_under("/home/secure_area/f", "/home/secure_area"));
        assert!(!is_under("/var/securex", "/var/secure"));
        assert!(!is_under("/var/secure_2", "/var/secure"));
        assert!(!is_under("/var/security", "/var/secure"));
        assert!(!is_under("/opt/protected2/x", "/opt/protected"));
        assert!(!is_under("/var", "/var/secure"));
        assert!(!is_under("/", "/var/secure"));
    }

    #[test]
    fn is_monitored_and_enforced() {
        assert!(is_monitored("/opt/protected/a"));
        assert!(is_monitored("/var/secure"));
        assert!(is_monitored("/home/secure_area/x/y"));
        assert!(!is_monitored("/tmp/x"));
        assert!(!is_monitored("/var/secure_2"));

        assert!(is_enforced("/var/secure/f"));
        assert!(is_enforced("/var/secure"));
        assert!(!is_enforced("/opt/protected/f"));
        assert!(!is_enforced("/home/secure_area/f"));
        assert!(!is_enforced("/var/secure_2"));
    }
}
