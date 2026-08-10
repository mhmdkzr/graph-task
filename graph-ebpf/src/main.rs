#![no_std]
#![no_main]

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, bpf_send_signal,
    },
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};
use graph_common::{Event, FileOp, PATH_BUF_SIZE};

// ---------------------------------------------------------------------------
// Kernel struct field offsets for Linux 6.12 x86_64, taken from the running
// kernel's BTF (/sys/kernel/btf/vmlinux). These are version/arch specific;
// they would need to change for other kernels.
// ---------------------------------------------------------------------------
const FILE_F_INODE_OFF: usize = 0x28;
const FILE_F_PATH_OFF: usize = 0x40;
const PATH_DENTRY_OFF: usize = 0x08;

const INODE_I_MODE_OFF: usize = 0x00;

const DENTRY_D_NAME_OFF: usize = 0x20;
const DENTRY_D_PARENT_OFF: usize = 0x18;
const DENTRY_D_SB_OFF: usize = 0x68;

const QSTR_NAME_OFF: usize = 0x08;
const QSTR_LEN_OFF: usize = 0x04;

const SUPER_BLOCK_S_ROOT_OFF: usize = 0x68;

const TASK_MM_OFF: usize = 0x900;
const TASK_REAL_PARENT_OFF: usize = 0x990;
const TASK_TGID_OFF: usize = 0x984;
const MM_EXE_FILE_OFF: usize = 0x488;

// A path that fits in PATH_BUF_SIZE can contain at most 127 one-byte
// components (`/a/a/...`). This bound therefore resolves every path we can
// represent, while remaining a verifier-bounded loop.
const MAX_DEPTH: u32 = 128;
const NAME_MAX: usize = 255;

const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;

const O_CREAT: u32 = 0o100;

const SIGKILL: u32 = 9;

// Event field offsets (match `graph_common::Event` repr(C) layout).
const EXE_OFF: usize = 24;
const FILE_OFF: usize = EXE_OFF + PATH_BUF_SIZE;

const MONITORED_PREFIXES: [&[u8]; 3] = [b"/opt/protected", b"/var/secure", b"/home/secure_area"];
const ENFORCED_PREFIX: &[u8] = b"/var/secure";

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// key 0 -> PID of the observer process (excluded from telemetry + enforcement).
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[kprobe]
pub fn graph_write(ctx: ProbeContext) -> u32 {
    try_emit(ctx, FileOp::Write, true).unwrap_or(0)
}

#[kprobe]
pub fn graph_unlink(ctx: ProbeContext) -> u32 {
    try_emit(ctx, FileOp::Delete, false).unwrap_or(0)
}

// `vfs_create` is inlined into its callers on this kernel, so a kprobe on it
// never fires. File creation is instead observed at the openat(2) syscall
// tracepoints, filtering on the O_CREAT flag.
#[tracepoint]
pub fn openat_create(ctx: TracePointContext) -> u32 {
    let filename: i64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let flags: i64 = match unsafe { ctx.read_at(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if (flags as u32) & O_CREAT == 0 {
        return 0;
    }
    emit_create(filename as *const u8)
}

#[tracepoint]
pub fn openat2_create(ctx: TracePointContext) -> u32 {
    let filename: i64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let how: i64 = match unsafe { ctx.read_at(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if how == 0 {
        return 0;
    }
    let flags: u64 = unsafe { bpf_probe_read_user(how as *const u64) }.unwrap_or(0);
    if (flags as u32) & O_CREAT == 0 {
        return 0;
    }
    emit_create(filename as *const u8)
}

/// Emit a `create` event for an openat-style call whose filename comes from
/// user space (the raw syscall path, usually absolute).
fn emit_create(filename: *const u8) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(observer) = unsafe { CONFIG.get(&0u32) } {
        if *observer == pid {
            return 0;
        }
    }

    let mut entry = match EVENTS.reserve_bytes(Event::SIZE + PATH_BUF_SIZE, 0) {
        Some(entry) => entry,
        None => return 0,
    };
    let (event_area, _slack) = entry.split_at_mut(Event::SIZE);
    let (exe_and_header, file_area) = event_area.split_at_mut(FILE_OFF);
    let (header, exe_area) = exe_and_header.split_at_mut(EXE_OFF);

    // Copy the NUL-terminated pathname from user memory into the path area.
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename, file_area) };
    if path_len(file_area) == 0 || !path_matches_any(file_area) {
        entry.discard(0);
        return 0;
    }

    if path_matches(file_area, ENFORCED_PREFIX) {
        let _ = unsafe { bpf_send_signal(SIGKILL) };
    }

    let ppid = current_ppid();
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    header[0] = FileOp::Create as u8;
    header[4..8].copy_from_slice(&pid.to_ne_bytes());
    header[8..12].copy_from_slice(&ppid.to_ne_bytes());
    header[16..24].copy_from_slice(&cgroup_id.to_ne_bytes());

    let exe_dentry = current_exe_dentry();
    if build_path(exe_dentry, exe_area) == 0 {
        entry.discard(0);
        return 0;
    }

    entry.submit(0);
    0
}

/// Build and emit one event for the operation described by `ctx`.
///
/// `target_is_file` selects how the target dentry is obtained from the probe
/// arguments: `vfs_write` receives a `struct file *` (arg 0), while
/// `vfs_create`/`vfs_unlink` receive a `struct dentry *` (arg 2).
fn try_emit(ctx: ProbeContext, op: FileOp, target_is_file: bool) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Never act on the observer itself.
    if let Some(observer) = unsafe { CONFIG.get(&0u32) } {
        if *observer == pid {
            return Ok(0);
        }
    }

    let dentry: *mut c_void = if target_is_file {
        let file_ptr: *mut c_void = ctx.arg(0).ok_or(0u32)?;
        // Cheap regular-file check before anything else: skip pipes, sockets,
        // char devices (e.g. the tty) and other non-regular files.
        let f_inode: *mut c_void = read_ptr(file_ptr, FILE_F_INODE_OFF).ok_or(0u32)?;
        let mode: u16 = read_field(f_inode, INODE_I_MODE_OFF).unwrap_or(0);
        if mode & S_IFMT != S_IFREG {
            return Ok(0);
        }
        // `file.f_path` is an embedded `struct path`, so take its address
        // rather than reading a pointer out of it; its `dentry` member is at +8.
        let f_path: *mut c_void = (file_ptr as usize + FILE_F_PATH_OFF) as *mut c_void;
        read_ptr(f_path, PATH_DENTRY_OFF).ok_or(0u32)?
    } else {
        ctx.arg(2).ok_or(0u32)?
    };

    // Reserve the event plus one path buffer of verifier slack. The verifier
    // checks each variable-length name copy against `off_max + size_max`
    // independently (up to 24 + 2*PATH_BUF + NAME_MAX bytes), which can exceed
    // Event::SIZE even though every real write stays inside the path area.
    // User space reads only the first `Event::SIZE` bytes.
    let mut entry = EVENTS
        .reserve_bytes(Event::SIZE + PATH_BUF_SIZE, 0)
        .ok_or(0u32)?;
    // Keep the path areas at exactly PATH_BUF_SIZE; the tail is verifier slack.
    let (event_area, _slack) = entry.split_at_mut(Event::SIZE);
    let (exe_and_header, file_area) = event_area.split_at_mut(FILE_OFF);
    let (header, exe_area) = exe_and_header.split_at_mut(EXE_OFF);

    // Build the file path first; only paths under a monitored dir are reported.
    let path_len = build_path(dentry, file_area);
    if path_len == 0 || !path_matches_any(file_area) {
        entry.discard(0);
        return Ok(0);
    }

    // Request termination before any optional telemetry work. This keeps the
    // protected-path behavior independent of process-path resolution.
    if path_matches(file_area, ENFORCED_PREFIX) {
        let _ = unsafe { bpf_send_signal(SIGKILL) };
    }

    let ppid = current_ppid();
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    header[0] = op as u8;
    header[4..8].copy_from_slice(&pid.to_ne_bytes());
    header[8..12].copy_from_slice(&ppid.to_ne_bytes());
    header[16..24].copy_from_slice(&cgroup_id.to_ne_bytes());

    let exe_dentry = current_exe_dentry();
    if build_path(exe_dentry, exe_area) == 0 {
        // Do not emit incomplete records. Enforcement, if applicable, was
        // already requested above.
        entry.discard(0);
        return Ok(0);
    }

    entry.submit(0);
    Ok(0)
}

/// Walk the dentry chain from `dentry` up to the filesystem root and write the
/// absolute path (NUL-terminated) into `buf`. Returns the number of bytes
/// written, or 0 unless the complete path fits and can be resolved.
///
/// The path is assembled in reverse (from the end of `buf` towards the front)
/// and then shifted to the beginning, so only `buf` itself is used as scratch.
///
/// NOTE: all writes use raw pointers with explicit bounds guards. Bounds-checked
/// indexing would pull `core::panicking::panic_*` into the linked program and
/// break verification.
fn build_path(mut dentry: *mut c_void, buf: &mut [u8]) -> usize {
    let end = buf.len();
    if end < 2 {
        return 0;
    }
    let sb = match read_ptr(dentry, DENTRY_D_SB_OFF) {
        Some(sb) => sb,
        None => return 0,
    };
    let root = match read_ptr(sb, SUPER_BLOCK_S_ROOT_OFF) {
        Some(root) => root,
        None => return 0,
    };

    if dentry == root {
        unsafe {
            *buf.as_mut_ptr() = b'/';
            *buf.as_mut_ptr().add(1) = 0;
        }
        return 2;
    }

    // Indices are tracked as i64 and explicitly guarded `>= 0`: the verifier
    // computes `pos - name_len` ranges independently of the preceding bounds
    // checks, so without the guards it can prove neither that the write index
    // is non-negative nor that `index + size` stays inside the buffer.
    let mut pos: i64 = (end - 1) as i64;
    unsafe {
        *buf.as_mut_ptr().add(pos as usize) = 0;
    }
    let mut depth = 0u32;

    while depth < MAX_DEPTH {
        if dentry == root {
            break;
        }
        let name_ptr: *mut u8 = match read_field(dentry, DENTRY_D_NAME_OFF + QSTR_NAME_OFF) {
            Some(name) => name,
            None => return 0,
        };
        let name_len_raw: u32 = match read_field(dentry, DENTRY_D_NAME_OFF + QSTR_LEN_OFF) {
            Some(len) => len,
            None => return 0,
        };
        let name_len = (name_len_raw as usize).min(NAME_MAX);
        if name_len == 0 {
            return 0;
        }

        // `dst < 1` is exactly the "is there room for the name plus the '/'
        // separator" test (name_len + 1 <= pos), but expressed after the
        // subtraction so the optimizer cannot fold it away: the verifier needs
        // an explicit branch that proves the index is non-negative.
        let dst = pos - name_len as i64;
        if dst < 1 {
            return 0;
        }
        let dst_slice = unsafe {
            core::slice::from_raw_parts_mut(buf.as_mut_ptr().add(dst as usize), name_len)
        };
        if unsafe { bpf_probe_read_kernel_buf(name_ptr, dst_slice) }.is_err() {
            return 0;
        }
        pos = dst - 1;
        if pos < 0 {
            return 0;
        }
        unsafe {
            *buf.as_mut_ptr().add(pos as usize) = b'/';
        }

        let parent = match read_ptr(dentry, DENTRY_D_PARENT_OFF) {
            Some(parent) => parent,
            None => return 0,
        };
        dentry = parent;
        depth += 1;
    }

    // Never treat a partial dentry walk as a path: that could make a suffix
    // appear to belong to a monitored directory.
    if dentry != root {
        return 0;
    }

    let len = (end as i64 - pos) as usize;
    unsafe {
        core::ptr::copy(buf.as_ptr().add(pos as usize), buf.as_mut_ptr(), len);
    }
    len
}

/// Length of the NUL-terminated string in `buf` (bounded by `buf.len()`).
fn path_len(buf: &[u8]) -> usize {
    let mut i = 0;
    while i < buf.len() {
        if unsafe { *buf.as_ptr().add(i) } == 0 {
            return i;
        }
        i += 1;
    }
    buf.len()
}

/// Component-boundary prefix match: `path` is `prefix` itself or starts with
/// `prefix/`.
fn path_matches(path: &[u8], prefix: &[u8]) -> bool {
    let plen = path_len(path);
    if plen < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < 32 {
        if i >= prefix.len() {
            break;
        }
        if unsafe { *path.as_ptr().add(i) } != unsafe { *prefix.as_ptr().add(i) } {
            return false;
        }
        i += 1;
    }
    plen == prefix.len() || unsafe { *path.as_ptr().add(prefix.len()) } == b'/'
}

fn path_matches_any(path: &[u8]) -> bool {
    let mut i = 0;
    while i < 3 {
        let prefix: &[u8] = unsafe { *MONITORED_PREFIXES.as_ptr().add(i) };
        if path_matches(path, prefix) {
            return true;
        }
        i += 1;
    }
    false
}

fn current_task() -> *mut c_void {
    (unsafe { bpf_get_current_task() }) as *mut c_void
}

fn current_ppid() -> u32 {
    let task = current_task();
    let parent = match read_ptr(task, TASK_REAL_PARENT_OFF) {
        Some(parent) => parent,
        None => return 0,
    };
    read_field(parent, TASK_TGID_OFF).unwrap_or(0)
}

fn current_exe_dentry() -> *mut c_void {
    let task = current_task();
    let mm = match read_ptr(task, TASK_MM_OFF) {
        Some(mm) => mm,
        None => return core::ptr::null_mut(),
    };
    let exe_file = match read_ptr(mm, MM_EXE_FILE_OFF) {
        Some(exe) => exe,
        None => return core::ptr::null_mut(),
    };
    // `file.f_path` is an embedded `struct path`; take its address and read the
    // `dentry` member at +8.
    let f_path: *mut c_void = (exe_file as usize + FILE_F_PATH_OFF) as *mut c_void;
    read_ptr(f_path, PATH_DENTRY_OFF).unwrap_or(core::ptr::null_mut())
}

/// Read a value of type `T` from kernel memory at `base + off`.
fn read_field<T>(base: *mut c_void, off: usize) -> Option<T> {
    let addr = (base as usize).wrapping_add(off);
    read_kernel(addr as *const T)
}

/// Read a pointer-sized value from kernel memory at `base + off`.
fn read_ptr(base: *mut c_void, off: usize) -> Option<*mut c_void> {
    read_field(base, off)
}

/// Read a value of type `T` from kernel memory at `src`.
fn read_kernel<T>(src: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(src).ok() }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
