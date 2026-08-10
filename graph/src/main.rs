use std::io::Write as _;
use std::process;

use anyhow::Context as _;
use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::KProbe;
use graph_common::{Event, FileOp, is_monitored};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bump the memlock rlimit. Needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("warning: failed to raise memlock rlimit");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/graph"
    )))?;

    // Register the observer's PID so the probes ignore this process.
    //
    // Borrow the map rather than `take` it: `take` would move it out of the
    // object, and dropping our handle would close the last fd and destroy the
    // map while the loaded probes still reference it.
    let mut config: HashMap<&mut MapData, u32, u32> = HashMap::try_from(
        ebpf.map_mut("CONFIG").context("failed to access CONFIG map")?,
    )?;
    config.insert(0, process::id(), 0)?;
    drop(config);

    for (program, function) in [
        ("graph_write", "vfs_write"),
        ("graph_unlink", "vfs_unlink"),
    ] {
        let p: &mut KProbe = ebpf
            .program_mut(program)
            .context("program not found")?
            .try_into()?;
        p.load()?;
        p.attach(function, 0)?;
    }

    // File creation is observed at the openat(2) tracepoints (vfs_create is
    // inlined on this kernel).
    for (program, category, name) in [
        ("openat_create", "syscalls", "sys_enter_openat"),
        ("openat2_create", "syscalls", "sys_enter_openat2"),
    ] {
        let p: &mut aya::programs::TracePoint = ebpf
            .program_mut(program)
            .context("program not found")?
            .try_into()?;
        p.load()?;
        p.attach(category, name)?;
    }

    let map = ebpf
        .take_map("EVENTS")
        .context("failed to take EVENTS map")?;
    let ring_buf: RingBuf<MapData> = RingBuf::try_from(map)?;

    let drain = tokio::spawn(async move {
        if let Err(e) = drain_events(ring_buf).await {
            eprintln!("event loop error: {e}");
        }
    });

    println!(
        "monitoring {:?} | enforcing writes under {} | press Ctrl-C to exit",
        graph_common::MONITORED_DIRS,
        graph_common::ENFORCED_DIR
    );
    let _ = std::io::stdout().flush();

    tokio::signal::ctrl_c().await?;
    println!("Exiting...");
    drain.abort();

    Ok(())
}

async fn drain_events(ring_buf: RingBuf<MapData>) -> anyhow::Result<()> {
    let mut async_fd = AsyncFd::with_interest(ring_buf, Interest::READABLE)?;
    loop {
        let mut guard = async_fd.readable_mut().await?;
        loop {
            let Some(item) = guard.get_inner_mut().next() else {
                break;
            };
            // The kernel reserves verifier slack past Event::SIZE; only the
            // first Event::SIZE bytes carry the record.
            if item.len() < Event::SIZE {
                continue;
            }
            let Some(event) = Event::from_bytes(&item[..Event::SIZE]) else {
                continue;
            };
            // The kernel already filters, but re-checking here keeps the
            // display logic honest and exercises the shared testable code.
            if !is_monitored(&String::from_utf8_lossy(graph_common::cstr_bytes(
                &event.file_path,
            ))) {
                continue;
            }
            println!("{}", format_event(&event));
            let _ = std::io::stdout().flush();
        }
        guard.clear_ready();
    }
}

fn format_event(event: &Event) -> String {
    let op = FileOp::from_u8(event.op)
        .map(|op| op.label())
        .unwrap_or("unknown");
    let exe_path = String::from_utf8_lossy(graph_common::cstr_bytes(&event.exe_path));
    let file_path = String::from_utf8_lossy(graph_common::cstr_bytes(&event.file_path));
    format!(
        "[{op}] pid={} ppid={} cgroup={} exe={} path={}",
        event.pid, event.ppid, event.cgroup_id, exe_path, file_path,
    )
}
