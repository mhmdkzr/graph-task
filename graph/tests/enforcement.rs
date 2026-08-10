//! Integration test exercising the real eBPF program end-to-end.
//!
//! Requires root and a kernel with eBPF available (loading the probe needs
//! privileges). Run with:
//!
//! ```text
//! sudo -E cargo test --test enforcement -- --ignored
//! ```

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MONITORED: [&str; 3] = ["/opt/protected", "/var/secure", "/home/secure_area"];
const ENFORCED_FILE: &str = "/var/secure/evil";
const TELEMETRY_FILE: &str = "/home/secure_area/note";
const BENIGN_FILE: &str = "/tmp/benign";

fn start_graph() -> (Child, Arc<Mutex<Vec<String>>>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_graph"))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn graph");
    let stdout = child.stdout.take().unwrap();
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let collector = Arc::clone(&lines);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            collector.lock().unwrap().push(line);
        }
    });
    (child, lines)
}

fn wait_for(
    pred: impl Fn(&str) -> bool,
    lines: &Arc<Mutex<Vec<String>>>,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if lines.lock().unwrap().iter().any(|line| pred(line)) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    lines.lock().unwrap().iter().any(|line| pred(line))
}

#[test]
#[ignore = "requires root + eBPF; run with: sudo -E cargo test --test enforcement -- --ignored"]
fn enforcement_and_telemetry() {
    for dir in MONITORED {
        let _ = std::fs::create_dir_all(dir);
    }
    for file in [ENFORCED_FILE, TELEMETRY_FILE, BENIGN_FILE] {
        let _ = std::fs::remove_file(file);
    }

    let (mut graph, lines) = start_graph();
    assert!(
        wait_for(
            |l| l.contains("monitoring"),
            &lines,
            Duration::from_secs(10)
        ),
        "graph did not report readiness: {:?}",
        *lines.lock().unwrap()
    );

    // (1) write/create under the protected dir terminates the process.
    let killed = Command::new("sh")
        .arg("-c")
        .arg(format!("echo x > {ENFORCED_FILE}"))
        .status()
        .unwrap();
    assert_eq!(
        killed.signal(),
        Some(9),
        "writer under /var/secure should be SIGKILLed, got {:?}",
        killed
    );

    // (2) writes outside monitored dirs are untouched.
    let benign = Command::new("sh")
        .arg("-c")
        .arg(format!("echo x > {BENIGN_FILE}"))
        .status()
        .unwrap();
    assert!(benign.success(), "benign write must not be killed");

    // (3) monitored but not enforced: creates/writes/delete reported, process
    // survives.
    let note = Command::new("sh")
        .arg("-c")
        .arg(format!("echo x > {TELEMETRY_FILE}"))
        .status()
        .unwrap();
    assert!(note.success(), "telemetry-only dir must not kill");
    let _ = Command::new("rm").args(["-f", TELEMETRY_FILE]).status();

    // Collect and verify the telemetry stream.
    assert!(
        wait_for(
            |l| l.contains("path=") && l.contains(ENFORCED_FILE),
            &lines,
            Duration::from_secs(5)
        ),
        "no event for {ENFORCED_FILE}: {:?}",
        *lines.lock().unwrap()
    );
    assert!(
        wait_for(
            |l| l.contains("path=") && l.contains(TELEMETRY_FILE),
            &lines,
            Duration::from_secs(5)
        ),
        "no event for {TELEMETRY_FILE}: {:?}",
        *lines.lock().unwrap()
    );
    assert!(
        wait_for(
            |l| l.contains("[delete]") && l.contains(TELEMETRY_FILE),
            &lines,
            Duration::from_secs(5)
        ),
        "no delete event for {TELEMETRY_FILE}: {:?}",
        *lines.lock().unwrap()
    );

    // Sanity: the benign file must never have been reported.
    thread::sleep(Duration::from_millis(500));
    assert!(
        !lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(BENIGN_FILE)),
        "benign file leaked into the event stream: {:?}",
        *lines.lock().unwrap()
    );

    let _ = Command::new("rm").args(["-f", ENFORCED_FILE]).status();
    let _ = graph.kill();
    let _ = graph.wait();
}
