use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use crate::platform::CanonicalizeExt;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ListenerProcess {
    pid: u32,
    command_name: String,
    uid: u32,
    command: String,
    start_token: String,
}

fn system_tool<'a>(absolute: &'a str, fallback: &'a str) -> &'a str {
    if std::path::Path::new(absolute).is_file() {
        absolute
    } else {
        fallback
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyProxyCleanup {
    NotLegacy,
    IdentityChanged(u32),
    Stopped(u32),
    StopFailed(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedGatewayCleanup {
    NotManaged,
    Stopped(u32),
    StopUnknown {
        pid: u32,
        kind: ManagedGatewayStopUnknownKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedGatewayStopUnknownKind {
    SignalFailed,
    ExitUnconfirmed,
}

fn parse_lsof_records(output: &str) -> Vec<(u32, String)> {
    let mut records = Vec::new();
    let mut pid = None;
    let mut command_name = String::new();
    for line in output.lines() {
        if let Some(raw) = line.strip_prefix('p') {
            if let Some(previous) = pid.take() {
                records.push((previous, std::mem::take(&mut command_name)));
            }
            pid = raw.trim().parse::<u32>().ok();
        } else if let Some(raw) = line.strip_prefix('c') {
            command_name = raw.trim().to_string();
        }
    }
    if let Some(previous) = pid {
        records.push((previous, command_name));
    }
    records
}

fn listener_records(port: u16) -> Vec<(u32, String)> {
    let filter = format!("-iTCP:{port}");
    let output = match Command::new(system_tool("/usr/sbin/lsof", "lsof"))
        .args(["-nP", "-a", &filter, "-sTCP:LISTEN", "-Fpc"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_lsof_records(&String::from_utf8_lossy(&output.stdout))
}

fn parse_ps_record(output: &str) -> Option<(u32, String)> {
    let trimmed = output.trim();
    let split = trimmed.find(char::is_whitespace)?;
    let uid = trimmed[..split].parse::<u32>().ok()?;
    let command = trimmed[split..].trim().to_string();
    (!command.is_empty()).then_some((uid, command))
}

fn process_snapshot(pid: u32, command_name: String) -> Option<ListenerProcess> {
    let output = Command::new(system_tool("/bin/ps", "ps"))
        .args([
            "-ww",
            "-p",
            &pid.to_string(),
            "-o",
            "uid=",
            "-o",
            "command=",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let (uid, command) = parse_ps_record(&String::from_utf8_lossy(&output.stdout))?;
    let start_output = Command::new(system_tool("/bin/ps", "ps"))
        .args(["-ww", "-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .ok()?;
    if !start_output.status.success() {
        return None;
    }
    let start_token = String::from_utf8_lossy(&start_output.stdout)
        .trim()
        .to_string();
    if start_token.is_empty() {
        return None;
    }
    Some(ListenerProcess {
        pid,
        command_name,
        uid,
        command,
        start_token,
    })
}

fn current_uid() -> Option<u32> {
    let output = Command::new(system_tool("/usr/bin/id", "id"))
        .arg("-u")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
}

fn process_text_files(pid: u32) -> Vec<std::path::PathBuf> {
    let output = match Command::new(system_tool("/usr/sbin/lsof", "lsof"))
        .args(["-nP", "-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .map(std::path::PathBuf::from)
        .collect()
}

fn has_exact_arg_pair(command: &str, name: &str, value: &str) -> bool {
    let fields: Vec<&str> = command.split_whitespace().collect();
    fields
        .windows(2)
        .any(|pair| pair[0] == name && pair[1] == value)
}

fn arg_value<'a>(command: &'a str, name: &str) -> Option<&'a str> {
    let fields: Vec<&str> = command.split_whitespace().collect();
    fields
        .windows(2)
        .find(|pair| pair[0] == name && !pair[1].starts_with('-'))
        .map(|pair| pair[1])
}

fn is_legacy_csswitch_python(
    process: &ListenerProcess,
    port: u16,
    uid: u32,
    expected_script: &Path,
) -> bool {
    if process.pid <= 1 || process.uid != uid {
        return false;
    }
    let process_name = process.command_name.to_ascii_lowercase();
    if !process_name.starts_with("python") {
        return false;
    }
    let expected_script = expected_script.to_string_lossy();
    let Some(script_start) = process.command.find(expected_script.as_ref()) else {
        return false;
    };
    let before_script = &process.command[..script_start];
    let after_script = &process.command[script_start + expected_script.len()..];
    !expected_script.is_empty()
        && before_script.split_whitespace().count() == 1
        && after_script.starts_with(" --provider ")
        && arg_value(&process.command, "--provider").is_some()
        && has_exact_arg_pair(&process.command, "--port", &port.to_string())
}

fn exact_legacy_listener(port: u16, expected_script: &Path) -> Option<ListenerProcess> {
    let uid = current_uid()?;
    let records = listener_records(port);
    if records.len() != 1 {
        return None;
    }
    let (pid, command_name) = records.into_iter().next()?;
    let process = process_snapshot(pid, command_name)?;
    is_legacy_csswitch_python(&process, port, uid, expected_script).then_some(process)
}

pub(crate) fn stop_legacy_csswitch_python_on_port(
    port: u16,
    expected_script: &Path,
) -> LegacyProxyCleanup {
    let Some(process) = exact_legacy_listener(port, expected_script) else {
        return LegacyProxyCleanup::NotLegacy;
    };
    stop_claimed_legacy_process_with(
        process,
        |expected| exact_legacy_listener(port, expected_script).as_ref() == Some(expected),
        |pid| {
            let result = unsafe { crate::platform::kill(pid as i32, libc::SIGTERM) };
            (result == 0).then_some(()).ok_or(())
        },
        |pid| {
            listener_records(port)
                .iter()
                .any(|(listener_pid, _)| *listener_pid == pid)
        },
    )
}

fn stop_claimed_legacy_process_with<Recheck, Signal, StillListening>(
    process: ListenerProcess,
    recheck: Recheck,
    signal_term: Signal,
    still_listening: StillListening,
) -> LegacyProxyCleanup
where
    Recheck: FnOnce(&ListenerProcess) -> bool,
    Signal: FnOnce(u32) -> Result<(), ()>,
    StillListening: Fn(u32) -> bool,
{
    if !recheck(&process) {
        return LegacyProxyCleanup::IdentityChanged(process.pid);
    }
    if signal_term(process.pid).is_err() {
        return LegacyProxyCleanup::StopFailed(process.pid);
    }
    for _ in 0..30 {
        if !still_listening(process.pid) {
            return LegacyProxyCleanup::Stopped(process.pid);
        }
        thread::sleep(Duration::from_millis(50));
    }
    LegacyProxyCleanup::StopFailed(process.pid)
}

/// Stop an interrupted managed Rust Gateway only after the caller has
/// authenticated its health identity. Process ownership is independently
/// constrained to one listener owned by the current uid whose executable is
/// the exact packaged Gateway binary. `health_still_matches` is re-run
/// immediately before SIGTERM to close the listener-replacement race.
pub(crate) fn stop_managed_gateway_on_port<F>(
    port: u16,
    expected_binary: &Path,
    health_still_matches: F,
) -> ManagedGatewayCleanup
where
    F: Fn() -> bool,
{
    stop_managed_gateway_on_port_with(port, expected_binary, health_still_matches, |pid| {
        let result = unsafe { crate::platform::kill(pid as i32, libc::SIGTERM) };
        if result == 0 {
            Ok(())
        } else {
            Err(())
        }
    })
}

pub(crate) fn stop_managed_gateway_on_port_with<F, Signal>(
    port: u16,
    expected_binary: &Path,
    health_still_matches: F,
    signal_term: Signal,
) -> ManagedGatewayCleanup
where
    F: Fn() -> bool,
    Signal: FnOnce(u32) -> Result<(), ()>,
{
    let Some(uid) = current_uid() else {
        return ManagedGatewayCleanup::NotManaged;
    };
    let records = listener_records(port);
    if records.len() != 1 {
        return ManagedGatewayCleanup::NotManaged;
    }
    let (pid, command_name) = records[0].clone();
    let Some(process) = process_snapshot(pid, command_name) else {
        return ManagedGatewayCleanup::NotManaged;
    };
    if pid <= 1 || process.uid != uid {
        return ManagedGatewayCleanup::NotManaged;
    }
    let Ok(expected) = expected_binary.canonicalize_norm() else {
        return ManagedGatewayCleanup::NotManaged;
    };
    let executable_matches = process_text_files(pid)
        .into_iter()
        .filter_map(|path| path.canonicalize_norm().ok())
        .any(|path| path == expected);
    if !executable_matches
        || !health_still_matches()
        || listener_records(port).as_slice() != [(pid, process.command_name.clone())]
    {
        return ManagedGatewayCleanup::NotManaged;
    }
    if signal_term(pid).is_err() {
        return ManagedGatewayCleanup::StopUnknown {
            pid,
            kind: ManagedGatewayStopUnknownKind::SignalFailed,
        };
    }
    for _ in 0..40 {
        if !listener_records(port)
            .iter()
            .any(|(listener_pid, _)| *listener_pid == pid)
        {
            return ManagedGatewayCleanup::Stopped(pid);
        }
        thread::sleep(Duration::from_millis(50));
    }
    ManagedGatewayCleanup::StopUnknown {
        pid,
        kind: ManagedGatewayStopUnknownKind::ExitUnconfirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_legacy_csswitch_python, parse_lsof_records, parse_ps_record,
        stop_claimed_legacy_process_with, stop_legacy_csswitch_python_on_port, LegacyProxyCleanup,
        ListenerProcess,
    };

    fn process(command_name: &str, uid: u32, command: &str) -> ListenerProcess {
        ListenerProcess {
            pid: 4321,
            command_name: command_name.to_string(),
            uid,
            command: command.to_string(),
            start_token: "Sun Aug  9 12:00:00 2026".into(),
        }
    }

    #[test]
    fn lsof_parser_keeps_pid_and_command_records() {
        assert_eq!(
            parse_lsof_records("p12\ncPython\np34\nccsswitch-gateway\n"),
            vec![(12, "Python".into()), (34, "csswitch-gateway".into())]
        );
    }

    #[test]
    fn ps_parser_separates_uid_without_logging_command() {
        assert_eq!(
            parse_ps_record("  501 /usr/bin/python3 /Applications/CSSwitch.app/x\n"),
            Some((501, "/usr/bin/python3 /Applications/CSSwitch.app/x".into()))
        );
        assert_eq!(parse_ps_record("not-a-uid command"), None);
    }

    #[test]
    fn classifier_accepts_only_exact_owned_legacy_bundle_listener() {
        let exact = process(
            "Python",
            501,
            "/Applications/Xcode.app/Python /Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py --provider relay --port 18991 --auth-token hidden",
        );
        let expected = std::path::Path::new(
            "/Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py",
        );
        assert!(is_legacy_csswitch_python(&exact, 18991, 501, expected));
        assert!(!is_legacy_csswitch_python(&exact, 18992, 501, expected));
        assert!(!is_legacy_csswitch_python(&exact, 18991, 502, expected));

        let unknown_script = process(
            "Python",
            501,
            "/usr/bin/python3 /tmp/csswitch_proxy.py --provider relay --port 18991",
        );
        assert!(!is_legacy_csswitch_python(
            &unknown_script,
            18991,
            501,
            expected
        ));

        let spoofed_name = process(
            "node",
            501,
            "/Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py --provider relay --port 18991",
        );
        assert!(!is_legacy_csswitch_python(
            &spoofed_name,
            18991,
            501,
            expected
        ));

        let rust_gateway = process(
            "csswitch-gateway",
            501,
            "/Applications/CSSwitch.app/Contents/MacOS/csswitch-gateway --provider relay --port 18991",
        );
        assert!(!is_legacy_csswitch_python(
            &rust_gateway,
            18991,
            501,
            expected
        ));

        let path_only_as_argument = process(
            "Python",
            501,
            "/usr/bin/python3 /tmp/listener.py --note /Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py --provider relay --port 18991",
        );
        assert!(!is_legacy_csswitch_python(
            &path_only_as_argument,
            18991,
            501,
            expected
        ));

        let path_as_second_positional_argument = process(
            "Python",
            501,
            "/usr/bin/python3 /tmp/listener.py /Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py --provider relay --port 18991",
        );
        assert!(!is_legacy_csswitch_python(
            &path_as_second_positional_argument,
            18991,
            501,
            expected
        ));
    }

    #[test]
    fn legacy_cleanup_rechecks_full_identity_before_signal() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let owner = process(
            "Python",
            501,
            "/usr/bin/python3 /Applications/CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py --provider relay --port 18991",
        );
        let signal_called = AtomicBool::new(false);
        let outcome = stop_claimed_legacy_process_with(
            owner.clone(),
            |expected| {
                let mut replacement = owner.clone();
                replacement.start_token = "Sun Aug  9 12:00:01 2026".into();
                &replacement == expected
            },
            |_| {
                signal_called.store(true, Ordering::SeqCst);
                Ok(())
            },
            |_| true,
        );

        assert_eq!(outcome, LegacyProxyCleanup::IdentityChanged(owner.pid));
        assert!(!signal_called.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_legacy_listener_is_terminated_without_touching_other_processes() {
        use std::fs;
        use std::net::TcpStream;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let python = ["/usr/bin/python3", "/opt/homebrew/bin/python3"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("macOS test requires python3");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("CSSwitch legacy test {nonce}"));
        let script = root.join("CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(
            &script,
            "import argparse, socket, time\np=argparse.ArgumentParser(); p.add_argument('--provider'); p.add_argument('--port', type=int); a=p.parse_args()\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',a.port)); s.listen(1)\nwhile True: time.sleep(1)\n",
        )
        .unwrap();
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut child = Command::new(python)
            .arg(&script)
            .args(["--provider", "relay", "--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..40 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(ready, "test legacy listener did not start");
        let result = stop_legacy_csswitch_python_on_port(port, &script);
        if result != LegacyProxyCleanup::Stopped(child.id()) {
            let _ = child.kill();
        }
        let _ = child.wait();
        let _ = fs::remove_dir_all(root);
        assert_eq!(result, LegacyProxyCleanup::Stopped(child.id()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_unknown_python_listener_is_left_running() {
        use std::fs;
        use std::net::TcpStream;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let python = ["/usr/bin/python3", "/opt/homebrew/bin/python3"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("macOS test requires python3");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("unrelated listener {nonce}"));
        let script = root.join("listener.py");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &script,
            "import argparse, socket, time\np=argparse.ArgumentParser(); p.add_argument('--provider'); p.add_argument('--port', type=int); a=p.parse_args()\ns=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',a.port)); s.listen(1)\nwhile True: time.sleep(1)\n",
        )
        .unwrap();
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut child = Command::new(python)
            .arg(&script)
            .args(["--provider", "relay", "--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..40 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(ready, "test unrelated listener did not start");
        assert_eq!(
            stop_legacy_csswitch_python_on_port(
                port,
                &root.join("CSSwitch.app/Contents/Resources/proxy/csswitch_proxy.py")
            ),
            LegacyProxyCleanup::NotLegacy
        );
        assert!(child.try_wait().unwrap().is_none());
        assert!(super::listener_records(port)
            .iter()
            .any(|(pid, _)| *pid == child.id()));
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(root);
    }
}
