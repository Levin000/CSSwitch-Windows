//! 进程管家用到的纯 std 辅助：探活、一次性 secret 生成、上游可达性。
//! 无第三方依赖，便于单测；有状态的子进程编排放在 lib.rs（持 Child 句柄）。

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildLiveness {
    Running,
    Exited(String),
    Unknown(String),
}

fn classify_child_try_wait(
    result: std::io::Result<Option<std::process::ExitStatus>>,
) -> ChildLiveness {
    match result {
        Ok(None) => ChildLiveness::Running,
        Ok(Some(status)) => ChildLiveness::Exited(status.to_string()),
        Err(error) => ChildLiveness::Unknown(error.to_string()),
    }
}

pub fn poll_child_liveness(child: &mut std::process::Child) -> ChildLiveness {
    classify_child_try_wait(child.try_wait())
}

pub fn tracked_child_is_running(child: &mut Option<std::process::Child>) -> bool {
    child
        .as_mut()
        .map(|child| matches!(poll_child_liveness(child), ChildLiveness::Running))
        .unwrap_or(false)
}

/// Check whether a loopback TCP port is already accepting connections without
/// sending any HTTP bytes or path secret to the listener.
pub fn loopback_port_in_use(port: u16, timeout_ms: u64) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

/// Final publish/probe guard used immediately before exposing a child as usable.
/// It is deliberately fail-closed for both an observed exit and an indeterminate poll.
pub fn require_child_running(child: &mut std::process::Child, context: &str) -> Result<(), String> {
    match poll_child_liveness(child) {
        ChildLiveness::Running => Ok(()),
        ChildLiveness::Exited(status) => Err(format!("{context}提前退出（{status}）")),
        ChildLiveness::Unknown(error) => Err(format!("{context}存活状态未知：{error}")),
    }
}

/// 对本地回环代理做 HTTP 探活：`GET /<secret>/health`，响应状态行含 200 即视为健康。
/// 代理带 path-secret 鉴权时必须带上 secret，否则会拿到 403。
pub fn http_health(port: u16, secret: Option<&str>, timeout_ms: u64) -> bool {
    http_health_response(port, secret, timeout_ms).is_some()
}

#[cfg(test)]
const SCIENCE_HEALTH_HEADER_LIMIT: usize = 16 * 1024;
#[cfg(test)]
const SCIENCE_HEALTH_BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScienceDbHealth {
    Ready,
    ReverifyPending,
    RestartRequired,
}

#[cfg(test)]
pub(crate) fn science_db_health(port: u16, timeout_ms: u64) -> Result<ScienceDbHealth, String> {
    let (status, body) =
        http_get_body_bounded(port, "/api/health", timeout_ms, SCIENCE_HEALTH_BODY_LIMIT)?;
    if status != 200 {
        return Err(format!("science_api_health_status_{status}"));
    }
    science_db_health_from_body(&body)
}

pub(crate) fn science_db_health_from_body(body: &str) -> Result<ScienceDbHealth, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "science_api_health_malformed")?;
    let corruption = value
        .get("db_corruption")
        .and_then(serde_json::Value::as_object)
        .ok_or("science_api_health_missing_db_corruption")?;
    let flagged = corruption
        .get("flagged")
        .and_then(serde_json::Value::as_bool)
        .ok_or("science_api_health_missing_db_corruption")?;
    let kind = corruption
        .get("kind")
        .ok_or("science_api_health_missing_db_corruption_kind")?;
    let migrations_skipped = value
        .get("db_migrations_skipped")
        .and_then(serde_json::Value::as_bool)
        .ok_or("science_api_health_missing_db_migrations_skipped")?;
    match (flagged, kind.as_str(), kind.is_null()) {
        (true, Some("damage"), false) if migrations_skipped => {
            return Ok(ScienceDbHealth::ReverifyPending)
        }
        (true, Some("damage"), false) => return Ok(ScienceDbHealth::RestartRequired),
        (true, Some("io_errors"), false) => return Ok(ScienceDbHealth::RestartRequired),
        (false, None, true) => {}
        _ => return Err("science_api_health_invalid_db_corruption_kind".into()),
    }
    if migrations_skipped {
        return Ok(ScienceDbHealth::RestartRequired);
    }
    Ok(ScienceDbHealth::Ready)
}

#[cfg(test)]
fn http_get_body_bounded(
    port: u16,
    path: &str,
    timeout_ms: u64,
    body_limit: usize,
) -> Result<(u16, String), String> {
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .map_err(|_| "science_api_health_unreachable")?
        .next()
        .ok_or("science_api_health_unreachable")?;
    let dur = Duration::from_millis(timeout_ms);
    let mut stream =
        TcpStream::connect_timeout(&addr, dur).map_err(|_| "science_api_health_unreachable")?;
    let poll = Duration::from_millis(250).min(dur);
    stream
        .set_read_timeout(Some(poll))
        .map_err(|_| "science_api_health_unreachable")?;
    stream
        .set_write_timeout(Some(poll))
        .map_err(|_| "science_api_health_unreachable")?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "science_api_health_unreachable")?;
    let deadline = Instant::now() + dur;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("science_api_health_incomplete".into());
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(250).min(remaining)));
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    header_end = raw.windows(4).position(|window| window == b"\r\n\r\n");
                    if header_end.is_none() && raw.len() > SCIENCE_HEALTH_HEADER_LIMIT {
                        return Err("science_api_health_headers_too_large".into());
                    }
                }
                if let Some(end) = header_end {
                    if end > SCIENCE_HEALTH_HEADER_LIMIT {
                        return Err("science_api_health_headers_too_large".into());
                    }
                    if raw.len().saturating_sub(end + 4) > body_limit {
                        return Err("science_api_health_body_too_large".into());
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("science_api_health_unreachable".into()),
        }
    }
    let header_end = header_end.ok_or("science_api_health_incomplete")?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "science_api_health_malformed_headers")?;
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && !value.trim().eq_ignore_ascii_case("identity")
        })
    }) {
        return Err("science_api_health_unsupported_transfer_encoding".into());
    }
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("science_api_health_malformed_status")?;
    let body = &raw[header_end + 4..];
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err("science_api_health_malformed_headers".into());
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("science_api_health_malformed_headers".into());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "science_api_health_malformed_headers")?,
            );
        }
    }
    if let Some(length) = content_length {
        if length > body_limit {
            return Err("science_api_health_body_too_large".into());
        }
        if length != body.len() {
            return Err("science_api_health_incomplete".into());
        }
    }
    let body = std::str::from_utf8(body).map_err(|_| "science_api_health_malformed_utf8")?;
    Ok((status, body.to_string()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHealth {
    pub gateway: String,
    pub provider: String,
    pub shim: String,
    pub launch_id: String,
    pub provider_contract_id: String,
    pub provider_contract_digest: String,
    pub catalog_fp: String,
    pub intent: String,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayHealthExpectation<'a> {
    pub gateway: &'a str,
    pub provider: Option<&'a str>,
    pub shim: Option<&'a str>,
    pub launch_id: Option<&'a str>,
    pub provider_contract_id: Option<&'a str>,
    pub provider_contract_digest: Option<&'a str>,
}

/// 读取 Rust gateway 声明的运行身份。
pub fn http_gateway_health(
    port: u16,
    secret: Option<&str>,
    timeout_ms: u64,
) -> Option<GatewayHealth> {
    let response = http_health_response(port, secret, timeout_ms)?;
    gateway_health_from_response(&response)
}

/// CSSwitch proxy 强身份探活。Managed Rust launch 必须匹配
/// gateway/provider/shim/launch_id/provider contract；launch_id 防止同端口同
/// secret、甚至同 provider/shim 的旧 gateway 冒充新 child。Managed launches
/// 必须同时提供精确 contract id 与 catalog digest；不完整的期望身份失败关闭。
pub fn http_health_gateway(
    port: u16,
    secret: Option<&str>,
    timeout_ms: u64,
    expected: GatewayHealthExpectation<'_>,
) -> bool {
    let Some(actual) = http_gateway_health(port, secret, timeout_ms) else {
        return false;
    };
    gateway_health_matches(&actual, expected)
}

pub(crate) fn gateway_health_matches(
    actual: &GatewayHealth,
    expected: GatewayHealthExpectation<'_>,
) -> bool {
    let contract_matches = match (
        expected.provider_contract_id,
        expected.provider_contract_digest,
    ) {
        (None, None) => true,
        (Some(id), Some(digest)) => {
            !id.is_empty()
                && !digest.is_empty()
                && actual.provider_contract_id == id
                && actual.provider_contract_digest == digest
        }
        _ => false,
    };
    actual.gateway == expected.gateway
        && expected
            .provider
            .map(|expected| actual.provider == expected)
            .unwrap_or(true)
        && expected
            .shim
            .map(|expected| actual.shim == expected)
            .unwrap_or(true)
        && expected
            .launch_id
            .map(|expected| !expected.is_empty() && actual.launch_id == expected)
            .unwrap_or(true)
        && contract_matches
}

fn http_health_response(port: u16, secret: Option<&str>, timeout_ms: u64) -> Option<String> {
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())?;
    let dur = Duration::from_millis(timeout_ms);
    let mut stream = match TcpStream::connect_timeout(&addr, dur) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));
    let path = match secret {
        Some(s) if !s.is_empty() => format!("/{s}/health"),
        _ => "/health".to_string(),
    };
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    // 读完整个小 health 响应；读上限防呆，超时则用已读内容判定。
    let mut chunk = [0u8; 1024];
    while buf.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        if let Some(expected) = expected_http_response_len(&buf) {
            if buf.len() >= expected {
                break;
            }
        }
    }
    let resp = String::from_utf8_lossy(&buf).to_string();
    let status_line = resp.lines().next().unwrap_or("");
    // 形如 "HTTP/1.1 200 OK"：严格取第二段等于 200，避免 contains 误配 reason phrase。
    if status_line.split_whitespace().nth(1) == Some("200") {
        Some(resp)
    } else {
        None
    }
}

fn gateway_health_from_response(resp: &str) -> Option<GatewayHealth> {
    let (_, body) = resp.split_once("\r\n\r\n")?;
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let string_field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let gateway = string_field("gateway");
    if gateway.is_empty() {
        return None;
    }
    Some(GatewayHealth {
        gateway,
        provider: string_field("provider"),
        shim: string_field("shim"),
        launch_id: string_field("launch_id"),
        provider_contract_id: string_field("provider_contract_id"),
        provider_contract_digest: string_field("provider_contract_digest"),
        catalog_fp: string_field("catalog_fp"),
        intent: string_field("intent"),
    })
}

fn expected_http_response_len(buf: &[u8]) -> Option<usize> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..header_end]);
    for line in head.lines() {
        let (name, value) = match line.split_once(':') {
            Some(parts) => parts,
            None => continue,
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if let Ok(len) = value.trim().parse::<usize>() {
                return Some(header_end + len);
            }
        }
    }
    Some(header_end)
}

/// 向本地回环代理 POST 一段 JSON（`POST /<secret><path>`），返回 HTTP 响应状态码；
/// 连不上 / 无响应返回 None。用于「存 key 后用最小请求真正验一次 key」——
/// 请求经代理打到上游，200=可用，401/403=key 被拒。回环明文，无需 TLS。
/// timeout_ms 要给足（代理要转发上游），建议调用方传 ~15000。
pub fn http_post_status(
    port: u16,
    secret: Option<&str>,
    path_suffix: &str,
    body: &[u8],
    timeout_ms: u64,
) -> Option<u16> {
    let addr = ("127.0.0.1", port).to_socket_addrs().ok()?.next()?;
    let dur = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&addr, dur).ok()?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));
    let path = match secret {
        Some(s) if !s.is_empty() => format!("/{s}{path_suffix}"),
        _ => path_suffix.to_string(),
    };
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    // 只需读到状态行（非流式响应，状态行随首个头块到达）；读上限防呆。
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
}

/// 向本地回环代理 GET 一段路径（`GET /<secret><path>`），返回 (状态码, 响应体)。
/// 连不上 / 无响应返回 None。用于经代理回源拉中转站 `/v1/models`——代理有 TLS（urllib），
/// 这里只打回环明文，无需在 Rust 侧引 TLS。timeout_ms 要给足（代理要转发上游），建议 ~15000。
#[cfg(test)]
fn http_get_body(
    port: u16,
    secret: Option<&str>,
    path_suffix: &str,
    timeout_ms: u64,
) -> Option<(u16, String)> {
    http_get_body_cancellable(port, secret, path_suffix, timeout_ms, None)
}

pub fn http_get_body_cancellable(
    port: u16,
    secret: Option<&str>,
    path_suffix: &str,
    timeout_ms: u64,
    cancel: Option<&AtomicBool>,
) -> Option<(u16, String)> {
    if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
        return None;
    }
    let addr = ("127.0.0.1", port).to_socket_addrs().ok()?.next()?;
    let dur = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&addr, dur).ok()?;
    let poll = Duration::from_millis(250);
    let _ = stream.set_read_timeout(Some(poll.min(dur)));
    let _ = stream.set_write_timeout(Some(poll.min(dur)));
    let path = match secret {
        Some(s) if !s.is_empty() => format!("/{s}{path_suffix}"),
        _ => path_suffix.to_string(),
    };
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    // 读完整响应（状态行 + 头 + 体）。上限防呆：模型列表通常 < 数十 KB，给 1 MiB。
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + dur;
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(poll.min(remaining)));
        if buf.len() > 1_048_576 {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())?;
    // 分割头与体：首个空行之后即响应体。
    let body = match text.split_once("\r\n\r\n") {
        Some((_, b)) => b.to_string(),
        None => String::new(),
    };
    Some((status, body))
}

/// 上游主机可达性（仅 TCP 连通，不校验 key）。绿灯=可达，黄灯=不可达。
pub fn tcp_reachable(host: &str, port: u16, timeout_ms: u64) -> bool {
    let dur = Duration::from_millis(timeout_ms);
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            for a in addrs {
                if TcpStream::connect_timeout(&a, dur).is_ok() {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 生成一次性 path-secret：从 /dev/urandom 取 16 字节，hex 编码为 32 字符。
/// 失败关闭：urandom 不可用时返回 Err，绝不退回可猜的弱 secret（宁可起代理失败）。
pub fn gen_secret() -> std::io::Result<String> {
    let b = crate::platform::rand_bytes(16)?;
    Ok(hex(&b))
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(H[(byte >> 4) as usize] as char);
        s.push(H[(byte & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn loopback_port_occupancy_probe_detects_listener_without_http() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8765);
        assert!(loopback_port_in_use(port, 200));
        drop(listener);
        // Do not assert global vacancy after drop: the parallel test suite may
        // legitimately acquire this just-released ephemeral port immediately.
    }

    #[test]
    fn child_liveness_classifier_fails_closed_for_exit_and_poll_error() {
        assert_eq!(classify_child_try_wait(Ok(None)), ChildLiveness::Running);
        let status = Command::new("sh")
            .args(["-c", "exit 7"])
            .status()
            .expect("test shell should exit");
        assert!(matches!(
            classify_child_try_wait(Ok(Some(status))),
            ChildLiveness::Exited(_)
        ));
        let unknown = classify_child_try_wait(Err(std::io::Error::other("poll failed")));
        assert_eq!(unknown, ChildLiveness::Unknown("poll failed".into()));
    }

    #[test]
    fn final_child_publish_guard_accepts_running_and_rejects_exited_child() {
        let mut running = Command::new("sh")
            .args(["-c", "sleep 5"])
            .spawn()
            .expect("test child should start");
        assert!(require_child_running(&mut running, "test child ").is_ok());
        let _ = running.kill();
        let _ = running.wait();

        let mut exited = Command::new("sh")
            .args(["-c", "exit 9"])
            .spawn()
            .expect("test child should start");
        let _ = exited.wait();
        let err = require_child_running(&mut exited, "publish child ").unwrap_err();
        assert!(err.contains("提前退出"));
    }

    #[test]
    fn tracked_child_presence_is_not_enough_for_running_status() {
        let mut absent = None;
        assert!(!tracked_child_is_running(&mut absent));

        let mut running = Some(
            Command::new("sh")
                .args(["-c", "sleep 5"])
                .spawn()
                .expect("test child should start"),
        );
        assert!(tracked_child_is_running(&mut running));
        if let Some(child) = running.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(!tracked_child_is_running(&mut running));
    }

    #[test]
    fn health_false_when_nothing_listening() {
        // 一个几乎肯定没人监听的高端口。
        assert!(!http_health(59999, None, 300));
    }

    #[test]
    fn science_db_health_requires_both_semantic_flags_to_be_clear() {
        assert_eq!(
            science_db_health_from_body(
                r#"{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":false}"#
            ),
            Ok(ScienceDbHealth::Ready)
        );
        assert_eq!(
            science_db_health_from_body(
                r#"{"db_corruption":{"flagged":true,"kind":"damage"},"db_migrations_skipped":true}"#
            ),
            Ok(ScienceDbHealth::ReverifyPending)
        );
        assert_eq!(
            science_db_health_from_body(
                r#"{"db_corruption":{"flagged":true,"kind":"damage"},"db_migrations_skipped":false}"#
            ),
            Ok(ScienceDbHealth::RestartRequired)
        );
        assert_eq!(
            science_db_health_from_body(
                r#"{"db_corruption":{"flagged":true,"kind":"io_errors"},"db_migrations_skipped":false}"#
            ),
            Ok(ScienceDbHealth::RestartRequired)
        );
        assert_eq!(
            science_db_health_from_body(
                r#"{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":true}"#
            ),
            Ok(ScienceDbHealth::RestartRequired)
        );
        for body in [
            r#"{"db_corruption":{"flagged":true},"db_migrations_skipped":false}"#,
            r#"{"db_corruption":{"flagged":true,"kind":null},"db_migrations_skipped":false}"#,
            r#"{"db_corruption":{"flagged":true,"kind":"unknown"},"db_migrations_skipped":false}"#,
            r#"{"db_corruption":{"flagged":false,"kind":"damage"},"db_migrations_skipped":false}"#,
        ] {
            assert!(science_db_health_from_body(body).is_err());
        }
        assert!(science_db_health_from_body(r#"{"status":"ok"}"#).is_err());
        assert!(science_db_health_from_body("not-json").is_err());
    }

    #[test]
    fn science_db_health_rejects_declared_body_over_64_kib() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();
        });
        assert_eq!(
            science_db_health(port, 1_000),
            Err("science_api_health_body_too_large".into())
        );
    }

    #[test]
    fn science_db_health_never_accepts_a_valid_json_prefix_of_an_oversize_body() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request);
            let prefix =
                br#"{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":false}"#;
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.write_all(prefix).unwrap();
            stream.write_all(&vec![b' '; 65_537]).unwrap();
            stream.write_all(b"not-json").unwrap();
        });
        assert_eq!(
            science_db_health(port, 1_000),
            Err("science_api_health_body_too_large".into())
        );
    }

    #[test]
    fn cancellable_get_interrupts_a_stalled_local_response() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request);
            thread::sleep(Duration::from_millis(600));
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let setter = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            setter.store(true, Ordering::SeqCst);
        });

        let started = Instant::now();
        assert!(http_get_body_cancellable(port, None, "/slow", 10_000, Some(&cancel)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn gateway_health_parses_full_rust_identity() {
        let rust = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ok\",\"gateway\":\"rust\",\"provider\":\"deepseek\",\"shim\":\"rewrite\",\"launch_id\":\"launch-new\"}";
        assert_eq!(
            gateway_health_from_response(rust),
            Some(GatewayHealth {
                gateway: "rust".into(),
                provider: "deepseek".into(),
                shim: "rewrite".into(),
                launch_id: "launch-new".into(),
                provider_contract_id: "".into(),
                provider_contract_digest: "".into(),
                catalog_fp: "".into(),
                intent: "".into(),
            })
        );
    }

    #[test]
    fn gateway_health_rejects_missing_or_malformed_identity() {
        assert!(
            gateway_health_from_response("HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}").is_none()
        );
        assert!(gateway_health_from_response("HTTP/1.1 200 OK\r\n\r\nnot-json").is_none());
    }

    #[test]
    fn managed_health_rejects_old_rust_launch() {
        let old = GatewayHealth {
            gateway: "rust".into(),
            provider: "deepseek".into(),
            shim: "off".into(),
            launch_id: "old-launch".into(),
            provider_contract_id: "".into(),
            provider_contract_digest: "".into(),
            catalog_fp: "".into(),
            intent: "".into(),
        };
        assert!(!gateway_health_matches(
            &old,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some("new-launch"),
                provider_contract_id: None,
                provider_contract_digest: None,
            },
        ));
        assert!(gateway_health_matches(
            &old,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some("old-launch"),
                provider_contract_id: None,
                provider_contract_digest: None,
            },
        ));
        assert!(!gateway_health_matches(
            &old,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some(""),
                provider_contract_id: None,
                provider_contract_digest: None,
            },
        ));
    }

    #[test]
    fn managed_health_requires_exact_provider_contract_identity_for_every_provider() {
        let contract_id = "deepseek-native";
        let contract_digest = crate::provider_contracts::static_catalog_digest();
        let mut health = GatewayHealth {
            gateway: "rust".into(),
            provider: "deepseek".into(),
            shim: "off".into(),
            launch_id: "launch".into(),
            provider_contract_id: contract_id.into(),
            provider_contract_digest: contract_digest.clone(),
            catalog_fp: "".into(),
            intent: "formal".into(),
        };
        assert!(gateway_health_matches(
            &health,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some("launch"),
                provider_contract_id: Some(contract_id),
                provider_contract_digest: Some(&contract_digest),
            },
        ));
        health.provider_contract_digest = "wrong".into();
        assert!(!gateway_health_matches(
            &health,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some("launch"),
                provider_contract_id: Some(contract_id),
                provider_contract_digest: Some(&contract_digest),
            },
        ));
        assert!(!gateway_health_matches(
            &health,
            GatewayHealthExpectation {
                gateway: "rust",
                provider: Some("deepseek"),
                shim: Some("off"),
                launch_id: Some("launch"),
                provider_contract_id: Some(contract_id),
                provider_contract_digest: None,
            },
        ));
    }

    #[test]
    fn health_reader_waits_for_declared_body() {
        let partial = b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\n\r\n{\"gateway\":\"r";
        assert_eq!(
            expected_http_response_len(partial),
            Some("HTTP/1.1 200 OK\r\ncontent-length: 17\r\n\r\n".len() + 17)
        );
        let complete = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        assert_eq!(expected_http_response_len(complete), Some(complete.len()));
    }

    #[test]
    fn get_body_none_when_nothing_listening() {
        // 没人监听 → 连不上 → None（与 http_health 一致的失败关闭语义）。
        assert!(http_get_body(59998, Some("secret"), "/v1/models", 300).is_none());
    }

    #[test]
    fn gen_secret_is_32_hex_and_varies() {
        let a = gen_secret().unwrap();
        let b = gen_secret().unwrap();
        assert_eq!(a.len(), 32, "urandom 路径应是 32 hex 字符");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "两次生成应不同");
    }

    #[test]
    fn hex_encodes_known_bytes() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }
}
