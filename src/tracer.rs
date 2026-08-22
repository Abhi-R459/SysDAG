//! State-machine strace parser. A single regex is not sufficient.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::Config;
use crate::event::{CaptureInfo, EventArgs, ParseStats, ProcessRef, SyscallRef, TraceEvent};
use crate::labels::{build_labels, is_fd_allocator, is_tracked};

#[derive(Debug, Clone)]
struct Unfinished {
    enter_ns: u64,
    args_prefix: String,
    raw: String,
}

#[derive(Debug)]
struct FileParser {
    pid_hint: Option<i32>,
    unfinished: HashMap<String, Vec<Unfinished>>,
    stats: ParseStats,
}

#[derive(Debug)]
struct RawEvent {
    pid: i32,
    tid: i32,
    enter_ns: u64,
    exit_ns: u64,
    name: String,
    args: EventArgs,
    ret: Option<i64>,
    errno: Option<String>,
    raw: String,
}

pub fn parse_strace_path(path: &Path, cfg: &Config) -> Result<(Vec<TraceEvent>, ParseStats)> {
    if path.is_dir() {
        let mut files: Vec<_> = fs::read_dir(path)
            .with_context(|| format!("read trace dir {}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        let mut all = Vec::new();
        let mut stats = ParseStats::default();
        for f in files {
            let (ev, st) = parse_strace_file(&f, cfg)?;
            merge_stats(&mut stats, &st);
            all.extend(ev);
        }
        finalize_events(&mut all);
        return Ok((all, stats));
    }
    let (mut events, stats) = parse_strace_file(path, cfg)?;
    finalize_events(&mut events);
    Ok((events, stats))
}

fn parse_strace_file(path: &Path, cfg: &Config) -> Result<(Vec<TraceEvent>, ParseStats)> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let pid_hint = pid_from_filename(path);
    let mut parser = FileParser {
        pid_hint,
        unfinished: HashMap::new(),
        stats: ParseStats::default(),
    };
    let mut raw_events = Vec::new();
    for line in text.lines() {
        parser.stats.lines += 1;
        if let Some(ev) = parser.push_line(line) {
            raw_events.push(ev);
        }
    }
    Ok((materialize(raw_events, cfg), parser.stats))
}

fn pid_from_filename(path: &Path) -> Option<i32> {
    let name = path.file_name()?.to_str()?;
    name.rsplit('.').next()?.parse().ok()
}

impl FileParser {
    fn push_line(&mut self, line: &str) -> Option<RawEvent> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (pid_inline, rest) = strip_pid_prefix(trimmed);
        let Some((ts, body)) = split_timestamp(rest) else {
            self.stats.rejected += 1;
            return None;
        };
        if body.starts_with("--- ") {
            self.stats.signals += 1;
            return None;
        }
        if body.starts_with("+++ ") {
            self.stats.exits += 1;
            return None;
        }
        let pid = pid_inline.or(self.pid_hint).unwrap_or(0);
        if let Some(name) = unfinished_name(body) {
            self.stats.unfinished += 1;
            let args_prefix = body
                .split_once('(')
                .map(|(_, r)| r.replace(" <unfinished ...>", ""))
                .unwrap_or_default();
            self.unfinished.entry(name).or_default().push(Unfinished {
                enter_ns: ts,
                args_prefix,
                raw: trimmed.to_string(),
            });
            return None;
        }
        if let Some((name, resumed)) = resumed_parts(body) {
            let start = self.unfinished.get_mut(&name).and_then(|q| q.pop());
            let Some(start) = start else {
                self.stats.rejected += 1;
                return None;
            };
            let merged = format!("{}({})", name, join_unfinished(&start.args_prefix, resumed));
            return self.finish(
                pid,
                start.enter_ns,
                ts,
                &merged,
                &format!("{}\n{trimmed}", start.raw),
            );
        }
        self.finish(pid, ts, ts, body, trimmed)
    }

    fn finish(
        &mut self,
        pid: i32,
        enter_ns: u64,
        exit_ns: u64,
        body: &str,
        raw: &str,
    ) -> Option<RawEvent> {
        match parse_completed(body) {
            Some((name, args, ret, errno)) => Some(RawEvent {
                pid,
                tid: pid,
                enter_ns,
                exit_ns,
                name,
                args,
                ret,
                errno,
                raw: raw.to_string(),
            }),
            None => {
                self.stats.rejected += 1;
                None
            }
        }
    }
}

fn materialize(raw: Vec<RawEvent>, cfg: &Config) -> Vec<TraceEvent> {
    raw.into_iter()
        .filter(|r| is_tracked(&r.name, &cfg.syscall_classes))
        .map(|r| {
            let labels = build_labels(
                &r.name,
                r.args.path.as_deref().unwrap_or(""),
                r.args.flags.as_deref().unwrap_or(""),
                r.args.fd_path.as_deref().unwrap_or(""),
                r.args.sock_info.as_deref().unwrap_or(""),
                r.ret,
                r.errno.as_deref(),
                r.args
                    .count
                    .filter(|_| r.errno.is_none())
                    .or(r.ret.filter(|v| *v >= 0)),
                &cfg.labels.app_root,
            );
            TraceEvent::new(
                ProcessRef {
                    pid: r.pid,
                    tid: r.tid,
                    start_ns: 0,
                    image_gen: 0,
                    comm: String::new(),
                },
                0,
                r.enter_ns,
                r.exit_ns,
                SyscallRef {
                    nr: -1,
                    name: r.name,
                    arch: "linux".into(),
                },
                r.args,
                r.ret,
                r.errno,
                labels,
                CaptureInfo {
                    source: "strace".into(),
                    truncated: false,
                    raw_line: r.raw,
                    lost: false,
                },
            )
        })
        .collect()
}

fn finalize_events(events: &mut [TraceEvent]) {
    events.sort_by(|a, b| {
        (a.enter_ns, a.process.pid, a.syscall.name.as_str()).cmp(&(
            b.enter_ns,
            b.process.pid,
            b.syscall.name.as_str(),
        ))
    });
    for (i, ev) in events.iter_mut().enumerate() {
        ev.seq = (i as u64) + 1;
    }
}

fn merge_stats(dst: &mut ParseStats, src: &ParseStats) {
    dst.lines += src.lines;
    dst.events += src.events;
    dst.rejected += src.rejected;
    dst.signals += src.signals;
    dst.exits += src.exits;
    dst.unfinished += src.unfinished;
}

fn strip_pid_prefix(line: &str) -> (Option<i32>, &str) {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("[pid ") {
        if let Some((num, after)) = rest.split_once(']') {
            return (num.trim().parse().ok(), after.trim_start());
        }
    }
    (None, line)
}

fn split_timestamp(line: &str) -> Option<(u64, &str)> {
    let (first, rest) = line.split_once(' ')?;
    if !first.chars().next()?.is_ascii_digit() || !first.contains('.') {
        return None;
    }
    let (sec, frac) = first.split_once('.')?;
    let sec: u64 = sec.parse().ok()?;
    let mut micros = frac.to_string();
    while micros.len() < 9 {
        micros.push('0');
    }
    micros.truncate(9);
    let ns_frac: u64 = micros.parse().ok()?;
    Some((sec.saturating_mul(1_000_000_000) + ns_frac, rest))
}

fn unfinished_name(body: &str) -> Option<String> {
    if !body.contains("<unfinished ...>") {
        return None;
    }
    let name = body.split('(').next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(normalize_name(name))
}

fn resumed_parts(body: &str) -> Option<(String, &str)> {
    let rest = body.strip_prefix("<... ")?;
    let (name, after) = rest.split_once(" resumed>")?;
    Some((normalize_name(name.trim()), after.trim_start()))
}

fn join_unfinished(prefix: &str, resumed: &str) -> String {
    let p = prefix.trim().trim_end_matches(',');
    let r = resumed.trim().trim_start_matches(',');
    if p.is_empty() {
        r.to_string()
    } else if r.is_empty() {
        p.to_string()
    } else {
        format!("{p}, {r}")
    }
}

fn normalize_name(name: &str) -> String {
    let base = name.split('@').next().unwrap_or(name).trim();
    base.to_string()
}

fn parse_completed(body: &str) -> Option<(String, EventArgs, Option<i64>, Option<String>)> {
    let body = body.trim();
    let name_end = body.find('(')?;
    let name = normalize_name(&body[..name_end]);
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let after_name = &body[name_end + 1..];
    let (args_src, tail) = split_args_and_tail(after_name)?;
    let (ret, errno) = parse_return(tail);
    let mut args = interpret_args(&name, &args_src);
    if args.fd.is_none() && is_fd_allocator(&name) {
        if let Some(r) = ret.filter(|v| *v >= 0) {
            args.fd = Some(r as i32);
        }
    }
    if name == "dup2" || name == "dup3" {
        if let Some(r) = ret.filter(|v| *v >= 0) {
            args.newfd = Some(r as i32);
        }
    }
    if matches!(name.as_str(), "clone" | "clone3" | "fork" | "vfork") {
        if let Some(r) = ret.filter(|v| *v > 0) {
            args.child_pid = Some(r as i32);
        }
    }
    Some((name, args, ret, errno))
}

fn split_args_and_tail(s: &str) -> Option<(String, &str)> {
    let mut depth = 1i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in s.char_indices() {
        if in_str {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((s[..i].to_string(), s[i + 1..].trim_start()));
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_return(tail: &str) -> (Option<i64>, Option<String>) {
    let t = tail.trim();
    let t = t.strip_prefix('=').unwrap_or(t).trim();
    if t.is_empty() || t.starts_with('?') {
        return (None, None);
    }
    let t = strip_duration(t);
    let token = t.split_whitespace().next().unwrap_or("");
    let token = token.split('<').next().unwrap_or(token);
    let ret = parse_int_token(token);
    let errno = t
        .split_whitespace()
        .nth(1)
        .filter(|s| {
            s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
        .map(|s| s.to_string());
    (ret, errno)
}

fn strip_duration(s: &str) -> &str {
    if let Some(idx) = s.rfind('<') {
        if s.trim_end().ends_with('>') {
            return s[..idx].trim_end();
        }
    }
    s
}

fn parse_int_token(tok: &str) -> Option<i64> {
    let tok = tok.trim();
    if tok.is_empty() || tok == "?" {
        return None;
    }
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    tok.parse().ok()
}

fn interpret_args(name: &str, raw: &str) -> EventArgs {
    let parts = split_top_args(raw);
    let mut args = EventArgs::default();
    match name {
        "open" | "creat" => {
            args.path = first_path(&parts);
            args.flags = parts.get(1).cloned();
        }
        "openat" | "openat2" | "newfstatat" | "faccessat" | "faccessat2" | "unlinkat"
        | "mkdirat" | "execveat" => {
            args.dirfd = parts.first().and_then(|s| parse_fd_number(s));
            args.path = first_path(&parts);
            args.flags = parts.get(2).cloned();
        }
        "execve" | "stat" | "lstat" | "access" | "unlink" | "chdir" | "chmod" | "readlink" => {
            args.path = first_path(&parts);
        }
        "read" | "write" | "pread64" | "pwrite64" | "sendto" | "recvfrom" | "send" | "recv"
        | "sendmsg" | "recvmsg" => {
            fill_fd(&mut args, parts.first());
            if let Some(buf) = parts.get(1) {
                args.buffer_addr = parse_hex_addr(buf);
                if buf.starts_with('"') {
                    args.buffer = Some("0xREDACTED".into());
                }
            }
            args.count = parts
                .get(2)
                .or(parts.last())
                .and_then(|s| parse_int_token(s.trim_end_matches(',')));
        }
        "close" | "lseek" | "fstat" | "fsync" | "connect" | "bind" | "listen" | "accept"
        | "accept4" | "shutdown" => {
            fill_fd(&mut args, parts.first());
        }
        "dup" => fill_fd(&mut args, parts.first()),
        "dup2" | "dup3" => {
            fill_fd(&mut args, parts.first());
            args.newfd = parts.get(1).and_then(|s| parse_fd_number(s));
        }
        "fcntl" => {
            fill_fd(&mut args, parts.first());
            if parts.get(1).map(|s| s.contains("DUP")).unwrap_or(false) {
                args.newfd = parts.get(2).and_then(|s| parse_fd_number(s));
            }
        }
        "pipe" | "pipe2" => {
            args.pipe_fds = parse_pipe_fds(raw);
        }
        "socket" => {
            args.flags = parts.get(1).cloned();
        }
        _ => {
            fill_fd(&mut args, parts.first());
            if args.path.is_none() {
                args.path = first_path(&parts);
            }
        }
    }
    args
}

fn fill_fd(args: &mut EventArgs, tok: Option<&String>) {
    if let Some(tok) = tok {
        args.fd = parse_fd_number(tok);
        if let Some(dec) = decode_fd_annotation(tok) {
            if dec.contains("TCP") || dec.contains("UDP") || dec.contains("socket") {
                args.sock_info = Some(dec);
            } else {
                args.fd_path = Some(dec);
            }
        }
    }
}

fn split_top_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '(' | '{' | '[' => {
                depth += 1;
                cur.push(c);
            }
            ')' | '}' | ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                let t = cur.trim().to_string();
                if !t.is_empty() {
                    out.push(t);
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        out.push(t);
    }
    out
}

fn first_path(parts: &[String]) -> Option<String> {
    for p in parts {
        if let Some(s) = unquote(p) {
            if s.starts_with('/') || s.starts_with('.') || s.contains('/') {
                return Some(s);
            }
        }
    }
    None
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Some(unescape(&s[1..s.len() - 1]));
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_fd_number(tok: &str) -> Option<i32> {
    let tok = tok.trim();
    if tok == "AT_FDCWD" {
        return Some(-100);
    }
    let num = tok.split('<').next().unwrap_or(tok);
    num.parse().ok()
}

fn decode_fd_annotation(tok: &str) -> Option<String> {
    let start = tok.find('<')?;
    let end = tok.rfind('>')?;
    if end <= start + 1 {
        return None;
    }
    Some(tok[start + 1..end].to_string())
}

fn parse_hex_addr(tok: &str) -> Option<u64> {
    let tok = tok.trim();
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

fn parse_pipe_fds(raw: &str) -> Option<(i32, i32)> {
    let inner = raw.find('[')?;
    let rest = &raw[inner + 1..];
    let end = rest.find(']')?;
    let parts = split_top_args(&rest[..end]);
    if parts.len() >= 2 {
        return Some((parse_fd_number(&parts[0])?, parse_fd_number(&parts[1])?));
    }
    None
}

pub fn looks_like_strace(text: &str) -> bool {
    text.lines()
        .take(20)
        .filter(|l| !l.trim().is_empty())
        .any(|l| split_timestamp(strip_pid_prefix(l.trim()).1).is_some())
}

pub const STRACE_FILTER: &str = "%file,%network,%desc,%process";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openat_read_close() {
        let body = r#"openat(AT_FDCWD, "/app/www/index.html", O_RDONLY) = 3</app/www/index.html> <0.000010>"#;
        let (name, args, ret, errno) = parse_completed(body).unwrap();
        assert_eq!(name, "openat");
        assert_eq!(args.path.as_deref(), Some("/app/www/index.html"));
        assert_eq!(args.fd, Some(3));
        assert_eq!(ret, Some(3));
        assert!(errno.is_none());
    }

    #[test]
    fn parses_failed_open() {
        let body = r#"openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000008>"#;
        let (_, _, ret, errno) = parse_completed(body).unwrap();
        assert_eq!(ret, Some(-1));
        assert_eq!(errno.as_deref(), Some("ENOENT"));
    }

    #[test]
    fn unfinished_and_resumed() {
        let mut p = FileParser {
            pid_hint: Some(9),
            unfinished: HashMap::new(),
            stats: ParseStats::default(),
        };
        assert!(p
            .push_line("1000.000001 read(3,  <unfinished ...>")
            .is_none());
        let ev = p
            .push_line(r#"1000.000002 <... read resumed> "hi", 4096) = 2 <0.0001>"#)
            .unwrap();
        assert_eq!(ev.name, "read");
        assert_eq!(ev.ret, Some(2));
        assert_eq!(ev.args.fd, Some(3));
    }
}
