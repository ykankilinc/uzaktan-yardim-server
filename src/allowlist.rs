//! Uzaktan Yardım: bağlantı izin listesi.
//!
//! `ALLOWLIST_FILE` ortam değişkeni tanımlıysa, yalnızca bu dosyada yazan
//! ID'lere bağlantı (punch hole / relay) isteği iletilir. Dosya her satırda bir
//! ID içerir; boş satırlar ve `#` ile başlayanlar yok sayılır. Dosya birkaç
//! saniyede bir, değiştiyse yeniden okunur.
//!
//! Değişken tanımlı değilse filtre kapalıdır (upstream davranışı). Tanımlı ama
//! dosya hiç okunamamışsa hiçbir ID'ye izin verilmez.
//!
//! `ALLOWLIST_REJECT_LOG` tanımlıysa reddedilen her istek bu dosyaya JSON satırı
//! olarak eklenir (`{"t":<unix>,"ip":"..","id":".."}`); panel buradan okur.
//! Dosya 1 MB'ı geçince `.1` uzantısıyla bir kez döndürülür.

use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    sync::RwLock,
    time::{Duration, Instant, SystemTime},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(3);
const REJECT_LOG_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
struct State {
    ids: HashSet<String>,
    mtime: Option<SystemTime>,
    checked: Option<Instant>,
}

static PATH: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("ALLOWLIST_FILE").ok().filter(|p| !p.is_empty()));
static STATE: Lazy<RwLock<State>> = Lazy::new(Default::default);
static REJECT_LOG: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("ALLOWLIST_REJECT_LOG").ok().filter(|p| !p.is_empty()));

pub fn record_rejection(ip: std::net::IpAddr, id: &str) {
    let Some(path) = REJECT_LOG.as_deref() else {
        return;
    };
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        v4 => v4.to_string(),
    };
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // ID ve IP yalnızca rakam/nokta/iki nokta içerir; yine de JSON için kaçışla.
    let line = format!(
        "{{\"t\":{t},\"ip\":{},\"id\":{}}}\n",
        json_str(&ip),
        json_str(id)
    );
    if std::fs::metadata(path).map_or(false, |m| m.len() > REJECT_LOG_MAX_BYTES) {
        let _ = std::fs::rename(path, format!("{path}.1"));
    }
    use std::io::Write;
    let res = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = res {
        log::warn!("Red kaydı yazılamadı ({path}): {e}");
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn is_allowed(id: &str) -> bool {
    let Some(path) = PATH.as_deref() else {
        return true;
    };
    refresh(path);
    STATE.read().unwrap().ids.contains(id)
}

fn refresh(path: &str) {
    if let Some(checked) = STATE.read().unwrap().checked {
        if checked.elapsed() < CHECK_INTERVAL {
            return;
        }
    }
    let mut state = STATE.write().unwrap();
    state.checked = Some(Instant::now());
    let mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Allowlist okunamadı ({path}): {e}");
            return;
        }
    };
    if state.mtime == Some(mtime) {
        return;
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            state.ids = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect();
            state.mtime = Some(mtime);
            log::info!("Allowlist yüklendi: {} ID", state.ids.len());
        }
        Err(e) => log::warn!("Allowlist okunamadı ({path}): {e}"),
    }
}
