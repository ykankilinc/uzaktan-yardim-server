//! Uzaktan Yardım: bağlantı izin listesi.
//!
//! `ALLOWLIST_FILE` ortam değişkeni tanımlıysa, yalnızca bu dosyada yazan
//! ID'lere bağlantı (punch hole / relay) isteği iletilir. Dosya her satırda bir
//! ID içerir; boş satırlar ve `#` ile başlayanlar yok sayılır. Dosya birkaç
//! saniyede bir, değiştiyse yeniden okunur.
//!
//! Değişken tanımlı değilse filtre kapalıdır (upstream davranışı). Tanımlı ama
//! dosya hiç okunamamışsa hiçbir ID'ye izin verilmez.

use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    sync::RwLock,
    time::{Duration, Instant, SystemTime},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Default)]
struct State {
    ids: HashSet<String>,
    mtime: Option<SystemTime>,
    checked: Option<Instant>,
}

static PATH: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("ALLOWLIST_FILE").ok().filter(|p| !p.is_empty()));
static STATE: Lazy<RwLock<State>> = Lazy::new(Default::default);

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
