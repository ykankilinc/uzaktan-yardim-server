//! Uzaktan Yardım: teknisyen anahtarı denetimi.
//!
//! `TECH_TOKENS_FILE` ortam değişkeni tanımlıysa, bağlantı (punch hole / relay)
//! isteğindeki `token` alanı denetlenir. Teknisyen uygulaması panelden eşleşince
//! aldığı anahtarı bu alanda gönderir. Dosyayı panel yazar; her satır:
//!
//!     <anahtarın sha256'sı (hex)>\t<ID'ler>
//!
//! ID alanı `*` (yönetici: hepsi) veya virgülle ayrılmış ID listesidir. Anahtarı
//! olmayan, dosyada bulunmayan veya ID'ye izni olmayan istek reddedilir. Dosya
//! birkaç saniyede bir, değiştiyse yeniden okunur.
//!
//! Değişken tanımlı değilse denetim kapalıdır. Tanımlı ama dosya hiç
//! okunamamışsa hiçbir isteğe izin verilmez.

use hbb_common::{log, sodiumoxide::crypto::hash::sha256};
use once_cell::sync::Lazy;
use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    time::{Duration, Instant, SystemTime},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(3);
pub const DENIED_MESSAGE: &str =
    "Bu cihaza bağlanma yetkiniz yok. Teknisyen uygulamasını panelden eşleştirin veya yöneticiye başvurun.";

enum Scope {
    All,
    Ids(HashSet<String>),
}

#[derive(Default)]
struct State {
    tokens: HashMap<String, Scope>,
    mtime: Option<SystemTime>,
    checked: Option<Instant>,
}

static PATH: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("TECH_TOKENS_FILE").ok().filter(|p| !p.is_empty()));
static STATE: Lazy<RwLock<State>> = Lazy::new(Default::default);

pub fn enabled() -> bool {
    PATH.is_some()
}

fn digest(token: &str) -> String {
    sha256::hash(token.as_bytes())
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Bu anahtarla bu ID'ye bağlanılabilir mi?
pub fn allows(token: &str, id: &str) -> bool {
    let Some(path) = PATH.as_deref() else {
        return true;
    };
    if token.is_empty() {
        return false;
    }
    refresh(path);
    match STATE.read().unwrap().tokens.get(&digest(token)) {
        Some(Scope::All) => true,
        Some(Scope::Ids(ids)) => ids.contains(id),
        None => false,
    }
}

fn parse(content: &str) -> HashMap<String, Scope> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let (hash, ids) = line.split_once('\t')?;
            let hash = hash.trim().to_ascii_lowercase();
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let ids = ids.trim();
            let scope = if ids == "*" {
                Scope::All
            } else {
                Scope::Ids(
                    ids.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect(),
                )
            };
            Some((hash, scope))
        })
        .collect()
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
            log::warn!("Teknisyen anahtarları okunamadı ({path}): {e}");
            return;
        }
    };
    if state.mtime == Some(mtime) {
        return;
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            state.tokens = parse(&content);
            state.mtime = Some(mtime);
            log::info!("Teknisyen anahtarları yüklendi: {}", state.tokens.len());
        }
        Err(e) => log::warn!("Teknisyen anahtarları okunamadı ({path}): {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scopes_and_skips_garbage() {
        let a = digest("admin-token");
        let t = digest("tech-token");
        let content = format!("# yorum\n{a}\t*\n{t}\t111, 222\nbozuk satır\nabc\t333\n");
        let tokens = parse(&content);
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens.get(&a), Some(Scope::All)));
        match tokens.get(&t) {
            Some(Scope::Ids(ids)) => assert!(ids.contains("111") && ids.contains("222")),
            _ => panic!("teknisyen kapsamı okunamadı"),
        }
    }

    #[test]
    fn digest_is_hex_sha256() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
