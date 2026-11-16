//! معادل ویندوزیِ `data/SecretStore.kt` — انبار رازِ مهرشده.
//!
//! # چرا نه فقط یک فایل JSON کنار پروفایل
//!
//! کلید API کاربر یک اطلاعات محرمانه است و باید مثل یکی با آن رفتار شود. در
//! اندروید با یک کلید AES-GCM سخت‌افزاری از Android Keystore مهر می‌شود. معادلِ
//! *واقعیِ* آن روی ویندوز — و نه یک هم‌سنگ سلیقه‌ای — همان چیزی است که خود
//! ویندوز برای همین کار دارد: **DPAPI** (`CryptProtectData`). کلیدِ رمزنگاری از
//! نشستِ ورودِ همین کاربر مشتق می‌شود، هرگز در دسترس فرآیند ما نیست، و متن
//! رمزشده روی هیچ حساب کاربری یا دستگاه دیگری باز نمی‌شود. یعنی فایل
//! `secrets.bin` که از پروفایل کاربر بیرون کشیده شود، به‌تنهایی بی‌ارزش است.
//!
//! `CRYPTPROTECT_UI_FORBIDDEN` هم صریح پاس داده می‌شود: این کد ممکن است از
//! رشتهٔ پس‌زمینه صدا زده شود و DPAPI هرگز نباید اجازه داشته باشد یک پنجرهٔ
//! گفت‌وگو بالا بیاورد که هیچ‌کس منتظرش نیست.
//!
//! # قاعده‌های دیگری که از موبایل می‌آیند
//!
//! * انبارِ راز از `profile.json` جدا است. پروفایل با «بازنشانی همهٔ تنظیمات»
//!   پاک می‌شود؛ کلید API نه. ازدست‌دادن کلید به‌خاطر اینکه کسی MTU‌اش را ریست
//!   کرده، آزاردهنده است — همان استدلال `GeminiStore` که DataStore جداگانه دارد.
//! * کلید پیش از ذخیره `trim` می‌شود. کلیدی که از یک صفحهٔ وب کپی می‌شود تقریباً
//!   همیشه با یک newline یا فاصلهٔ اضافی می‌آید و کلیدِ دارای فاصله با یک ۴۰۰
//!   شکست می‌خورد که هیچ چیز مفیدی درباره‌ی علتش نمی‌گوید.
//! * نوشتن اتمیک است (فایل موقت + rename)، مثل `ProfileStore`.

use crate::log::DiagnosticsLog;
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// نامِ کلیدِ رازِ Gemini در انبار.
pub const GEMINI_KEY: &str = "geminiApiKey";

pub struct SecretStore {
    path: PathBuf,
}

impl SecretStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("secrets.bin"),
        }
    }

    pub fn read(&self, name: &str) -> String {
        self.read_all().get(name).cloned().unwrap_or_default()
    }

    pub fn write(&self, name: &str, value: &str) -> Result<()> {
        let mut all = self.read_all();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            all.remove(name);
        } else {
            all.insert(name.to_string(), trimmed.to_string());
        }
        self.write_all(&all)
    }

    fn read_all(&self) -> BTreeMap<String, String> {
        let sealed = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(_) => return BTreeMap::new(),
        };
        match unprotect(&sealed) {
            Ok(plain) => serde_json::from_slice(&plain).unwrap_or_default(),
            Err(e) => {
                DiagnosticsLog::w(
                    "ai",
                    &format!(
                        "The sealed secret store could not be opened ({e}); treating it as empty."
                    ),
                );
                BTreeMap::new()
            }
        }
    }

    fn write_all(&self, all: &BTreeMap<String, String>) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if all.is_empty() {
            let _ = std::fs::remove_file(&self.path);
            return Ok(());
        }
        let plain = serde_json::to_vec(all)?;
        let sealed = protect(&plain)?;
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub(crate) fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    protect(plain)
}

pub(crate) fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    unprotect(sealed)
}

#[cfg(windows)]
fn protect(plain: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &mut input,
            windows::core::w!("Aether secrets"),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| anyhow!("CryptProtectData failed: {e}"))?;
        let sealed = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(sealed)
    }
}

#[cfg(windows)]
fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: sealed.len() as u32,
            pbData: sealed.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| anyhow!("CryptUnprotectData failed: {e}"))?;
        let plain = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(plain)
    }
}

#[cfg(not(windows))]
fn linux_seal_key() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut ikm = Vec::new();
    if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
        ikm.extend_from_slice(mid.trim().as_bytes());
    }
    if let Ok(home) = std::env::var("HOME") {
        ikm.extend_from_slice(home.as_bytes());
    }
    if let Ok(user) = std::env::var("USER") {
        ikm.extend_from_slice(user.as_bytes());
    }
    if ikm.is_empty() {
        ikm.extend_from_slice(b"aether-linux-fallback-ikm");
    }
    let hk = Hkdf::<Sha256>::new(Some(b"AetherDesktop-Linux-SecretStore-v1"), &ikm);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"chacha20poly1305-seal", &mut key);
    key
}

#[cfg(not(windows))]
fn linux_random_nonce() -> [u8; 12] {
    use std::io::Read;
    let mut nonce = [0u8; 12];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut nonce).is_ok() {
            return nonce;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nonce[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    nonce
}

#[cfg(not(windows))]
const LINUX_SEAL_MAGIC: &[u8; 5] = b"AETH1";

#[cfg(not(windows))]
fn protect(plain: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use zeroize::Zeroize;

    let mut key_bytes = linux_seal_key();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let nonce_bytes = linux_random_nonce();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain)
        .map_err(|e| anyhow!("Linux secret store encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(LINUX_SEAL_MAGIC.len() + nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(LINUX_SEAL_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[cfg(not(windows))]
fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use zeroize::Zeroize;

    let header = LINUX_SEAL_MAGIC.len() + 12;
    if sealed.len() < header || &sealed[..5] != LINUX_SEAL_MAGIC {
        return Err(anyhow!("invalid or unsealed Linux secret store blob"));
    }
    let mut key_bytes = linux_seal_key();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(&sealed[5..17]);
    cipher
        .decrypt(nonce, &sealed[17..])
        .map_err(|e| anyhow!("Linux secret store decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_trims() {
        let dir = std::env::temp_dir().join(format!("aether-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SecretStore::new(&dir);

        assert_eq!(store.read(GEMINI_KEY), "");
        store.write(GEMINI_KEY, "  AIzaExampleKey \n").unwrap();
        assert_eq!(store.read(GEMINI_KEY), "AIzaExampleKey");

        store.write(GEMINI_KEY, "").unwrap();
        assert_eq!(store.read(GEMINI_KEY), "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
