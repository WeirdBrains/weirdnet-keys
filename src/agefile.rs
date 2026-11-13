//! Password (scrypt) age files.
use crate::error::{KeysError, Result};
use secrecy::SecretString;
use zeroize::Zeroizing;

/// scrypt work factor for new files (2^16).
pub const WORK_FACTOR: u8 = 16;

pub fn encrypt(password: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut r = age::scrypt::Recipient::new(password.clone());
    r.set_work_factor(WORK_FACTOR);
    age::encrypt(&r, plaintext).map_err(|e| KeysError::crypto(format!("age: {e}")))
}

/// First line of an ASCII-armored age file.
const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// Decrypts a binary or ASCII-armored file (whitespace before the armor is ignored); age
/// bounds the work factor it accepts. A wrong password and a damaged file both give
/// [`KeysError::Unlock`].
pub fn decrypt(password: &SecretString, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let id = age::scrypt::Identity::new(password.clone());
    // age's armor reader wants the marker at the first byte; pasted or edited files often
    // start with a blank line.
    let ct = if is_armored(ct) { ct.trim_ascii_start() } else { ct };
    age::decrypt(&id, ct).map(Zeroizing::new).map_err(|e| KeysError::Unlock(format!("could not decrypt export (wrong password?): {e}")))
}

/// True for an age file, binary or ASCII-armored.
pub fn is_age(bytes: &[u8]) -> bool {
    bytes.starts_with(b"age-encryption.org/") || is_armored(bytes)
}

/// True for an ASCII-armored age file, allowing whitespace before the armor.
pub fn is_armored(bytes: &[u8]) -> bool {
    bytes.trim_ascii_start().starts_with(ARMOR_BEGIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_wrong_password_and_tamper() {
        let pw = SecretString::from("pw");
        let ct = encrypt(&pw, b"hello").unwrap();
        assert!(is_age(&ct) && !is_age(b"hello"));
        assert_eq!(&decrypt(&pw, &ct).unwrap()[..], b"hello");
        assert!(matches!(decrypt(&SecretString::from("no"), &ct), Err(KeysError::Unlock(_))));
        let mut t = ct.clone();
        let n = t.len() - 3;
        t[n] ^= 1;
        assert!(decrypt(&pw, &t).is_err());
    }

    fn armor(ct: &[u8]) -> String {
        use std::io::Write;
        let mut out = vec![];
        let mut w = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor).unwrap();
        w.write_all(ct).unwrap();
        w.finish().unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn armored_files_read_like_binary_ones() {
        let pw = SecretString::from("pw");
        let text = armor(&encrypt(&pw, b"hello").unwrap());
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        for variant in [text.clone(), format!("\n  \n{text}\n\n"), text.replace('\n', "\r\n")] {
            assert!(is_age(variant.as_bytes()) && is_armored(variant.as_bytes()), "{variant:?}");
            assert_eq!(&decrypt(&pw, variant.as_bytes()).unwrap()[..], b"hello");
        }
        assert!(matches!(decrypt(&SecretString::from("no"), text.as_bytes()), Err(KeysError::Unlock(_))));
        // A damaged body is an error, not plaintext.
        let lines: Vec<&str> = text.lines().collect();
        let mut body = lines[1].to_string();
        body.replace_range(0..1, if body.starts_with('A') { "B" } else { "A" });
        let damaged = [lines[0], &body].into_iter().chain(lines[2..].iter().copied()).collect::<Vec<_>>().join("\n");
        assert!(is_age(damaged.as_bytes()) && decrypt(&pw, damaged.as_bytes()).is_err());
    }

    #[test]
    fn plain_text_is_not_age() {
        for t in ["", "hello", "abandon ability able", " -----BEGIN PGP MESSAGE-----", "x-----BEGIN AGE ENCRYPTED FILE-----"] {
            assert!(!is_age(t.as_bytes()) && !is_armored(t.as_bytes()), "{t:?}");
        }
        assert!(!is_armored(b"age-encryption.org/v1\n"));
    }
}
