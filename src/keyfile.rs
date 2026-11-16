//! Key files: an Ed25519 keypair sealed with a passphrase (Argon2id, then
//! XChaCha20-Poly1305), with the public key in the clear.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use libp2p_identity::Keypair;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use weirdnet_schemes::signed::{encode_key, key_id};
use zeroize::Zeroizing;

const AAD: &str = "weirdnetctl/key/v1\n";

/// Argon2id costs. Stored in the file, so they can rise later without breaking old keys.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Kdf {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// The default: 256 MiB, 3 passes.
pub const KDF: Kdf = Kdf { m: 256 * 1024, t: 3, p: 1 };
const KDF_MIN_M: u32 = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct File {
    format: u32,
    /// What the key is for, such as "weirdbrains-root" (informational).
    label: String,
    public: String,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<Sealed>,
    /// Only for `--unencrypted` keys (tests and throwaway publisher keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plain: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    kdf: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
    ct: String,
}

fn derive(pass: &[u8], salt: &[u8], k: Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(k.m, k.t, k.p, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass, salt, out.as_mut()).map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

fn aad(label: &str, public: &str) -> Vec<u8> {
    format!("{AAD}{label}\n{public}").into_bytes()
}

/// A key file's public part, readable without the passphrase.
pub struct Info {
    /// The label.
    pub label: String,
    /// The public key (text form).
    pub public: String,
    /// Its id.
    pub key_id: String,
    /// Sealed with a passphrase.
    pub encrypted: bool,
}

fn parse(bytes: &[u8]) -> Result<File> {
    let f: File = serde_json::from_slice(bytes).context("not a weirdnetctl key file")?;
    if f.format != 1 {
        bail!("key file format {} is not supported", f.format);
    }
    Ok(f)
}

/// Reads the public part.
pub fn info(path: &Path) -> Result<Info> {
    let f = parse(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)?;
    Ok(Info { label: f.label, public: f.public, key_id: f.key_id, encrypted: f.sealed.is_some() })
}

/// Seals `kp` (or stores it plainly when `pass` is `None`) as key file bytes.
pub fn seal(kp: &Keypair, label: &str, pass: Option<&[u8]>, kdf: Kdf) -> Result<Vec<u8>> {
    let public = encode_key(&kp.public());
    let secret = Zeroizing::new(kp.to_protobuf_encoding().map_err(|e| anyhow!("encoding the key: {e}"))?);
    let mut f = File { format: 1, label: label.into(), public: public.clone(), key_id: key_id(&kp.public()), sealed: None, plain: None };
    match pass {
        None => f.plain = Some(B64.encode(&*secret)),
        Some(pass) => {
            if kdf.m < KDF_MIN_M {
                bail!("argon2 memory below {KDF_MIN_M} KiB");
            }
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut salt).map_err(|e| anyhow!("random: {e}"))?;
            getrandom::fill(&mut nonce).map_err(|e| anyhow!("random: {e}"))?;
            let key = derive(pass, &salt, kdf)?;
            let ct = XChaCha20Poly1305::new(key.as_ref().into())
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: &secret, aad: &aad(label, &public) })
                .map_err(|_| anyhow!("sealing the key"))?;
            f.sealed = Some(Sealed {
                kdf: "argon2id".into(),
                m: kdf.m,
                t: kdf.t,
                p: kdf.p,
                salt: B64.encode(salt),
                nonce: B64.encode(nonce),
                ct: B64.encode(ct),
            });
        }
    }
    Ok(serde_json::to_vec_pretty(&f)?)
}

/// Opens key file bytes. `pass` is asked for only if the key is sealed.
pub fn open(bytes: &[u8], pass: impl FnOnce() -> Result<Zeroizing<String>>) -> Result<Keypair> {
    let f = parse(bytes)?;
    let secret = match (&f.sealed, &f.plain) {
        (Some(s), _) => {
            if s.kdf != "argon2id" {
                bail!("unknown kdf {}", s.kdf);
            }
            let pass = pass()?;
            let key = derive(pass.as_bytes(), &B64.decode(&s.salt)?, Kdf { m: s.m, t: s.t, p: s.p })?;
            let nonce = B64.decode(&s.nonce)?;
            if nonce.len() != 24 {
                bail!("bad nonce");
            }
            Zeroizing::new(
                XChaCha20Poly1305::new(key.as_ref().into())
                    .decrypt(XNonce::from_slice(&nonce), Payload { msg: &B64.decode(&s.ct)?, aad: &aad(&f.label, &f.public) })
                    .map_err(|_| anyhow!("wrong passphrase, or the key file was changed"))?,
            )
        }
        (None, Some(p)) => Zeroizing::new(B64.decode(p)?),
        (None, None) => bail!("the key file holds no key"),
    };
    let kp = Keypair::from_protobuf_encoding(&secret).map_err(|e| anyhow!("decoding the key: {e}"))?;
    if encode_key(&kp.public()) != f.public {
        bail!("the key does not match the public key in the file");
    }
    Ok(kp)
}

/// Writes a new file, never replacing one, readable only by the owner.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Kdf = Kdf { m: KDF_MIN_M, t: 1, p: 1 };

    #[test]
    fn seal_and_open() {
        let kp = Keypair::generate_ed25519();
        let b = seal(&kp, "root", Some(b"hunter2"), FAST).unwrap();
        assert!(!String::from_utf8_lossy(&b).contains(&B64.encode(kp.to_protobuf_encoding().unwrap())));
        let back = open(&b, || Ok(Zeroizing::new("hunter2".into()))).unwrap();
        assert_eq!(back.public(), kp.public());
        assert!(open(&b, || Ok(Zeroizing::new("nope".into()))).is_err());
        // Swapping the label or the public key breaks it.
        let mut f: serde_json::Value = serde_json::from_slice(&b).unwrap();
        f["label"] = "other".into();
        assert!(open(&serde_json::to_vec(&f).unwrap(), || Ok(Zeroizing::new("hunter2".into()))).is_err());
        assert!(seal(&kp, "x", Some(b"p"), Kdf { m: 1024, t: 1, p: 1 }).is_err());
        let plain = seal(&kp, "test", None, FAST).unwrap();
        assert_eq!(open(&plain, || panic!("no passphrase for plain keys")).unwrap().public(), kp.public());
    }
}
