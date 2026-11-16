//! weirdnetctl: Weirdnet signing keys and the records they sign.

mod keyfile;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use libp2p_identity::Keypair;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use weirdnet_schemes::names;
use weirdnet_schemes::signed::{decode_key, encode_key, key_id};
use weirdnet_schemes::*;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "weirdnetctl", version, about = "Weirdnet signing keys, records and the canonical list")]
struct Cli {
    /// Read the passphrase from this file instead of asking (first line; for scripts).
    #[arg(long, global = true, env = "WEIRDNETCTL_PASSPHRASE_FILE")]
    passphrase_file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Signing keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Signs a prefix registration (or withdrawal) as its publisher.
    Prefix {
        /// The publisher's key file.
        #[arg(long)]
        key: PathBuf,
        /// The prefix, such as `acme` or `weirdnet-morph`.
        #[arg(long)]
        prefix: String,
        /// Must be higher than the last record's.
        #[arg(long)]
        seq: u64,
        /// How long it is good for.
        #[arg(long, default_value_t = 365)]
        expires_days: u64,
        /// Withdraw the prefix instead.
        #[arg(long)]
        withdraw: bool,
        /// Write here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Signs a scheme registration (or withdrawal) as its publisher.
    Scheme {
        /// The publisher's key file.
        #[arg(long)]
        key: PathBuf,
        /// The scheme, such as `weirdnet-morph`.
        #[arg(long)]
        scheme: String,
        /// The prefix it falls under (the publisher must hold it).
        #[arg(long)]
        prefix: String,
        /// A stable app id, such as `org.weirdbrains.morph`.
        #[arg(long)]
        app_id: String,
        /// The app's name.
        #[arg(long)]
        name: String,
        /// What the handler does (repeat): browse, join, answer, ...
        #[arg(long = "cap")]
        caps: Vec<String>,
        /// Where to get the app (repeat): salty-gull=ID, app-store=ID, play=PKG, f-droid=PKG,
        /// https=URL.
        #[arg(long = "install")]
        install: Vec<String>,
        /// Must be higher than the last record's.
        #[arg(long)]
        seq: u64,
        /// How long it is good for.
        #[arg(long, default_value_t = 365)]
        expires_days: u64,
        /// Withdraw the scheme instead.
        #[arg(long)]
        withdraw: bool,
        /// Write here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Adds a signature to a signed record: `root` for a reserved prefix or scheme, or
    /// `transfer` from a prefix's previous holder.
    Countersign {
        /// The signing key file.
        #[arg(long)]
        key: PathBuf,
        /// What the signature speaks for.
        #[arg(long = "as", value_enum)]
        role: SignAs,
        /// The signed record.
        file: PathBuf,
        /// Write here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Builds and signs the canonical list from signed records, countersigning reserved
    /// records with the root key where needed, then checks it loads.
    List {
        /// The root key file.
        #[arg(long)]
        key: PathBuf,
        /// Must be higher than the published list's.
        #[arg(long)]
        seq: u64,
        /// How long it is good for.
        #[arg(long, default_value_t = 90)]
        expires_days: u64,
        /// Signed prefix and scheme records.
        records: Vec<PathBuf>,
        /// Write here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Checks a signed record, list or rotation and says what it is.
    Verify {
        /// Trusted root keys (text form). Needed for lists, reserved records and rotations.
        #[arg(long = "anchor")]
        anchors: Vec<String>,
        /// The file.
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Makes a new Ed25519 key, sealed with a passphrase.
    New {
        /// The new key file (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// What it is for, such as `weirdbrains-root` or `acme-publisher`.
        #[arg(long, default_value = "weirdnet-signing")]
        label: String,
        /// Store the key without a passphrase (tests and throwaway keys only).
        #[arg(long)]
        unencrypted: bool,
    },
    /// Prints a key file's public key and key id.
    Show {
        /// The key file.
        key: PathBuf,
    },
    /// Checks the passphrase opens the key.
    Check {
        /// The key file.
        key: PathBuf,
    },
    /// Makes a new key and a rotation signed by both the old and the new key. Ship the new
    /// public key as an anchor and publish the rotation; keep the old key file offline.
    Rotate {
        /// The current key file.
        #[arg(long)]
        key: PathBuf,
        /// The new key file (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// The signed rotation (must not exist).
        #[arg(long)]
        rotation: PathBuf,
        /// The new key's label (default: the old one's).
        #[arg(long)]
        label: Option<String>,
        /// Store the new key without a passphrase (tests only).
        #[arg(long)]
        unencrypted: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SignAs {
    Root,
    Transfer,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn days(d: u64) -> Result<u64> {
    if d == 0 || d > 3650 {
        bail!("expiry must be 1 to 3650 days");
    }
    Ok(now() + d * 86400)
}

struct Ctx {
    passphrase_file: Option<PathBuf>,
}

impl Ctx {
    fn passphrase(&self, prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
        if let Some(f) = &self.passphrase_file {
            let s = Zeroizing::new(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?);
            let line = Zeroizing::new(s.lines().next().unwrap_or("").to_string());
            if line.is_empty() {
                bail!("the passphrase file is empty");
            }
            return Ok(line);
        }
        let p = Zeroizing::new(rpassword::prompt_password(prompt)?);
        if confirm {
            if p.chars().count() < 12 {
                bail!("use at least 12 characters");
            }
            let again = Zeroizing::new(rpassword::prompt_password("again: ")?);
            if *again != *p {
                bail!("the passphrases differ");
            }
        }
        Ok(p)
    }

    fn open(&self, path: &Path) -> Result<Keypair> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        keyfile::open(&bytes, || self.passphrase(&format!("passphrase for {}: ", path.display()), false))
    }

    fn new_key(&self, out: &Path, label: &str, unencrypted: bool, kp: &Keypair) -> Result<()> {
        let pass = if unencrypted { None } else { Some(self.passphrase(&format!("new passphrase for {}: ", out.display()), true)?) };
        let bytes = keyfile::seal(kp, label, pass.as_ref().map(|p| p.as_bytes()), keyfile::KDF)?;
        keyfile::write_new(out, &bytes)
    }
}

fn emit(out: Option<&Path>, s: &Signed) -> Result<()> {
    let json = serde_json::to_string_pretty(s)? + "\n";
    match out {
        Some(p) => std::fs::write(p, json).with_context(|| format!("writing {}", p.display())),
        None => {
            print!("{json}");
            Ok(())
        }
    }
}

fn read_signed(p: &Path) -> Result<Signed> {
    serde_json::from_slice(&std::fs::read(p).with_context(|| format!("reading {}", p.display()))?)
        .with_context(|| format!("{} is not a signed record", p.display()))
}

fn hint(s: &str) -> Result<InstallHint> {
    let (k, v) = s.split_once('=').ok_or_else(|| anyhow!("--install KIND=VALUE, got {s:?}"))?;
    Ok(match k {
        "salty-gull" => InstallHint::SaltyGull(v.into()),
        "app-store" => InstallHint::AppStore(v.into()),
        "play" => InstallHint::Play(v.into()),
        "f-droid" => InstallHint::FDroid(v.into()),
        "https" => InstallHint::Https(v.into()),
        _ => bail!("unknown install kind {k}: salty-gull, app-store, play, f-droid or https"),
    })
}

/// The prefix a prefix or scheme record falls under, and its publisher key.
fn prefix_of(s: &Signed) -> Result<(String, String, String)> {
    Ok(match s.kind.as_str() {
        "prefix" => {
            let r: PrefixRecord = s.record("prefix")?;
            r.check()?;
            (r.prefix.clone(), r.publisher, format!("prefix {}", r.prefix))
        }
        "scheme" => {
            let r: SchemeRecord = s.record("scheme")?;
            r.check()?;
            (r.prefix, r.publisher, format!("scheme {} ({})", r.scheme, r.app_id))
        }
        k => bail!("expected a prefix or scheme record, got {k}"),
    })
}

fn run(cli: Cli) -> Result<()> {
    let ctx = Ctx { passphrase_file: cli.passphrase_file };
    match cli.cmd {
        Cmd::Key(KeyCmd::New { out, label, unencrypted }) => {
            let kp = Keypair::generate_ed25519();
            ctx.new_key(&out, &label, unencrypted, &kp)?;
            println!("{}\nkey id {}", encode_key(&kp.public()), key_id(&kp.public()));
        }
        Cmd::Key(KeyCmd::Show { key }) => {
            let i = keyfile::info(&key)?;
            println!(
                "{}\nkey id {}\nlabel {}\n{}",
                i.public,
                i.key_id,
                i.label,
                if i.encrypted { "sealed with a passphrase" } else { "NOT encrypted" }
            );
        }
        Cmd::Key(KeyCmd::Check { key }) => {
            let kp = ctx.open(&key)?;
            println!("ok: {}", key_id(&kp.public()));
        }
        Cmd::Key(KeyCmd::Rotate { key, out, rotation, label, unencrypted }) => {
            if rotation.exists() {
                bail!("{} exists", rotation.display());
            }
            let old = ctx.open(&key)?;
            let label = label.unwrap_or(keyfile::info(&key)?.label);
            let new = Keypair::generate_ed25519();
            let signed = RootRotation::sign(&old, &new, now())?;
            ctx.new_key(&out, &label, unencrypted, &new)?;
            emit(Some(&rotation), &signed)?;
            println!("{}\nkey id {}\nrotation: {}", encode_key(&new.public()), key_id(&new.public()), rotation.display());
        }
        Cmd::Prefix { key, prefix, seq, expires_days, withdraw, out } => {
            let kp = ctx.open(&key)?;
            let mut r = PrefixRecord::new(&prefix.to_ascii_lowercase(), &kp.public(), seq, days(expires_days)?);
            r.withdrawn = withdraw;
            let s = r.sign(&kp)?;
            if names::is_reserved(&r.prefix) {
                eprintln!("{} is reserved: it needs a root countersignature and a place on the canonical list", r.prefix);
            }
            emit(out.as_deref(), &s)?;
        }
        Cmd::Scheme { key, scheme, prefix, app_id, name, caps, install, seq, expires_days, withdraw, out } => {
            let kp = ctx.open(&key)?;
            let r = SchemeRecord {
                format: records::FORMAT,
                scheme: scheme.to_ascii_lowercase(),
                prefix: prefix.to_ascii_lowercase(),
                app_id,
                publisher: encode_key(&kp.public()),
                display_name: name,
                capabilities: caps,
                install: install.iter().map(|h| hint(h)).collect::<Result<_>>()?,
                seq,
                expires: days(expires_days)?,
                withdrawn: withdraw,
            };
            emit(out.as_deref(), &r.sign(&kp)?)?;
        }
        Cmd::Countersign { key, role, file, out } => {
            let s = read_signed(&file)?;
            let (prefix, publisher, what) = prefix_of(&s)?;
            if !s.signed_by(Role::Publisher, &decode_key(&publisher)?) {
                bail!("{what} is not signed by its publisher");
            }
            let kp = ctx.open(&key)?;
            let role = match role {
                SignAs::Root => {
                    if !names::is_reserved(&prefix) {
                        eprintln!("note: {prefix} is not reserved; a root signature is not needed");
                    }
                    Role::Root
                }
                SignAs::Transfer => {
                    if s.kind != "prefix" {
                        bail!("transfers are signed on prefix records");
                    }
                    if encode_key(&kp.public()) == publisher {
                        bail!("a transfer is signed by the previous holder, not the new one");
                    }
                    Role::Transfer
                }
            };
            eprintln!("signing {what} for publisher {}", key_id(&decode_key(&publisher)?));
            emit(out.as_deref(), &s.sign(role, &kp)?)?;
        }
        Cmd::List { key, seq, expires_days, records, out } => {
            let root = ctx.open(&key)?;
            let (mut prefixes, mut schemes) = (Vec::new(), Vec::new());
            for p in &records {
                let mut s = read_signed(p)?;
                let (prefix, publisher, what) = prefix_of(&s)?;
                if !s.signed_by(Role::Publisher, &decode_key(&publisher)?) {
                    bail!("{}: {what} is not signed by its publisher", p.display());
                }
                if names::is_reserved(&prefix) && !s.signed_by(Role::Root, &root.public()) {
                    eprintln!("countersigning {what}");
                    s = s.sign(Role::Root, &root)?;
                }
                if s.kind == "prefix" { prefixes.push(s) } else { schemes.push(s) }
            }
            let issued = now();
            let list = CanonicalList { format: records::FORMAT, seq, issued, expires: days(expires_days)?, prefixes, schemes }.sign(&root)?;
            // It must load in a fresh registry trusting only this root.
            Registry::new(TrustAnchors::from_keys(vec![root.public()])).load_canonical(&list, issued).context("the list does not load")?;
            emit(out.as_deref(), &list)?;
        }
        Cmd::Verify { anchors, file } => {
            let s = read_signed(&file)?;
            let anchors = TrustAnchors::new(&anchors)?;
            let root_ok = |s: &Signed| s.signed_by_any(Role::Root, anchors.keys());
            match s.kind.as_str() {
                "list" => {
                    let l: CanonicalList = s.record("list")?;
                    if anchors.keys().is_empty() {
                        bail!("give the root key with --anchor");
                    }
                    Registry::new(anchors.clone()).load_canonical(&s, now())?;
                    println!("ok: canonical list seq {}, {} prefixes, {} schemes, expires {}", l.seq, l.prefixes.len(), l.schemes.len(), l.expires);
                }
                "root-rotation" => {
                    let r: RootRotation = s.record("root-rotation")?;
                    let mut a = anchors.clone();
                    a.rotate(&s)?;
                    println!("ok: rotation from {} to {}", key_id(&decode_key(&r.old)?), key_id(&decode_key(&r.new)?));
                }
                _ => {
                    let (prefix, publisher, what) = prefix_of(&s)?;
                    if !s.signed_by(Role::Publisher, &decode_key(&publisher)?) {
                        bail!("{what} is not signed by its publisher");
                    }
                    let reserved = names::is_reserved(&prefix);
                    if reserved && !root_ok(&s) {
                        bail!("{what} is reserved and has no root signature from the given anchors");
                    }
                    let transfer = s.sigs.iter().any(|x| x.role == Role::Transfer);
                    println!(
                        "ok: {what}, publisher {}{}{}",
                        key_id(&decode_key(&publisher)?),
                        if reserved { ", root-signed" } else { "" },
                        if transfer { ", with a transfer signature (checked against the previous holder when added)" } else { "" }
                    );
                }
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("weirdnetctl: {e:#}");
        std::process::exit(1);
    }
}
