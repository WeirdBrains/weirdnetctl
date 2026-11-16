use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("weirdnetctl-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}

fn ctl(d: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_weirdnetctl")).current_dir(d).env_remove("WEIRDNETCTL_PASSPHRASE_FILE").args(args).output().unwrap()
}
fn ok(d: &Path, args: &[&str]) -> String {
    let o = ctl(d, args);
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}
fn fails(d: &Path, args: &[&str]) -> String {
    let o = ctl(d, args);
    assert!(!o.status.success(), "{args:?} should fail: {}", String::from_utf8_lossy(&o.stdout));
    String::from_utf8(o.stderr).unwrap()
}
fn public(d: &Path, key: &str) -> String {
    ok(d, &["key", "show", key]).lines().next().unwrap().to_string()
}

#[test]
fn first_party_flow() {
    let t = dir("flow");
    let d = &t.0;
    ok(d, &["key", "new", "--unencrypted", "--label", "weirdbrains-root", "--out", "root.key"]);
    ok(d, &["key", "new", "--unencrypted", "--out", "morph.key"]);
    assert!(fails(d, &["key", "new", "--unencrypted", "--out", "root.key"]).contains("must not exist"));
    assert!(ok(d, &["key", "show", "root.key"]).contains("NOT encrypted"));
    let root = public(d, "root.key");

    ok(d, &["prefix", "--key", "morph.key", "--prefix", "weirdnet-morph", "--seq", "1", "-o", "p.json"]);
    ok(
        d,
        &[
            "scheme",
            "--key",
            "morph.key",
            "--scheme",
            "weirdnet-morph",
            "--prefix",
            "weirdnet-morph",
            "--app-id",
            "org.weirdbrains.morph",
            "--name",
            "Morph",
            "--cap",
            "browse",
            "--cap",
            "join",
            "--install",
            "salty-gull=org.weirdbrains.morph",
            "--install",
            "https=https://weirdbrains.com/morph",
            "--seq",
            "1",
            "-o",
            "s.json",
        ],
    );
    assert!(
        fails(
            d,
            &["scheme", "--key", "morph.key", "--scheme", "x", "--prefix", "y", "--app-id", "a.b", "--name", "n", "--install", "ftp=x", "--seq", "1"]
        )
        .contains("unknown install kind")
    );
    // A reserved record isn't valid alone until root signs it.
    assert!(fails(d, &["verify", "--anchor", &root, "p.json"]).contains("no root signature"));
    ok(d, &["countersign", "--key", "root.key", "--as", "root", "p.json", "-o", "p2.json"]);
    assert!(ok(d, &["verify", "--anchor", &root, "p2.json"]).contains("root-signed"));

    // The list countersigns the scheme on its own and loads.
    ok(d, &["list", "--key", "root.key", "--seq", "7", "p2.json", "s.json", "-o", "list.json"]);
    let v = ok(d, &["verify", "--anchor", &root, "list.json"]);
    assert!(v.contains("seq 7, 1 prefixes, 1 schemes"), "{v}");
    let other = public(d, "morph.key");
    fails(d, &["verify", "--anchor", &other, "list.json"]);
    fails(d, &["verify", "list.json"]);

    // A tampered record is refused everywhere.
    let mut s: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join("s.json")).unwrap()).unwrap();
    s["body"] = s["body"].as_str().unwrap().replace("Morph", "Evil").into();
    std::fs::write(d.join("bad.json"), s.to_string()).unwrap();
    assert!(fails(d, &["verify", "bad.json"]).contains("not signed by its publisher"));
    fails(d, &["list", "--key", "root.key", "--seq", "8", "bad.json"]);
    fails(d, &["countersign", "--key", "root.key", "--as", "root", "bad.json"]);

    // Transfers are signed by the previous holder, on prefix records.
    ok(d, &["key", "new", "--unencrypted", "--out", "acme2.key"]);
    ok(d, &["prefix", "--key", "acme2.key", "--prefix", "acme", "--seq", "2", "-o", "acme.json"]);
    assert!(fails(d, &["countersign", "--key", "acme2.key", "--as", "transfer", "acme.json"]).contains("previous holder"));
    let t = ok(d, &["countersign", "--key", "morph.key", "--as", "transfer", "acme.json", "-o", "acme-t.json"]);
    assert!(t.is_empty());
    assert!(ok(d, &["verify", "acme-t.json"]).contains("transfer signature"));
    fails(d, &["countersign", "--key", "morph.key", "--as", "transfer", "s.json"]);
}

#[test]
fn sealed_keys_and_rotation() {
    let t = dir("sealed");
    let d = &t.0;
    std::fs::write(d.join("pass"), "correct horse battery staple\n").unwrap();
    std::fs::write(d.join("wrong"), "not it\n").unwrap();
    ok(d, &["--passphrase-file", "pass", "key", "new", "--label", "weirdbrains-root", "--out", "root.key"]);
    let raw = std::fs::read_to_string(d.join("root.key")).unwrap();
    assert!(raw.contains("argon2id") && !raw.contains("\"plain\""));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d.join("root.key")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(ok(d, &["key", "show", "root.key"]).contains("sealed with a passphrase"));
    ok(d, &["--passphrase-file", "pass", "key", "check", "root.key"]);
    assert!(fails(d, &["--passphrase-file", "wrong", "key", "check", "root.key"]).contains("wrong passphrase"));
    let old = public(d, "root.key");

    ok(d, &["--passphrase-file", "pass", "key", "rotate", "--key", "root.key", "--out", "root2.key", "--rotation", "rot.json"]);
    assert!(ok(d, &["key", "show", "root2.key"]).contains("weirdbrains-root"));
    let new = public(d, "root2.key");
    assert!(ok(d, &["verify", "--anchor", &old, "rot.json"]).contains("rotation from"));
    fails(d, &["verify", "--anchor", &new, "rot.json"]);
    assert!(
        fails(d, &["--passphrase-file", "pass", "key", "rotate", "--key", "root.key", "--out", "root3.key", "--rotation", "rot.json"])
            .contains("exists")
    );

    // The new root signs lists the old anchor no longer trusts once rotated.
    ok(d, &["key", "new", "--unencrypted", "--out", "pub.key"]);
    ok(d, &["prefix", "--key", "pub.key", "--prefix", "weirdnet-files", "--seq", "1", "-o", "p.json"]);
    ok(d, &["--passphrase-file", "pass", "list", "--key", "root2.key", "--seq", "1", "p.json", "-o", "l.json"]);
    ok(d, &["verify", "--anchor", &new, "l.json"]);
    fails(d, &["verify", "--anchor", &old, "l.json"]);
}
