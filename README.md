# weirdnetctl

The maintainer's tool for Weirdnet signing keys and the records they sign. It holds and
rotates the [WeirdBrains](https://weirdbrains.com) root key, signs prefix and scheme records for
[weirdnet-schemes](https://github.com/WeirdBrains/weirdnet-schemes), countersigns
reserved `weirdnet…` records, builds the canonical list, and verifies all of them.

```sh
# Keys are Ed25519, sealed with a passphrase (Argon2id, then XChaCha20-Poly1305).
weirdnetctl key new --label weirdbrains-root --out root.key
weirdnetctl key show root.key            # public key, key id: ship it as the trust anchor

# A publisher signs its prefix and scheme.
weirdnetctl prefix --key morph.key --prefix weirdnet-morph --seq 1 -o prefix.json
weirdnetctl scheme --key morph.key --scheme weirdnet-morph --prefix weirdnet-morph \
  --app-id org.weirdbrains.morph --name Morph --cap browse --cap join --cap answer \
  --install salty-gull=org.weirdbrains.morph --install https=https://weirdbrains.com/morph \
  --seq 1 -o scheme.json

# WeirdBrains builds the canonical list, countersigning reserved records as needed.
weirdnetctl list --key root.key --seq 42 prefix.json scheme.json -o canonical.json
weirdnetctl verify --anchor "$(weirdnetctl key show root.key | head -1)" canonical.json
```

| Command | What it does |
| --- | --- |
| `key new` / `show` / `check` | Make a key; print its public key and id; check the passphrase. |
| `key rotate` | Make a new key and a rotation signed by both keys. |
| `prefix`, `scheme` | Sign a registration or, with `--withdraw`, a withdrawal. |
| `countersign --as root` | Add the root signature that reserved records need. |
| `countersign --as transfer` | The previous holder hands a prefix to a new publisher. |
| `list` | Build and sign the canonical list, then check that it loads. |
| `verify` | Check a record, a list, or a rotation against `--anchor` keys. |

## Keys

- Key files are JSON. The public key and label are stored in the clear, and both are bound
  to the sealed key. Files are created with mode 0600 and are never overwritten.
- The passphrase is prompted for, or read from `--passphrase-file` or
  `WEIRDNETCTL_PASSPHRASE_FILE` for scripts. New keys need at least 12 characters when
  typed.
- `--unencrypted` stores a key in the clear. Use it only for tests and throwaway keys.

## Rotating the root key

1. Run `weirdnetctl key rotate --key root.key --out root-2.key --rotation rotation.json`.
2. Publish `rotation.json` and ship the new public key as an anchor in app updates.
   Apps follow the rotation (`TrustAnchors::rotate`) and stop trusting the old key.
3. Sign the next canonical list with the new key, then keep the old key file offline.

See [SECURITY.md](SECURITY.md). License: BSD-3-Clause.
