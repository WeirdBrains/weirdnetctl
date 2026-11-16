# Security

Report problems privately to m3talsmith@gmail.com.

- Key files are sealed with Argon2id (256 MiB, 3 passes by default; the costs are stored
  in the file) and XChaCha20-Poly1305. The label and public key are bound as associated
  data, so swapping them breaks the file. The secret is zeroized after use.
- Files are created new with mode 0600 (on Unix) and never replaced.
- Every signing command checks the record first: names, shape and the publisher's
  signature. `list` refuses unsigned or tampered records, and checks that the finished
  list loads in a registry that trusts only its root.
- Keep the root key offline. Anyone holding it and its passphrase can sign canonical
  lists and reserved prefixes for every Weirdnet app.

## Limits

- `--unencrypted` keys and passphrase files are only as safe as the disk they're on.
- `verify` checks transfer signatures for shape only. Whether the signer was the previous
  holder is checked by the registry when the record is added.
