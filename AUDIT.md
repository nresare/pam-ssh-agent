# macOS debug & audit of `pam-ssh-agent`

This document records an audit of `pam-ssh-agent` aimed at making the module build and load on
**macOS** (which uses OpenPAM, not Linux-PAM) and reviewing the authentication / certificate /
verification logic for correctness. The changes in this branch are rebased onto upstream
`main` (v0.9.7).

> A fourth issue found during the audit — certificates were not checked to be *user*
> certificates — was **independently fixed upstream** in commit `8e21d5e` ("Ensure that only
> user certificates can be used to authenticate") while this work was in progress, so it is not
> included here.

## Environment & verification

Performed on macOS (Apple Silicon), MSRV 1.88 / toolchain per `rust-toolchain.toml`. Both
crypto backends were built and tested:

| Check | Result |
|-------|--------|
| `cargo build` (default, pure-Rust) | ✅ produces `target/debug/libpam_ssh_agent.dylib` |
| `cargo test --no-default-features` | ✅ pass |
| `cargo test --no-default-features --features native-crypto` | ✅ pass (OpenSSL) |
| `cargo fmt --check` | ✅ clean |
| `cargo clippy --no-deps` | ✅ clean |

Not exercised here: loading the built `.dylib` into a live OpenPAM stack and authenticating
end-to-end. That depends on local PAM configuration; steps are in `README.md` → "Building and
installing on macOS".

## Findings & fixes

### FIX 1 — macOS cdylib fails to link (platform blocker) — High
* **Where:** build/link layer; `Cargo.toml` declares the module as a `cdylib`.
* **Platform:** macOS only.
* **Problem:** the module references PAM symbols (`pam_get_item`, …) that the loader supplies
  at runtime. The macOS linker refuses undefined symbols by default, so the build fails with
  `Undefined symbols: _pam_get_item`. (The GNU linker on Linux tolerates this, which is why CI
  — Ubuntu only — never caught it.)
* **Fix:** added `build.rs` that, on macOS only, emits
  `cargo::rustc-link-arg-cdylib=-Wl,-undefined,dynamic_lookup`. Scoped to the cdylib and to
  macOS, so the `lib`/test builds and Linux/CI are unaffected.
* **Verified:** the `.dylib` now links and is produced on macOS.

### FIX 2 — logging setup denies authentication when syslog is unavailable — High (availability)
* **Where:** `src/lib.rs::run` (call site) → `src/logging.rs::init_logging` / `init_impl`.
* **Platform:** any host where the syslog socket can't be opened; more likely on macOS.
* **Problem:** `run()` called `init_logging(...)?`. `init_impl` hard-errors if `syslog::unix()`
  cannot connect to `/dev/log`, `/var/run/syslog`, or `/var/run/log`. That error propagated to
  `PAM_AUTH_ERR`, so a logging-setup failure failed **every** authentication closed (lockout).
* **Fix:** `init_logging` is now best-effort at the call site — on failure we write a line to
  stderr and continue. A logging problem can no longer gate authentication. `init_logging`
  keeps its `Result` and idempotency contract; only the call site stops treating failure as
  fatal.

### FIX 4 — `SSH_AUTH_INFO_0` was parsed incorrectly for the sshd special case — Medium (correctness)
* **Where:** `src/lib.rs::check_sshd_special_case`.
* **Platform:** all.
* **Problem:** the code ran `PublicKey::from_openssh()` on the raw `SSH_AUTH_INFO_0` value, but
  `sshd` formats each entry with a leading method token, e.g. `publickey ssh-ed25519 AAAA…`.
  Parsing always failed, so the documented sshd "`sufficient`" shortcut never fired — and worse,
  the parse error propagated, short-circuiting the normal challenge-response path too.
  (Fail-safe: a `sufficient` module that errors is skipped by PAM, so it was a broken feature,
  not a bypass.) Certificates were not handled.
* **Fix:** strip the leading `publickey ` token (tolerating its absence), iterate newline
  entries, and parse each as a certificate or a plain public key based on the key type. Parse
  failures are now **non-fatal** — logged and skipped, falling back to normal challenge-response.
  Certificates are routed through the full `validate_cert` check (window, CA, principal, type)
  so the shortcut is never weaker than the main path; the calling user is threaded in as the
  principal. This requires exposing `validate_cert` (`pub(crate)`) from `src/auth.rs`.
* **Test:** `tests::test_check_sshd_special_case` covers a matching `publickey` entry, an
  untrusted key, non-`sshd` services, an unparseable (non-fatal) entry, and a CA-trusted but
  expired certificate that is correctly rejected.

## Reviewed and assessed OK (no change)

* **Challenge-response core** (`src/auth.rs::authenticate` / `sign_and_verify`): signs a fresh
  32-byte random challenge from `getrandom` and verifies the signature locally; a
  `RemoteFailure` (e.g. an `sk`/hardware key not present) is non-fatal and moves to the next
  key. Sound.
* **Certificate validation** (`src/auth.rs::validate_cert`): window, CA-fingerprint signature,
  user-cert type (upstream `8e21d5e`), principal membership, and empty critical options all
  enforced.
* **Crypto-backend parity** (`src/verify.rs` ↔ `src/nativecrypto.rs`): both paths cover
  Ed25519, ECDSA P-256/384/521, and RSA-SHA256/512, and fail closed otherwise.
* **Home-directory expansion** (`src/expansions.rs`): `~`/`%h` is intentionally unsafe and
  documented as such; left unchanged by design.

## Notes

* **PAM result-code numbering** differs between Linux-PAM and OpenPAM, and `pam-bindings` uses
  the Linux values. This is fail-safe for this module: only the happy path returns
  `PAM_SUCCESS` (`0`, which agrees across both), and every error path collapses to a non-zero
  failure code, which PAM treats as "not success" regardless of the exact number. The
  `PAM_USER` / `PAM_SERVICE` item selectors used in `src/pamext.rs` agree across both
  implementations. No change required; documented for reviewers.

## Remaining (user, on a Mac)

1. Build the release dylib and install per `README.md` → "Building and installing on macOS".
2. Wire it into a test `/etc/pam.d` service (e.g. `sudo_local`) and authenticate via
   Secretive's agent (`SSH_AUTH_SOCK`).
3. Optionally confirm FIX 2 by making the syslog socket unavailable and verifying that
   authentication still succeeds.
