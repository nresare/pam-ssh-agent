// Build script.
//
// On macOS the module is loaded by the OpenPAM runtime, which provides the `pam_*`
// symbols (pam_get_item, etc.) at load time. The macOS linker, unlike the GNU linker
// used on Linux, refuses to produce a dynamic library with unresolved symbols by
// default and the build fails with "Undefined symbols: _pam_get_item". Tell the macOS
// linker to defer those symbols to dynamic lookup at load time.
//
// This is scoped to the cdylib artifact and to macOS only, so it has no effect on the
// `lib`/test builds or on Linux (including CI).
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo::rustc-link-arg-cdylib=-Wl,-undefined,dynamic_lookup");
    }
}
