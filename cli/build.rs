// Embed the release version and the git commit the binary was built from
// into the binary at compile time (exposed via `nova-slim --version`).
//
// The version becomes "X.Y.Z (abcd123)" when built from a git checkout, and
// plain "X.Y.Z" in release tarballs without a git directory.

use std::env;
use std::process::Command;

fn main() {
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let version = if commit.is_empty() {
        pkg_version
    } else {
        format!("{pkg_version} ({commit})")
    };

    // Re-run on git state changes and on this script itself.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rustc-env=NOVA_SLIM_VERSION={version}");
}