// Builds the optional native backend (vendored blst + the C ABI shim) when the
// `native` feature is enabled.  Without the feature this does nothing and the
// crate builds exactly as before.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!(
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_DIR is set by cargo"
    ));
    let native_dir = manifest_dir.join("native");

    if std::env::var_os("CARGO_FEATURE_NATIVE").is_some() {
        let dst = cmake::Config::new(&native_dir)
            .profile("Release")
            .build_target("nova_backend")
            .build();

        /* `cmake::Config::build` leaves the target's static lib in the cmake
           build subdirectory (`<out>/build/`), not `<out>/` itself;
           `.build_target` skips `install`, so no copy lands in `dst`. */
        println!("cargo:rustc-link-search=native={}", dst.join("build").display());
        println!("cargo:rustc-link-lib=static=nova_backend");
        /* nova_backend.cpp.o references blst symbols, so the vendored blst
           archive must sit on the link line *after* nova_backend. */
        println!("cargo:rustc-link-lib=static=blst");
        println!("cargo:rustc-link-lib=stdc++");
    }

    println!("cargo:rerun-if-changed=native/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/include/nova_backend.h");
    println!("cargo:rerun-if-changed=native/src/nova_backend.cpp");
    println!("cargo:rerun-if-changed=native/tests/test_nova_backend.cpp");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NATIVE");
}
