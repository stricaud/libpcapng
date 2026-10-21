use std::path::{Path, PathBuf};

// The library's C sources. This list and LIBPCAPNG_SOURCES in lib/CMakeLists.txt
// have to agree: the CMake build and this one compile the same library, and a
// file in one and not the other is a link error in whichever is missing it.
//
// `check_sources_match_cmake` below enforces that when building from the repo
// tree, because the comment asking for it was not enough — the two lists drifted
// by five files (flow_hash.c, dfilter.c, reader.c, tls_keylog.c, surgery.c), and
// since dissect.c calls into flow_hash.c and tls_keylog.c, every crate that
// linked pcapng-sys failed with undefined symbols.
const C_SOURCES: &[&str] = &[
    "blocks.c",
    "easyapi.c",
    "flow_hash.c",
    "io.c",
    "protocols/asn1.c",
    "protocols/rdp.c",
    "protocols/ethernet.c",
    "protocols/ipv4.c",
    "protocols/tcp.c",
    "protocols/udp.c",
    "protocols/dns.c",
    "protocols/icmp.c",
    "protocols/flow.c",
    "protocols/dhcp.c",
    "protocols/ntp.c",
    "protocols/ssl.c",
    "protocols/ssh.c",
    "protocols/http2.c",
    "protocols/http2_hpack.c",
    "protocols/http2_stream.c",
    "protocols/tls_stream.c",
    "protocols/tcp_mss.c",
    "reassembly.c",
    "reassembly_tcp.c",
    "capture.c",
    "dissect.c",
    "dfilter.c",
    "objects.c",
    "reader.c",
    "posa.c",
    "community_id.c",
    "wire_layout.c",
    "tls_keylog.c",
    "surgery.c",
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // vendor/ is populated by scripts/sync-sources.sh before `cargo publish`.
    // Fall back to the live repo tree for local development.
    let vendor = manifest.join("vendor");
    let (src_root, inc_root) = if vendor.exists() {
        (vendor.join("src"), vendor.join("include"))
    } else {
        let lib = manifest.join("../../../lib");
        (lib.clone(), lib.join("include"))
    };

    // Checked against CMake whenever the repo tree is reachable — which is not
    // the same as whether vendor/ exists, since a leftover vendor/ from a
    // publish run would otherwise silence the check in the one place it is
    // meant to run. A published crate has no lib/ above it and skips this.
    let cmakelists = manifest.join("../../../lib/CMakeLists.txt");
    if cmakelists.is_file() {
        check_sources_match_cmake(&cmakelists);
        println!("cargo:rerun-if-changed={}", cmakelists.display());
    }

    // Compile libpcapng C sources into a static library.
    let mut build = cc::Build::new();
    build.include(&inc_root).warnings(false);

    for src in C_SOURCES {
        let path = src_root.join(src);
        // Checked here rather than left to the compiler, because `cc` reports a
        // missing source as a failed compiler invocation with the path buried
        // in its output.
        assert!(path.is_file(), "pcapng-sys: C source not found: {}", path.display());
        // Without this, cargo reruns build.rs only when build.rs or wrapper.h
        // changes, so editing the C library leaves a stale static library
        // linked into every dependent crate — the change appears to have had
        // no effect, which is a bewildering thing to debug.
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }

    // Windows needs ws2_32 for Winsock (ntohs/inet_ntop/etc.).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
    }

    build.compile("pcapng");

    // Rebuild triggers. The C sources add their own above; the headers are
    // walked here, since a struct layout can change with no .c file touched.
    //
    // Both trees, not just the public one: `builtin_protos.h` — the embedded
    // .posa decoders, and the file most likely to be regenerated — sits
    // beside the sources in lib/, not in lib/include/. Watching only the
    // include directory meant a regenerated protocol set was compiled into
    // nothing, which looks exactly like the edit having had no effect.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    watch_headers(&inc_root);
    if src_root != inc_root {
        watch_headers(&src_root);
    }

    // Generate bindings with bindgen.
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", inc_root.display()))
        .layout_tests(false)
        .allowlist_function("libpcapng_.*")
        .allowlist_function("pcapng_.*")
        .allowlist_type("pcapng_.*")
        .allowlist_type("libpcapng_.*")
        .allowlist_type("foreach_pcapng_block_cb")
        .allowlist_var("PCAPNG_.*")
        .allowlist_var("LIBPCAPNG_.*")
        .allowlist_var("BLOCK_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("bindings.rs")).expect("write bindings");
}

/// Fail the build if C_SOURCES and LIBPCAPNG_SOURCES have drifted apart.
///
/// Order does not matter — both lists end up in one static library — but
/// membership does, in both directions: a file CMake builds and this one does
/// not becomes an undefined symbol, and one this builds and CMake does not is a
/// source the C library has stopped using.
fn check_sources_match_cmake(cmakelists: &Path) {
    let Ok(text) = std::fs::read_to_string(cmakelists) else {
        // The caller already established that it is a file, so this is a
        // permissions or I/O problem rather than a missing checkout. Not a
        // reason to fail a build that would otherwise succeed.
        println!(
            "cargo:warning=pcapng-sys: cannot read {}, so C_SOURCES was not checked \
             against CMake",
            cmakelists.display()
        );
        return;
    };

    let Some(body) = text
        .split_once("set(LIBPCAPNG_SOURCES")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(body, _)| body)
    else {
        println!(
            "cargo:warning=pcapng-sys: no closed LIBPCAPNG_SOURCES list in {}",
            cmakelists.display()
        );
        return;
    };

    let mut from_cmake: Vec<&str> = body
        .lines()
        // An entry can carry a trailing `#` comment.
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| l.ends_with(".c"))
        .collect();
    from_cmake.sort_unstable();

    let mut from_here: Vec<&str> = C_SOURCES.to_vec();
    from_here.sort_unstable();

    if from_cmake == from_here {
        return;
    }

    let missing: Vec<&str> =
        from_cmake.iter().copied().filter(|f| !from_here.contains(f)).collect();
    let extra: Vec<&str> =
        from_here.iter().copied().filter(|f| !from_cmake.contains(f)).collect();

    let mut msg = format!(
        "pcapng-sys: C_SOURCES in build.rs and LIBPCAPNG_SOURCES in {} disagree.\n",
        cmakelists.display()
    );
    if !missing.is_empty() {
        msg.push_str(&format!(
            "  in CMake but not in build.rs — these become undefined symbols at link \
             time: {missing:?}\n"
        ));
    }
    if !extra.is_empty() {
        msg.push_str(&format!("  in build.rs but not in CMake: {extra:?}\n"));
    }
    msg.push_str("  Edit C_SOURCES in bindings/rust/pcapng-sys/build.rs to match.");
    panic!("{msg}");
}

/// Tell cargo to rerun when any header under `dir` changes.
fn watch_headers(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            watch_headers(&path);
        } else if path.extension().is_some_and(|e| e == "h") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
