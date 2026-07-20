use std::path::PathBuf;

// Keep in sync with LIBPCAPNG_SOURCES in lib/CMakeLists.txt.
const C_SOURCES: &[&str] = &[
    "blocks.c",
    "easyapi.c",
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
    "objects.c",
    "posa.c",
    "wire_layout.c",
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

    // Compile libpcapng C sources into a static library.
    let mut build = cc::Build::new();
    build
        .include(&inc_root)
        .warnings(false);

    for src in C_SOURCES {
        build.file(src_root.join(src));
    }

    // Windows needs ws2_32 for Winsock (ntohs/inet_ntop/etc.).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
    }

    build.compile("pcapng");

    // Rebuild triggers.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");

    // Generate bindings with bindgen.
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", inc_root.display()))
        .layout_tests(false)
        .allowlist_function("libpcapng_.*")
        .allowlist_function("pcapng_.*")
        .allowlist_type("pcapng_.*")
        .allowlist_type("foreach_pcapng_block_cb")
        .allowlist_var("PCAPNG_.*")
        .allowlist_var("BLOCK_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("bindings.rs")).expect("write bindings");
}
