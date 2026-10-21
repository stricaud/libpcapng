//! Tests for the parts of the safe API that have no C-side test of their own:
//! the protocol registry, display filters, and the pcapng writer.
//!
//! These are deliberately end-to-end rather than unit tests. The bug they are
//! guarding against was not a wrong answer from a function — it was functions
//! that were never compiled into the library, and a header the binding
//! generator never saw, which no amount of unit testing inside Rust would have
//! caught. A test that compiles a filter, dissects a real frame, matches one
//! against the other, writes the frame to a pcapng file and reads it back
//! exercises every layer that was broken.

use libpcapng::{ensure_protocols, DisplayFilter, Dissection, Writer, LINKTYPE_ETHERNET};

/// An Ethernet/IPv4/TCP frame carrying `payload`, built by hand so the tests
/// need no capture file.
fn frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&1000u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&2000u32.to_be_bytes()); // ack
    tcp.push(5 << 4); // data offset, no options
    tcp.push(0x18); // PSH | ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum, left unset
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    tcp.extend_from_slice(payload);

    let total = (20 + tcp.len()) as u16;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0x00]);
    ip.push(64); // TTL
    ip.push(6); // TCP
    ip.extend_from_slice(&[0, 0]); // header checksum, left unset
    ip.extend_from_slice(&[203, 0, 113, 9]);
    ip.extend_from_slice(&[10, 0, 0, 5]);

    let mut eth = Vec::with_capacity(14 + ip.len() + tcp.len());
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth.extend_from_slice(&tcp);
    eth
}

fn http_get() -> Vec<u8> {
    frame(
        b"GET /cgi-bin/status?cmd=id HTTP/1.1\r\nHost: victim.example\r\n\r\n",
        40000,
        80,
    )
}

#[test]
fn the_protocol_registry_brings_the_posa_decoders_with_it() {
    ensure_protocols();
    // Idempotent: calling it again must not undo anything.
    ensure_protocols();

    let f = http_get();
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).expect("dissect");
    // HTTP/1.x is a POSA decoder compiled into the library, not a C dissector.
    // If the registry were empty this would report `tcp`.
    //
    // Compared without regard to case on purpose: `proto()` is the dissection's
    // column, which a POSA decoder sets with `col` and spells however it likes
    // ("HTTP"), while the C dissectors use their lowercase abbreviation
    // ("tcp"). Field *abbrevs* are consistently lowercase; this one string is
    // not, so nothing should be asserted about its case.
    assert_eq!(d.proto().to_ascii_lowercase(), "http");
    assert_eq!(d.src(), "203.0.113.9");
    assert!(d.info().contains("/cgi-bin/status"), "info was {:?}", d.info());
}

#[test]
fn a_display_filter_compiles_and_matches() {
    ensure_protocols();
    let f = http_get();
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();

    for expr in [
        "http",
        "http.uri",
        r#"http.uri contains "/cgi-bin/""#,
        r#"http.method == "GET""#,
        r#"http.headers.host contains "victim""#,
        "ip.src == 203.0.113.9",
        "ip.src == 203.0.113.0/24",
        "tcp.port == 80",
        "tcp.port in {80, 443}",
        "ip.ttl >= 64",
        r#"http.uri matches "cmd=[a-z]+$""#,
        "eth.src[0:1] == 02",
        r#"http and not dns"#,
    ] {
        let filter = DisplayFilter::compile(expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert!(filter.matches(&d), "{expr} should match");
        // The reverse spelling has to agree.
        assert!(d.matches(&filter), "{expr} should match through Dissection::matches");
    }

    for expr in [
        "dns",
        "dns.qname",
        r#"http.uri contains "/wp-admin/""#,
        r#"http.method == "POST""#,
        "ip.src == 10.0.0.1",
        "tcp.port == 22",
        "udp",
    ] {
        let filter = DisplayFilter::compile(expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert!(!filter.matches(&d), "{expr} should not match");
    }
}

#[test]
fn a_blank_filter_matches_everything_and_says_so() {
    ensure_protocols();
    let f = http_get();
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();

    for expr in ["", "   "] {
        let filter = DisplayFilter::compile(expr).unwrap();
        assert!(filter.is_match_all(), "{expr:?} should be a match-all filter");
        assert!(filter.matches(&d));
    }
    assert!(!DisplayFilter::compile("http").unwrap().is_match_all());
}

#[test]
fn a_bad_filter_is_an_error_with_a_reason() {
    ensure_protocols();
    for expr in ["http.uri contains", "== 5", "(http", "tcp.port in {"] {
        let e = DisplayFilter::compile(expr)
            .err()
            .unwrap_or_else(|| panic!("{expr} should not compile"));
        assert!(!e.to_string().is_empty(), "{expr} gave an empty error");
    }
}

#[test]
fn a_filter_can_be_matched_from_several_threads() {
    ensure_protocols();
    // The point of `Send + Sync` on DisplayFilter: compile once on the main
    // thread, match on a pool.
    let filter = std::sync::Arc::new(
        DisplayFilter::compile(r#"http.uri contains "/cgi-bin/""#).unwrap(),
    );
    let mut handles = Vec::new();
    for _ in 0..4 {
        let filter = filter.clone();
        handles.push(std::thread::spawn(move || {
            let f = http_get();
            let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();
            for _ in 0..200 {
                assert!(filter.matches(&d));
            }
        }));
    }
    for h in handles {
        h.join().expect("a worker panicked");
    }
}

#[test]
fn a_written_capture_reads_back_packet_for_packet() {
    ensure_protocols();
    let dir = std::env::temp_dir().join(format!("libpcapng-writer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("roundtrip.pcapng");

    let a = http_get();
    let b = frame(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 80, 40000);

    let mut w = Writer::create_with(
        &path,
        LINKTYPE_ETHERNET,
        Some("written by the libpcapng test suite"),
        Some("libpcapng tests"),
    )
    .unwrap();
    w.packet(&a, 1_700_000_000_000_000).unwrap();
    w.packet_full(&b, b.len() as u32, 1_700_000_000_000_250, Some("the reply")).unwrap();
    assert_eq!(w.packets(), 2);
    w.finish().unwrap();

    let mut seen: Vec<(u64, usize, String)> = Vec::new();
    libpcapng::read_packets(&path, |pkt| {
        let info = Dissection::new(pkt.data, LINKTYPE_ETHERNET)
            .map(|d| d.info().to_string())
            .unwrap_or_default();
        seen.push((pkt.timestamp_us, pkt.data.len(), info));
        true
    })
    .unwrap();

    assert_eq!(seen.len(), 2, "{seen:#?}");
    // Microsecond timestamps survive, which the FILE*-based easyapi writer
    // cannot do: it takes whole seconds.
    assert_eq!(seen[0].0, 1_700_000_000_000_000);
    assert_eq!(seen[1].0, 1_700_000_000_000_250);
    assert_eq!(seen[0].1, a.len());
    assert_eq!(seen[1].1, b.len());
    assert!(seen[0].2.contains("/cgi-bin/"), "{:?}", seen[0].2);
    assert!(seen[1].2.contains("404") || seen[1].2.contains("Not Found"), "{:?}", seen[1].2);
}

#[test]
fn a_capture_can_be_built_in_memory() {
    ensure_protocols();
    // `Writer::new` takes any io::Write, so a capture need not touch a disk.
    let mut w = Writer::new(Vec::new(), LINKTYPE_ETHERNET, None, None).unwrap();
    let f = http_get();
    w.packet(&f, 1).unwrap();
    let bytes = w.finish().unwrap();

    // Section header, interface description, one packet: the file begins with
    // the SHB block type and the byte-order magic, little-endian.
    assert_eq!(&bytes[0..4], &0x0A0D_0D0Au32.to_le_bytes());
    assert_eq!(&bytes[8..12], &0x1A2B_3C4Du32.to_le_bytes());
    assert!(bytes.len() > f.len());

    // And it is readable, which is the part that matters.
    let dir = std::env::temp_dir().join(format!("libpcapng-mem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("in-memory.pcapng");
    std::fs::write(&path, &bytes).unwrap();

    let mut n = 0;
    libpcapng::read_packets(&path, |_| {
        n += 1;
        true
    })
    .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn an_empty_capture_is_still_a_valid_file() {
    let dir = std::env::temp_dir().join(format!("libpcapng-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("empty.pcapng");

    let w = Writer::create(&path, LINKTYPE_ETHERNET).unwrap();
    assert_eq!(w.packets(), 0);
    w.finish().unwrap();

    let mut n = 0;
    libpcapng::read_packets(&path, |_| {
        n += 1;
        true
    })
    .unwrap();
    assert_eq!(n, 0);
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
}

#[test]
fn a_truncated_packet_keeps_both_of_its_lengths() {
    ensure_protocols();
    let dir = std::env::temp_dir().join(format!("libpcapng-snap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("snaplen.pcapng");

    let full = http_get();
    let captured = &full[..40]; // as if taken with a 40-byte snaplen

    let mut w = Writer::create(&path, LINKTYPE_ETHERNET).unwrap();
    w.packet_full(captured, full.len() as u32, 7, None).unwrap();
    w.finish().unwrap();

    let mut seen = Vec::new();
    libpcapng::read_packets(&path, |pkt| {
        seen.push((pkt.data.len(), pkt.origlen));
        true
    })
    .unwrap();
    assert_eq!(seen, vec![(40, full.len() as u32)]);
}

// ── regressions in the POSA parser ──────────────────────────────────────────

/// `starts` used to be parsed from one line only, and to hold at most eight
/// prefixes. FTP declares 34 across four lines, so everything from the ninth
/// on — `STOR `, `RETR `, `LIST `, and the whole no-argument list past
/// `REIN` — decoded as nothing at all. A honeypot or an IDS filtering on
/// `ftp.command == "STOR"` therefore never matched an upload.
#[test]
fn a_wrapped_starts_list_is_read_to_the_end() {
    ensure_protocols();

    // One command from each line of ftp.posa's two `starts` lists, including
    // the last of each, so a regression to any fixed cap is caught.
    for (command, line) in [
        ("USER anonymous", "with an argument, 1st prefix"),
        ("STRU F", "with an argument, 8th — the old limit"),
        ("MODE S", "with an argument, 9th — the first ever dropped"),
        ("STOR evil.exe", "with an argument, 2nd line"),
        ("LIST .", "with an argument, 4th line"),
        ("HELP x", "with an argument, last of all"),
        ("PASV", "no argument, 1st prefix"),
        ("REIN", "no argument, 7th"),
        ("PWD", "no argument, 2nd line"),
        ("CCC", "no argument, last of all"),
    ] {
        let payload = format!("{command}\r\n");
        let f = frame(payload.as_bytes(), 40000, 21);
        let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();
        let verb = command.split(' ').next().unwrap();
        let got = d
            .root()
            .find("ftp.command")
            .map(|f| f.str_value().to_string());
        assert_eq!(got.as_deref(), Some(verb), "{command} ({line}) did not decode");
    }
}

/// The alias table held 64 entries while the bundled decoders declare 424, so
/// it filled during the first few protocols loaded — alphabetically, which is
/// why `amqp.*` aliases resolved and `ftp.*` never did. Every later `alias`
/// line was dropped in silence, and a display filter naming one matched
/// nothing, indistinguishable from the field not existing.
#[test]
fn aliases_declared_late_in_the_bundle_still_resolve() {
    ensure_protocols();

    let f = frame(b"USER anonymous\r\n", 40000, 21);
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();

    // The real field, and the alias ftp.posa declares for it. Both must match.
    for expr in [
        r#"ftp.command == "USER""#,
        r#"ftp.request.command == "USER""#,
        "ftp.request.arg",
    ] {
        let filter = DisplayFilter::compile(expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert!(filter.matches(&d), "{expr} should match through its alias");
    }

    // An alias from a protocol loaded early must keep working too.
    assert!(DisplayFilter::compile("amqp.type").is_ok());
}

/// `until "<delim>"` matches that exact byte sequence, so a field meant to end
/// at "a space or a CR" cannot be written `until " \r"` — that asks for a
/// space followed by a CR, which no line-oriented protocol produces. memcached
/// was written that way, and its `command` field decoded empty for every
/// command. `until any "<set>"` is the form that works.
#[test]
fn a_command_ending_at_any_of_several_bytes_decodes() {
    ensure_protocols();

    for (line, want) in [
        ("get flag\r\n", "get"),          // ends at a space
        ("set k 0 0 5\r\n", "set"),
        ("delete x\r\n", "delete"),
        ("stats\r\n", "stats"),           // ends at CR
        ("version\r\n", "version"),
        ("quit\r\n", "quit"),
    ] {
        let f = frame(line.as_bytes(), 40000, 11211);
        let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();
        let got = d
            .root()
            .find("memcached.command")
            .map(|f| f.str_value().to_string());
        assert_eq!(got.as_deref(), Some(want), "{line:?} did not decode its command");
    }

    // And a filter on it matches, which is the point.
    let f = frame(b"get flag\r\n", 40000, 11211);
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();
    assert!(DisplayFilter::compile(r#"memcached.command == "get""#).unwrap().matches(&d));
    assert!(!DisplayFilter::compile(r#"memcached.command == "set""#).unwrap().matches(&d));
}

/// steam.posa claimed `tcp.port == 27017`, which is MongoDB's default and is
/// also claimed by mongodb.posa. Whichever loaded last won, so traffic to a
/// MongoDB server decoded as Steam and exposed no `mongodb.*` field at all.
#[test]
fn mongodb_owns_its_own_port() {
    ensure_protocols();

    // An OP_QUERY for isMaster, which is what every MongoDB client and
    // scanner opens with.
    let doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00";
    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(b"admin.$cmd\x00");
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    body.extend_from_slice(doc);
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as i32).to_le_bytes());
    msg.extend_from_slice(&1i32.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2004i32.to_le_bytes());  // OP_QUERY
    msg.extend_from_slice(&body);

    let f = frame(&msg, 40000, 27017);
    let d = Dissection::new(&f, LINKTYPE_ETHERNET).unwrap();
    assert_eq!(d.proto().to_ascii_lowercase(), "mongodb", "27017 decoded as {}", d.proto());

    let root = d.root();
    assert_eq!(root.find("mongodb.op_code").map(|f| f.uint()), Some(2004));
    assert!(root.find("mongodb.message_length").is_some());

    // A filter naming the fields works, which it could not before.
    assert!(DisplayFilter::compile("mongodb.op_code == 2004").unwrap().matches(&d));
}
