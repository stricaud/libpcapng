/* bindgen entry point — pulls in the full libpcapng public API.
   <stddef.h> must come first: blocks.h uses size_t but doesn't include it. */
#include <stddef.h>
#include <stdio.h>
#include <libpcapng/libpcapng.h>

/* libpcapng.h is the convenience umbrella for the decoding and I/O core, and
   deliberately does not pull in everything — a C program that wants display
   filters includes <libpcapng/dfilter.h> itself, as bin/jackal.c does.
   bindgen has no such option: a header not reached from here produces no
   bindings at all, and the function is then missing from pcapng-sys however
   faithfully its .c file was compiled. So the rest of the public API is named
   explicitly below.

   dfilter.h is the one that mattered: without it there were no bindings for
   pcapng_dfilter_compile() or pcapng_dfilter_match(), which meant the display
   filter engine — the thing every tool built on this library matches rules
   with — was unreachable from Rust, and callers had to reimplement it. */
#include <libpcapng/dfilter.h>
#include <libpcapng/reader.h>
#include <libpcapng/surgery.h>
#include <libpcapng/community_id.h>
#include <libpcapng/flow_hash.h>
#include <libpcapng/tls_keylog.h>
#include <libpcapng/timestamp.h>
