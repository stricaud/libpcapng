#ifndef _LIBPCAPNG_PACKED_H_
#define _LIBPCAPNG_PACKED_H_

/*
 * Portable struct packing for the on-the-wire layouts.
 *
 * GCC/Clang spell this `__attribute__((packed))` on the closing brace. MSVC has
 * no such attribute — it uses `#pragma pack`. Since these structs are overlaid
 * directly on captured bytes, getting this wrong does not fail loudly: the
 * compiler inserts padding and every field past the first misaligned member
 * reads the wrong offset. (libpcapng_x224_cc_hdr is 7 bytes; unpacked it would
 * be 8.)
 *
 * So each header carrying wire structs brackets them with
 * PCAPNG_PACK_PUSH / PCAPNG_PACK_POP and marks each one PCAPNG_PACKED, and
 * lib/wire_layout.c asserts every resulting sizeof at compile time — a build
 * where the packing did not take effect fails instead of silently misparsing.
 */

#if defined(_MSC_VER)
#  define PCAPNG_PACK_PUSH  __pragma(pack(push, 1))
#  define PCAPNG_PACK_POP   __pragma(pack(pop))
#  define PCAPNG_PACKED     /* the pragma above does the work */
#else
#  define PCAPNG_PACK_PUSH
#  define PCAPNG_PACK_POP
#  define PCAPNG_PACKED     __attribute__((packed))
#endif

#endif /* _LIBPCAPNG_PACKED_H_ */
