#pragma once
#include <stdint.h>
#include <libpcapng/io.h>
#include <libpcapng/capture.h>

/* C trampolines that call into Go. The Go //export functions are defined in
   cbexport.go and registered via the same uintptr handle passed as userdata. */

int  cBlockCallback(uint32_t counter, uint32_t block_type, uint32_t block_total_length,
                    unsigned char *data, void *userdata);

void cPacketCallback(const pcapng_packet_info_t *pkt, void *userdata);

/* Carry a callback handle into C as the opaque `void *userdata` cookie.
   The handle is a counter from cbpool.go, not an address, so converting it on
   the Go side would mean handing the garbage collector an unsafe.Pointer that
   does not point at anything — which is what `go vet` reports as a possible
   misuse of unsafe.Pointer. Doing the cast here keeps that integer out of Go's
   pointer world; the trampolines above cast it straight back with
   (uintptr_t)userdata. */
void *cHandleToPtr(uintptr_t h);
