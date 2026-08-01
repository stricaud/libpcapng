#include "callbacks.h"

/* Declared by Go via //export. We cannot include the Go-generated header here
   because it would create a circular dependency; forward-declare instead. */
extern void goBlockCallback(uintptr_t handle, uint32_t counter, uint32_t block_type,
                            uint32_t block_total_length, unsigned char *data);
extern void goPacketCallback(uintptr_t handle, const pcapng_packet_info_t *pkt);

int cBlockCallback(uint32_t counter, uint32_t block_type, uint32_t block_total_length,
                   unsigned char *data, void *userdata)
{
    goBlockCallback((uintptr_t)userdata, counter, block_type, block_total_length, data);
    return 0;
}

void cPacketCallback(const pcapng_packet_info_t *pkt, void *userdata)
{
    goPacketCallback((uintptr_t)userdata, pkt);
}
