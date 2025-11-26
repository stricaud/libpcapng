#include <stdio.h>
#include <stdint.h>

int libpcapng_mac_str_to_bytes(const char *mac_str, uint8_t mac[6]) {
    if (sscanf(mac_str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &mac[0], &mac[1], &mac[2],
               &mac[3], &mac[4], &mac[5]) != 6) {
        return 1;
    }
    return 0;
}

