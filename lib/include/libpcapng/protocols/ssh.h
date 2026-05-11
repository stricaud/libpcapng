#ifndef _LIBPCAPNG_SSH_H_
#define _LIBPCAPNG_SSH_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SSH message numbers (RFC 4253) */
#define SSH_MSG_KEXINIT  20
#define SSH_MSG_NEWKEYS  21

/* Build SSH_MSG_KEXINIT binary packet.
 * is_server=0 → client-side algorithm list; is_server=1 → server-side.
 * Returns total bytes written into out. */
size_t ssh_build_kexinit(uint8_t *out, size_t max_len, int is_server);

/* Build SSH_MSG_NEWKEYS binary packet (single byte payload). */
size_t ssh_build_newkeys(uint8_t *out, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_SSH_H_ */
