#ifndef _LIBPCAPNG_HTTP2_H_
#define _LIBPCAPNG_HTTP2_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define H2_FRAME_DATA    0x0
#define H2_FRAME_HEADERS 0x1
#define H2_FRAME_SETTINGS 0x4

size_t h2_build_preface(uint8_t *out, size_t max_len);
size_t h2_build_settings(uint8_t *out, size_t max_len);
size_t h2_build_headers(uint8_t *out, size_t max_len, uint32_t stream_id);
size_t h2_build_data(uint8_t *out, size_t max_len,
                     uint32_t stream_id,
                     const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_HTTP2_H_
  
