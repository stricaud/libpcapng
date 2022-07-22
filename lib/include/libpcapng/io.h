/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_IO_H_
#define _LIBPCAPNG_IO_H_

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH 8 // sizeof(uint32_t) * 2

  typedef int (*foreach_pcapng_block_cb)(uint32_t block_counter, uint32_t block_type, uint32_t block_total_length, unsigned char *data, void *userdata);

int libpcapng_fp_read(FILE *fp, foreach_pcapng_block_cb pcapng_block_cb, void *userdata);
int libpcapng_file_read(char *filename, foreach_pcapng_block_cb pcapng_block_cb, void *userdata);
int libpcapng_file_read_debug(char *filename);

int libpcapng_padded_count(unsigned char *data, uint32_t data_len);
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_IO_H_
