#ifndef _LIBPCAPNG_FLOW_H_
#define _LIBPCAPNG_FLOW_H_

#include <stdint.h>

#define LIBPCAPNG_TCP_FIN 0x01
#define LIBPCAPNG_TCP_SYN 0x02
#define LIBPCAPNG_TCP_RST 0x04
#define LIBPCAPNG_TCP_PSH 0x08
#define LIBPCAPNG_TCP_ACK 0x10
#define LIBPCAPNG_TCP_URG 0x20

typedef struct {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_seq;
    uint32_t server_seq;
    uint8_t state; // 0=closed, 1=syn_sent, 2=established, 3=fin_wait, 4=close_wait, 5=closing
} libpcapng_tcp_flow_state_t;

/* This hash table only takes 1024 entries in memory and erase the old ones. */
#define FLOW_TABLE_SIZE 1024
libpcapng_tcp_flow_state_t flow_table[FLOW_TABLE_SIZE];
uint8_t flow_valid[FLOW_TABLE_SIZE] = {0};

uint32_t libpcapng_hash_flow(uint32_t client_ip, uint32_t server_ip, 
			     uint16_t client_port, uint16_t server_port);
libpcapng_tcp_flow_state_t* libpcapng_get_flow_state(uint32_t client_ip, uint32_t server_ip,
					   uint16_t client_port, uint16_t server_port);
uint8_t libpcapng_normalize_flow_direction(uint32_t src_ip, uint32_t dst_ip,
					   uint16_t src_port, uint16_t dst_port,
					   uint32_t *side_a_ip, uint32_t *side_b_ip,
					   uint16_t *side_a_port, uint16_t *side_b_port);
void libpcapng_update_tcp_state(libpcapng_tcp_flow_state_t *flow, uint8_t flags, uint8_t from_side_a);
void libpcapng_set_flow_state(uint32_t src_ip, uint32_t dst_ip,
			      uint16_t src_port, uint16_t dst_port,
			      uint32_t seq, uint32_t ack, uint8_t flags,
			      uint16_t data_len);
#endif
