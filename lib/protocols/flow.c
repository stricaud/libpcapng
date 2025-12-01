#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/protocols/flow.h>

uint8_t flow_valid[FLOW_TABLE_SIZE] = {0};

uint32_t libpcapng_hash_flow(uint32_t client_ip, uint32_t server_ip, 
                   uint16_t client_port, uint16_t server_port) {
    uint32_t hash = 2166136261u; // FNV offset basis
    
    hash ^= client_ip;
    hash *= 16777619u; // FNV prime
    hash ^= server_ip;
    hash *= 16777619u;
    hash ^= ((uint32_t)client_port << 16) | server_port;
    hash *= 16777619u;
    
    return hash % FLOW_TABLE_SIZE;
}

// Normalize flow direction and determine which side we're sending from
// Returns 1 if from side A, 0 if from side B
uint8_t libpcapng_normalize_flow_direction(uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint32_t *side_a_ip, uint32_t *side_b_ip,
                                  uint16_t *side_a_port, uint16_t *side_b_port) {
    uint8_t from_side_a;
    
    // Use a simple comparison to consistently determine flow direction
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        *side_a_ip = src_ip;
        *side_a_port = src_port;
        *side_b_ip = dst_ip;
        *side_b_port = dst_port;
        from_side_a = 1;
    } else {
        *side_a_ip = dst_ip;
        *side_a_port = dst_port;
        *side_b_ip = src_ip;
        *side_b_port = src_port;
        from_side_a = 0;
    }
    
    return from_side_a;
}

void libpcapng_update_tcp_state(libpcapng_tcp_flow_state_t *flow, uint8_t flags, uint8_t from_side_a)
{
    // Handle SYN flag (consumes 1 sequence number)
    if (flags & LIBPCAPNG_TCP_SYN) {
        if (from_side_a && flow->state == 0) {
            flow->state = 1; // SYN sent
        } else if (!from_side_a && flow->state == 1) {
            flow->state = 2; // SYN-ACK received, established
        }
    }
    
    // Handle FIN flag (consumes 1 sequence number)
    if (flags & LIBPCAPNG_TCP_FIN) {
        if (flow->state == 2) {
            flow->state = 3; // FIN_WAIT or CLOSE_WAIT
        } else if (flow->state == 3) {
            flow->state = 5; // Both sides sent FIN (CLOSING/TIME_WAIT)
        }
    }
}

void libpcapng_set_flow_state(uint32_t src_ip, uint32_t dst_ip,
			      uint16_t src_port, uint16_t dst_port,
			      uint32_t seq, uint32_t ack, uint8_t flags,
			      uint16_t data_len) {
    uint32_t side_a_ip, side_b_ip;
    uint16_t side_a_port, side_b_port;
    
    uint8_t from_side_a = libpcapng_normalize_flow_direction(src_ip, dst_ip, src_port, dst_port,
                                                    &side_a_ip, &side_b_ip,
                                                    &side_a_port, &side_b_port);
    
    libpcapng_tcp_flow_state_t *flow = libpcapng_get_flow_state(side_a_ip, side_b_ip, 
						      side_a_port, side_b_port);
    
    // Calculate sequence advance for this packet
    uint32_t seq_advance = data_len;
    if (flags & LIBPCAPNG_TCP_SYN) seq_advance++;
    if (flags & LIBPCAPNG_TCP_FIN) seq_advance++;
    
    // Update the sender's sequence number to reflect the NEXT expected seq
    if (from_side_a) {
        flow->client_seq = seq + seq_advance;
    } else {
        flow->server_seq = seq + seq_advance;
    }
    
    // If ACK flag is set, update what we've received from the other side
    if (flags & LIBPCAPNG_TCP_ACK) {
        if (from_side_a) {
            flow->server_seq = ack;  // We're ACKing server's data
        } else {
            flow->client_seq = ack;  // We're ACKing client's data
        }
    }
    
    // Update connection state based on flags
    if (flags & LIBPCAPNG_TCP_SYN) {
        if (from_side_a && flow->state == 0) {
            flow->state = 1; // SYN sent
        } else if (!from_side_a && flow->state == 1) {
            flow->state = 2; // SYN-ACK received, established
        }
    }
    
    if (flags & LIBPCAPNG_TCP_FIN) {
        if (flow->state == 2) {
            flow->state = 3; // FIN_WAIT or CLOSE_WAIT
        } else if (flow->state == 3) {
            flow->state = 5; // Both sides sent FIN (CLOSING/TIME_WAIT)
        }
    }
}

// Get or create flow state
libpcapng_tcp_flow_state_t* libpcapng_get_flow_state(uint32_t client_ip, uint32_t server_ip,
					   uint16_t client_port, uint16_t server_port) {
    uint32_t idx = libpcapng_hash_flow(client_ip, server_ip, client_port, server_port);
    uint32_t start_idx = idx;
    uint32_t first_valid_idx = idx;
    libpcapng_tcp_flow_state_t *flow = NULL;
    
    // Linear probing for collision resolution
    while (flow_valid[idx]) {
        flow = &flow_table[idx];
        if (flow->client_ip == client_ip && 
            flow->server_ip == server_ip &&
            flow->client_port == client_port && 
            flow->server_port == server_port) {
            return flow;
        }
        idx = (idx + 1) % FLOW_TABLE_SIZE;
        if (idx == start_idx) {
            // Table full - overwrite the slot we started at
            idx = first_valid_idx;
            break;
        }
    }
    
    // Create new flow (or overwrite if table was full)
    flow = &flow_table[idx];
    flow->client_ip = client_ip;
    flow->server_ip = server_ip;
    flow->client_port = client_port;
    flow->server_port = server_port;
    flow->client_seq = rand(); // Initial sequence number
    flow->server_seq = rand();
    flow->state = 0;
    flow_valid[idx] = 1;
    
    return flow;
}

