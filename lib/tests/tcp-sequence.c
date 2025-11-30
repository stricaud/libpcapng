#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <libpcapng/protocols/flow.h>


int write_tcp_packet(uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port,
                     uint8_t flags, const uint8_t *payload, 
                     uint16_t payload_len) {
    
    uint32_t side_a_ip, side_b_ip;
    uint16_t side_a_port, side_b_port;
    
    uint8_t from_side_a = libpcapng_normalize_flow_direction(src_ip, dst_ip, src_port, dst_port,
                                                    &side_a_ip, &side_b_ip,
                                                    &side_a_port, &side_b_port);
    
    libpcapng_tcp_flow_state_t *flow = libpcapng_get_flow_state(side_a_ip, side_b_ip, 
								side_a_port, side_b_port);
    
    uint32_t seq, ack;
    
    // Determine seq and ack based on direction and state
    if (from_side_a) {
        seq = flow->client_seq;
        ack = (flags & LIBPCAPNG_TCP_ACK) ? flow->server_seq : 0;
    } else {
        seq = flow->server_seq;
        ack = (flags & LIBPCAPNG_TCP_ACK) ? flow->client_seq : 0;
    }
    
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
    
    // Print packet info (replace with actual packet writing)
    printf("TCP Packet: %s:%u -> %s:%u\n",
           inet_ntoa((struct in_addr){.s_addr = htonl(src_ip)}),
           src_port,
           inet_ntoa((struct in_addr){.s_addr = htonl(dst_ip)}),
           dst_port);
    printf("  SEQ: %u, ACK: %u, Flags: %s%s%s, Len: %u\n",
           seq, ack,
           (flags & LIBPCAPNG_TCP_SYN) ? "SYN " : "",
           (flags & LIBPCAPNG_TCP_ACK) ? "ACK " : "",
           (flags & LIBPCAPNG_TCP_FIN) ? "FIN " : "",
           payload_len);
    
    // Update sequence numbers
    uint32_t seq_advance = payload_len;
    if (flags & LIBPCAPNG_TCP_SYN) seq_advance++;
    if (flags & LIBPCAPNG_TCP_FIN) seq_advance++;
    
    // Update the sender's sequence number
    if (from_side_a) {
        flow->client_seq += seq_advance;
    } else {
        flow->server_seq += seq_advance;
    }
    
    return 0;
}

// Example usage
int main() {
    uint32_t client_ip = 0xC0A80101; // 192.168.1.1
    uint32_t server_ip = 0xC0A80102; // 192.168.1.2
    uint16_t client_port = 54321;
    uint16_t server_port = 80;
    
    printf("=== TCP 3-way handshake ===\n");
    // Client sends SYN
    write_tcp_packet(client_ip, server_ip, client_port, server_port,
                    LIBPCAPNG_TCP_SYN, NULL, 0);
    
    // Server sends SYN-ACK
    write_tcp_packet(server_ip, client_ip, server_port, client_port,
                    LIBPCAPNG_TCP_SYN | LIBPCAPNG_TCP_ACK, NULL, 0);
    
    // Client sends ACK
    write_tcp_packet(client_ip, server_ip, client_port, server_port,
                    LIBPCAPNG_TCP_ACK, NULL, 0);
    
    printf("\n=== Data transfer ===\n");
    // Client sends data
    uint8_t data[] = "GET / HTTP/1.1\r\n";
    write_tcp_packet(client_ip, server_ip, client_port, server_port,
                    LIBPCAPNG_TCP_ACK | LIBPCAPNG_TCP_PSH, data, sizeof(data)-1);
    
    // Server sends response
    uint8_t response[] = "HTTP/1.1 200 OK\r\n";
    write_tcp_packet(server_ip, client_ip, server_port, client_port,
                    LIBPCAPNG_TCP_ACK | LIBPCAPNG_TCP_PSH, response, sizeof(response)-1);
    
    printf("\n=== Connection teardown ===\n");
    // Client sends FIN
    write_tcp_packet(client_ip, server_ip, client_port, server_port,
                    LIBPCAPNG_TCP_FIN | LIBPCAPNG_TCP_ACK, NULL, 0);
    
    // Server sends ACK
    write_tcp_packet(server_ip, client_ip, server_port, client_port,
                    LIBPCAPNG_TCP_ACK, NULL, 0);
    
    // Server sends FIN
    write_tcp_packet(server_ip, client_ip, server_port, client_port,
                    LIBPCAPNG_TCP_FIN | LIBPCAPNG_TCP_ACK, NULL, 0);
    
    // Client sends final ACK
    write_tcp_packet(client_ip, server_ip, client_port, server_port,
                    LIBPCAPNG_TCP_ACK, NULL, 0);
    
    return 0;
}
