# ARP — RFC 826
#
# htype(2) ptype(2) hlen(1) plen(1) oper(2), then sender hardware and protocol
# addresses and target hardware and protocol addresses.

name     ARP request for 10.0.0.2

# htype 1 Ethernet, ptype 0x0800 IPv4, hlen 6, plen 4, oper 1 request.
# The target hardware address is zero because that is what is being asked for.
packet   eth 0x0806  0001 0800 0604 0001 020202020202 0a000001 000000000000 0a000002
proto    ARP
info~    10.0.0.2
