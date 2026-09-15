# ICMP — RFC 792
#
# type(1) code(1) checksum(2), then four type-specific bytes. For echo those
# are identifier(2) and sequence(2), followed by the data the responder echoes.

name     ICMP echo request

# type 8 code 0 is an echo request. The checksum 0xf7fd is the one's-complement
# of 0x0800 + 0x0001 + 0x0001, which is what these bytes actually sum to.
packet   ip4 10.0.0.1 > 10.0.0.2 proto 1  0800 f7fd 0001 0001 6162636465666768
proto    ICMP
field    icmp.type       8
field    icmp.code       0
