# DHCP over BOOTP — RFC 2131
#
# op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2), four addresses,
# chaddr(16), sname(64), file(128), then the magic cookie 63825363 and the
# options. Option 53 is the message type; 1 is DISCOVER. Option 255 ends them.

name     DHCP Discover

# op 1 (BOOTREQUEST), htype 1 (Ethernet), hlen 6, hops 0, xid 0xdeadbeef,
# flags 0x8000 (broadcast). Options: 35 01 01 message type discover,
# 37 03 01 03 06 parameter request list, ff end.
packet   udp 0.0.0.0:68 > 255.255.255.255:67  01010600deadbeef000080000000000000000000000000000000000002000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013703010306ff
proto    DHCP
info~    Discover
field    dhcp.op         1
field    dhcp.htype      1
field    dhcp.hlen       6
field    dhcp.xid        0xdeadbeef
field    dhcp.cookie     0x63825363
# The options are a repeated block, so the first node with each abbrev is the
# first option: 35 01 01, code 53 (DHCP Message Type) length 1 value 1.
field    dhcp.opt_code   53
label~   dhcp.opt_code   DHCP Message Type
field    dhcp.opt_len    1
field    dhcp.msg_type   1
label~   dhcp.msg_type   Discover
