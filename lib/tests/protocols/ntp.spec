# NTP — RFC 5905
#
# The first byte packs LI(2) VN(3) Mode(3). 0x23 = 00 100 011: leap indicator
# 0 (no warning), version 4, mode 3 (client). Then stratum, poll, precision,
# and the four timestamps. A client request is 48 bytes.

name     NTP version 4 client request

# 0x23 flags, stratum 0 (unspecified, normal in a client request), poll 6
# (64 s), precision 0xec = -20 (about a microsecond). Everything after is
# zero, which is what a client sends when it has no clock state yet.
packet   udp 10.0.0.1:41000 > 10.0.0.2:123  23 00 06 ec 00000000 00000000 00000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
proto    NTP
# 0x23 unpacked: bits 7-6 leap indicator, 5-3 version, 2-0 mode.
field    ntp.li_vn_mode  0x23
field    ntp.li          0
field    ntp.vn          4
field    ntp.mode        3
label~   ntp.mode        Client
field    ntp.stratum     0
field    ntp.poll        6
field    ntp.root_delay  0
field    ntp.root_dispersion 0
# NOTE: precision is a signed exponent in RFC 5905 — 0xec is -20, about a
# microsecond. The decoder declares it uint8, so it reads back as 236. This
# expectation records what the decoder does, not what the field means; fixing
# the decoder should change this line to -20.
field    ntp.precision   236
