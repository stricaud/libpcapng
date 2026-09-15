# DNP3 — IEEE 1815
#
# Data link header: start bytes 0x05 0x64, length, control, then destination
# and source addresses little-endian, then a CRC. The control byte packs
# DIR(1) PRM(1) FCB(1) FCV(1) and a 4-bit function code.

name     DNP3 data link frame, master to outstation

# 0564 start, 05 length, c9 control = 1100 1001: DIR set (from master), PRM
# set (primary), FCB clear, FCV clear, function 9 (request link status).
# Destination 10, source 1, both little-endian.
#
# Function 9 is used rather than 4 (unconfirmed user data) because it carries
# no user data: the frame is complete at the data link header, so the whole
# capture is well-formed rather than a truncated fragment of a larger one.
#
# feda is the real CRC-16/DNP over the eight header bytes (reflected poly
# 0xA6BC, init 0, final complement), little-endian. Wireshark validates it, so
# a made-up value would have it refuse to recognise the frame at all — which
# is the point of getting it right: the capture is then cross-checkable
# against a second implementation rather than only against this one.
packet   tcp 10.0.0.1:53000 > 10.0.0.2:20000  05 64 05 c9 0a00 0100 feda
proto    DNP3
field    dnp3.start_lo     0x05
field    dnp3.start_hi     0x64
field    dnp3.length       5
field    dnp3.control      0xc9
field    dnp3.dir          1
label~   dnp3.dir          Master
field    dnp3.prm          1
field    dnp3.dl_func      9
label~   dnp3.dl_func      RequestLinkStatus
field    dnp3.destination  10
field    dnp3.source       1
field    dnp3.header_crc   0xfeda
