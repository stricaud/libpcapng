# DNS — RFC 1035
#
# Header is id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2), then
# the question section, then the answer records. A name is a sequence of
# length-prefixed labels ending in a zero byte, so "www.example.com" is
# 03 'www' 07 'example' 03 'com' 00.

name     DNS A query and its answer

# id 0x1234, flags 0x0100 = recursion desired, one question, no answers.
# qtype 1 = A, qclass 1 = IN.
packet   udp 10.0.0.1:40000 > 1.1.1.1:53  1234 0100 0001 0000 0000 0000 03777777 076578616d706c65 03636f6d 00 0001 0001
proto    DNS
info~    www.example.com
field    dns.id          0x1234
field    dns.qr          0
field    dns.rd          1
field    dns.questions   1
field    dns.answers     0
str      dns.qname       www.example.com
label~   dns.qtype       A
label~   dns.qclass      IN

# flags 0x8180 = response, recursion desired and available, rcode 0.
# The answer's name is the compression pointer c00c — offset 12, the question's
# name. ttl 0x0000003c = 60, rdlength 4, rdata 5db8d822 = 93.184.216.34.
packet   udp 1.1.1.1:53 > 10.0.0.1:40000  1234 8180 0001 0001 0000 0000 03777777 076578616d706c65 03636f6d 00 0001 0001 c00c 0001 0001 0000003c 0004 5db8d822
proto    DNS
field    dns.id          0x1234
field    dns.qr          1
field    dns.ra          1
field    dns.rcode       0
field    dns.answers     1
str      dns.qname       www.example.com
info~    93.184.216.34
