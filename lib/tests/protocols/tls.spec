# TLS 1.2/1.3 handshake — RFC 8446, RFC 6066 for the SNI extension
#
# Record layer: content_type(1) version(2) length(2). Content type 0x16 is
# handshake. Inside, handshake_type(1) length(3) client_version(2) random(32),
# then session id, cipher suites, compression methods and extensions.
#
# The Server Name extension is the reason a modern ruleset can still say
# something about an encrypted connection: the hostname travels in cleartext.

name     TLS ClientHello carrying a server name

# Record 16 0303 004d; handshake 01 (ClientHello) length 000049; client version
# 0303 (TLS 1.2); 32 bytes of random; session id length 00; cipher suites
# 0002 with one suite 0000; compression 01 00; extensions 001e, of which the
# first is 0000 (server_name) length 001a — and inside it the host itself,
# which is legible in the hex below as "cdn.gholoader.example".
packet   tcp 10.0.0.1:51002 > 10.0.0.2:443  160303004d010000490303111111111111111111111111111111111111111111111111111111111111111100000200000100001e0000001a001800001563646e2e67686f6c6f616465722e6578616d706c65
proto    TLS
str      tls.server_name   cdn.gholoader.example
info~    Client Hello
label~   tls.content_type  Handshake
