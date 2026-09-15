# MQTT 3.1.1 — OASIS MQTT Version 3.1.1
#
# Fixed header: the high nibble of the first byte is the packet type, then a
# variable-length "remaining length". Type 1 is CONNECT, so the first byte is
# 0x10. The variable header carries the protocol name as a length-prefixed
# string, then the protocol level, connect flags and the keepalive.

name     MQTT CONNECT from a sensor

# 10 15: CONNECT, 21 bytes remaining. 0004 "MQTT" protocol name, level 04
# (3.1.1), flags 02 (clean session), keepalive 003c (60 s), then the client
# identifier 0009 "sensor-01".
packet   tcp 10.0.0.1:52000 > 10.0.0.2:1883  101500044d5154540402003c000973656e736f722d3031
proto    MQTT
field    mqtt.msg_type      1
label~   mqtt.msg_type      CONNECT
str      mqtt.proto_name    MQTT
field    mqtt.protocol_level 4
field    mqtt.keep_alive    60
str      mqtt.client_id     sensor-01
field    mqtt.clean_session 1
