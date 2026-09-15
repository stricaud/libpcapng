# Modbus/TCP — Modbus Application Protocol v1.1b3, Modbus over TCP/IP v1.0b
#
# Expected values are read off the bytes and the specification, not off the
# decoder. The MBAP header is transaction_id(2) protocol_id(2) length(2)
# unit_id(1), then the PDU.

name     Modbus/TCP read holding registers, request and response

# 0001 transaction, 0000 protocol (always 0 for Modbus), 0006 length,
# 01 unit, 03 function, 0000 starting address, 0001 quantity.
# length counts unit_id + the 5-byte PDU = 6.
packet   tcp 10.0.0.1:45000 > 10.0.0.2:502  0001 0000 0006 01 03 0000 0001
proto    Modbus/TCP
info~    READ_HOLDING_REGISTERS
field    ModbusTCP.transaction_id   1
field    ModbusTCP.protocol_id      0
field    ModbusTCP.length           6
field    ModbusTCP.unit_id          1
field    ModbusTCP.function_code    3
label~   ModbusTCP.function_code    READ_HOLDING_REGISTERS
field    ModbusTCP.start_address    0
field    ModbusTCP.quantity         1
# A request carries no byte count; that field belongs to the response.
absent   ModbusTCP.byte_count

# The reply: length 5 covers unit_id, function, byte_count and two data bytes.
# byte_count 02 is one 16-bit register holding 0x1234 = 4660.
packet   tcp 10.0.0.2:502 > 10.0.0.1:45000  0001 0000 0005 01 03 02 1234
proto    Modbus/TCP
field    ModbusTCP.length           5
field    ModbusTCP.function_code    3
field    ModbusTCP.byte_count       2
field    ModbusTCP.value            4660
absent   ModbusTCP.quantity

# An exception reply sets the high bit of the function code: 3 | 0x80 = 0x83.
# Exception code 02 is ILLEGAL DATA ADDRESS.
packet   tcp 10.0.0.2:502 > 10.0.0.1:45000  0001 0000 0003 01 83 02
proto    Modbus/TCP
field    ModbusTCP.function_code    0x83
field    ModbusTCP.exception_code   2
label~   ModbusTCP.exception_code   ILLEGAL_DATA_ADDRESS
