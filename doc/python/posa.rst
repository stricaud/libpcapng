Protocol Definitions (posa)
===========================

pcapsh uses a small domain-specific language called **posa** to define
custom application-layer protocols.  Once a protocol is defined, it
becomes a first-class constructor in pcapsh scripts, just like the
built-in ``TCP()``, ``UDP()``, etc.

50+ protocols ship in ``bin/protos/`` (AMQP, CoAP, Modbus, gRPC, MQTT,
OSPF, QUIC, RADIUS, …).  You can add your own by writing a ``.posa``
file and loading it at runtime.

Syntax
------

A ``.posa`` file is a plain-text file.  Lines starting with ``#`` are
comments.  One or more protocol blocks may appear in a single file.

Protocol block
~~~~~~~~~~~~~~

::

    Object<parent> ProtocolName
        required <type>  field_name = default_value
            ENUM_A = 1
            ENUM_B = 2
        optional <type>  field_name2 = default_value
        ...

``Object<parent>``
    The parent protocol that carries this protocol as its payload.
    Common values: ``main`` (standalone), ``tcp``, ``udp``, ``ip``.
    Use ``main`` (or omit ``<parent>``) for protocols you chain
    manually with ``/``.

``required`` / ``optional``
    ``required`` fields are always serialised.  ``optional`` fields
    are omitted when set to their default value (not yet fully
    implemented for all types; use ``required`` when unsure).

Field types
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 15 45

   * - Type
     - Size
     - Notes
   * - ``uint8``
     - 1 byte
     - Big-endian (network byte order)
   * - ``uint16``
     - 2 bytes
     - Big-endian
   * - ``uint32``
     - 4 bytes
     - Big-endian
   * - ``uint64``
     - 8 bytes
     - Big-endian
   * - ``le_uint16``
     - 2 bytes
     - Little-endian (e.g. SMB, Windows protocols)
   * - ``le_uint32``
     - 4 bytes
     - Little-endian
   * - ``le_uint64``
     - 8 bytes
     - Little-endian
   * - ``mac``
     - 6 bytes
     - Accepts ``"aa:bb:cc:dd:ee:ff"`` string
   * - ``ip4`` / ``ip``
     - 4 bytes
     - IPv4 address field. Serialises as 4 bytes, network byte order — identical
       to ``uint32`` on the wire. The difference is that ``ip4`` accepts
       dotted-decimal notation everywhere: as a ``.posa`` default
       (``= 0.0.0.0``) and in script constructors
       (``OSPF(router_id="10.0.0.1")``). Using ``uint32`` instead would
       require hex or integer literals (``OSPF(router_id=0x0a000001)``).
       Use ``ip4`` for any field that holds an IPv4 address; use ``uint32``
       for plain 32-bit integers. IPv6 addresses (16 bytes) have no dedicated
       type — use ``bytes<16>`` and fill with ``fromhex()``.
   * - ``bytes<N>``
     - N bytes
     - Fixed-length raw bytes, default ``0x00...``
   * - ``bytes[len_field]``
     - variable
     - Length taken from another field at serialisation time
   * - ``payload`` / ``bytes_eod``
     - variable
     - Absorbs all remaining bytes (for dissection)
   * - ``string``
     - variable
     - Null-terminated C string

Enumeration values
~~~~~~~~~~~~~~~~~~

Indent enum constants one extra level under the field::

    required uint8  msg_type = 1
        CONNECT    = 1
        CONNACK    = 2
        PUBLISH    = 3
        PUBACK     = 4
        SUBSCRIBE  = 8
        SUBACK     = 9
        DISCONNECT = 14

In a pcapsh script you can then write::

    MQTT(msg_type=PUBLISH)

or use the numeric value directly.

Example — a minimal MQTT fixed header
--------------------------------------

Create ``~/my_protos/mqtt_fixed.posa``::

    # Minimal MQTT 3.1.1 fixed header (2 bytes)
    # Full packets require variable-length encoding for remaining_length;
    # use fromhex() or bytes<N> for the full payload.
    Object<main> MQTT
        required uint8  msg_type = 1
            CONNECT    = 1
            CONNACK    = 2
            PUBLISH    = 3
            PUBACK     = 4
            SUBSCRIBE  = 8
            SUBACK     = 9
            DISCONNECT = 14
        required uint8  remaining_length = 0

Use it in a Python script::

    import os
    os.environ["PCAPSH_PROTOS_DIR"] = os.path.expanduser("~/my_protos")

    from pycapng import pcapsh

    sh = pcapsh.PcapSH()
    # or load at any time:
    # sh.load_posa(os.path.expanduser("~/my_protos/mqtt_fixed.posa"))

    packets = sh.run_string("""
    wrpcap("x", Ether()/IP(src="10.0.1.5", dst="10.0.0.10")/
               TCP(sport=54321, dport=1883, flags="PA")/
               MQTT(msg_type=CONNECT, remaining_length=12))
    """)
    assert len(packets) == 1

Or use it in a ``.pcapsh`` script::

    wrpcap("mqtt_demo.pcapng", \
      Ether()/IP(src="10.0.1.5", dst="10.0.0.10")/ \
      TCP(sport=54321, dport=1883, flags="PA")/ \
      MQTT(msg_type=CONNECT, remaining_length=12))

Inline protocol definition in a pcapsh script
---------------------------------------------

You can define protocols directly inside a ``.pcapsh`` file or
``run_string()`` code using the ``protocol … end`` block::

    protocol MyHeader
        required uint16 version = 1
        required uint16 msg_id  = 0
        required uint32 length  = 0
    end

    wrpcap("out.pcapng", Ether()/IP()/UDP()/MyHeader(version=2, msg_id=42))

Defining the protocol inline does not persist across ``run_script()`` /
``run_string()`` calls because each call resets per-run state.  For
persistent definitions use a ``.posa`` file loaded via
:meth:`~pycapng.pcapsh.PcapSH.load_posa` or
``$PCAPSH_PROTOS_DIR``.

Little-endian example — Windows SMB2 dialect
--------------------------------------------

SMB2 and most Windows-native protocols use little-endian byte order::

    # smb2_dialect.posa
    Object<main> SMB2Dialect
        required le_uint16 dialect_count = 1
        required le_uint16 dialect       = 0x0311
            SMB202 = 0x0202
            SMB210 = 0x0210
            SMB300 = 0x0300
            SMB302 = 0x0302
            SMB311 = 0x0311

    # In a script:
    wrpcap("smb2.pcapng", Ether()/IP()/TCP(dport=445)/
           SMB2Dialect(dialect=SMB311))

Loading from Python
-------------------

::

    from pycapng import pcapsh

    sh = pcapsh.PcapSH()

    # Single file
    n = sh.load_posa("/path/to/my_proto.posa")
    print(f"Loaded {n} protocol(s)")

    # Entire directory
    n = sh.load_protos("/path/to/protos_dir/")
    print(f"Loaded {n} protocol(s) from directory")

Available built-in protocols
-----------------------------

Run ``pcapsh`` and type ``ls()`` for a summary, or ``ls(PROTO)`` for
field details.  Shipped ``.posa`` files include:

AH, AMQP, BACnet, BFD, BGP, CDP, CoAP, DCCP, DHCPv6, DNP3, EIGRP,
ESP, FTP, GRE, gRPC (HTTP/2 framing), HSS, IGMP, IS-IS, L2TP, LACP,
LLDP, MPLS, MQTT, Modbus, MLD, NetBIOS, NFS, OSPF, PIM, PPP, QUIC,
RADIUS, RIP, RSTP, SCTP, SIP, SNMP, STP, TACACS+, VRRP, VXLAN,
WireGuard, and more.
