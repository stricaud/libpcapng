Quick Start
===========

Installation
------------

Build the C extension first::

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target pcapsh_pymod

Then either install system-wide::

    cmake --install build --component Python

or add the source tree to ``PYTHONPATH`` for development::

    export PYTHONPATH=/path/to/libpcapng/bindings/python

Protocol definitions (.posa files) are discovered automatically.
To use a custom directory set the environment variable before importing::

    export PCAPSH_PROTOS_DIR=/path/to/bin/protos

Run a script, get packets
-------------------------

::

    from pycapng import pcapsh

    sh = pcapsh.PcapSH()
    packets = sh.run_string("""
    wrpcap("x", Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, flags="S"))
    wrpcap("x", Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=80, dport=1234, flags="SA"))
    """)

    print(f"{len(packets)} packets generated")
    for frame in packets:
        print(f"  {len(frame)} bytes")

``packets`` is a :class:`list` of :class:`bytes` objects, one per
``wrpcap()`` call in the script. Each item is a complete raw Ethernet
frame ready to write into any pcapng file.

You can also run a ``.pcapsh`` file from disk::

    packets = sh.run_script("/path/to/my_scenario.pcapsh")

Per-packet callback
-------------------

For large scripts or streaming use-cases, pass ``on_packet``::

    from pycapng import pcapsh

    sh = pcapsh.PcapSH()

    def handle(frame: bytes):
        print(f"  packet: {len(frame)} bytes")

    packets = sh.run_string("""
    wrpcap("x", Ether()/IP()/TCP(flags="S"))
    wrpcap("x", Ether()/IP()/TCP(flags="SA"))
    """, on_packet=handle)

The callback fires for **each** packet as it is produced, before
``run_script`` returns.  The return value still holds all frames, so
you can use both the callback and the list.

Inline pcapsh code
------------------

::

    from pycapng import pcapsh

    sh = pcapsh.PcapSH()
    packets = sh.run_string("""
    wrpcap("x", Ether()/IP(src="1.2.3.4", dst="5.6.7.8")/TCP(sport=12345, dport=80, flags="S"))
    wrpcap("x", Ether()/IP(src="5.6.7.8", dst="1.2.3.4")/TCP(sport=80, dport=12345, flags="SA"))
    """)
    assert len(packets) == 2

The string supports the full pcapsh syntax: backslash line continuation,
``for`` loops, ``protocol`` blocks, and all built-in helpers
(``TLS_CLIENT_HELLO``, ``SSH_KEXINIT``, ``fromhex``, …).

Writing a pcapng file
---------------------

Use the returned raw frames with any pcapng writer.  The minimal
built-in writer from the examples folder::

    import struct, time

    def write_pcapng(path: str, frames: list[bytes]) -> None:
        LINKTYPE_ETHERNET = 1

        def pad4(n): return (n + 3) & ~3

        with open(path, "wb") as f:
            shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
            bl  = 12 + len(shb)
            f.write(struct.pack("<II", 0x0A0D0D0A, bl) + shb + struct.pack("<I", bl))

            idb = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 65535)
            bl  = 12 + len(idb)
            f.write(struct.pack("<II", 0x00000001, bl) + idb + struct.pack("<I", bl))

            ts = int(time.time() * 1e6)
            for frame in frames:
                padded  = frame + b"\\x00" * (pad4(len(frame)) - len(frame))
                epb = struct.pack("<IIIII",
                    0, ts >> 32 & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                    len(frame), len(frame)) + padded
                bl = 12 + len(epb)
                f.write(struct.pack("<II", 0x00000006, bl) + epb + struct.pack("<I", bl))
                ts += 50_000

Or use the ``pycapng`` binding if installed::

    import pycapng

    ng = pycapng.PcapNG()
    ng.OpenFile("out.pcapng", "w")
    for frame in packets:
        ng.WritePacket(frame, "")
    ng.CloseFile()
