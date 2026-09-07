Examples
========

All examples are in ``bindings/python/examples/``.

lan_corp with a callback
------------------------

Run the ``lan_corp.pcapsh`` AD-environment simulation and process each
of the 286 packets as they arrive:

.. literalinclude:: ../../bindings/python/examples/pcapsh_callback.py
   :language: python
   :lines: 1-

Run a script file, write pcapng
--------------------------------

.. literalinclude:: ../../bindings/python/examples/pcapsh_run_script.py
   :language: python
   :lines: 1-

Inline pcapsh code
------------------

.. literalinclude:: ../../bindings/python/examples/pcapsh_inline.py
   :language: python
   :lines: 1-

CAN-bus captures (SocketCAN)
----------------------------

Defines the SocketCAN wire format as a ``protocol`` block (posa), then
builds frames with named fields — ``SocketCAN(can_id=0x7FF, dlc=8, data=…)``
— no raw ``struct.pack``.  Demonstrates explicit timestamps via
:meth:`~pycapng.PcapNG.WritePacketTime`, per-packet comments via
:meth:`~pycapng.PcapNG.WritePacket`, and an SHB-level capture comment via
:meth:`~pycapng.PcapNG.OpenFileLinkTypeComment`.

See also `issue #7 <https://github.com/stricaud/libpcapng/issues/7>`_.

.. literalinclude:: ../../bindings/python/examples/write_can.py
   :language: python
   :lines: 1-

TLS HTTPS with a self-signed certificate
-----------------------------------------

Generates an RSA certificate in Python (via ``openssl`` subprocess) and
injects it into the TLS Certificate record:

.. literalinclude:: ../../bindings/python/examples/pcapsh_tls_https.py
   :language: python
   :lines: 1-
