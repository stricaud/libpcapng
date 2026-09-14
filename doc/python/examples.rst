Examples
========

All examples are in ``bindings/python/examples/``.

Start here: the guided tour
---------------------------

``posa_tour.py`` walks the whole workflow in five stages — capture frames,
ask posa which decoder claims each one, dissect the ones it recognises,
write a decoder for the ones it does not, then build packets from that same
decoder and save them as pcapng.

It runs with no privileges and no capture file: given neither ``--iface``
nor ``--read`` it generates its own mixed traffic, some of which posa
already understands (Modbus/TCP) and some of which nothing does — which is
what motivates writing a decoder in stage 4.

.. code-block:: console

   $ python3 posa_tour.py                                  # the whole tour
   $ sudo python3 posa_tour.py --iface en0 --count 50      # capture for real
   $ python3 posa_tour.py --read mycapture.pcapng          # replay a file
   $ python3 posa_tour.py --stage discover --read x.pcapng # one stage alone

.. literalinclude:: ../../bindings/python/examples/posa_tour.py
   :language: python
   :lines: 1-

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
