API Reference
=============

pcapng Writer (``pycapng.PcapNG``)
-----------------------------------

.. module:: pycapng

``PcapNG`` writes pcapng files directly from Python, without running a
pcapsh script.  Use it when you already have raw frame bytes and want
fine-grained control over link types, timestamps, and block-level comments.

Key methods:

``OpenFileLinkTypeComment(path, mode, linktype, comment)``
    Open *path* for writing (``mode="w"``).  Writes a Section Header Block
    carrying *comment* as ``opt_comment`` (visible in Wireshark's
    *Edit → Capture File Properties*), followed by an Interface Description
    Block for *linktype*.  Pass ``""`` for no comment.

``OpenFileLinkType(path, mode, linktype)``
    Same as above without an SHB comment.

``WritePacket(data, comment)``
    Append an Enhanced Packet Block.  *comment* is stored as the EPB
    ``opt_comment`` (visible in Wireshark's packet detail pane).  Pass
    ``""`` for no comment.

``WritePacketTime(data, timestamp)``
    Append an EPB with an explicit Unix timestamp (seconds, ``uint32``).
    Use this when replaying recorded captures with original timing.

``CloseFile()``
    Flush and close the output file.

Linktype constants (e.g. ``pycapng.LINKTYPE_ETHERNET``,
``pycapng.LINKTYPE_CAN_SOCKETCAN``) match the IANA registry values used
by Wireshark and tcpdump.

.. module:: libpcapng.pcapsh

Script Engine
-------------

.. autoclass:: PcapSH
   :members:
   :undoc-members:

TLS Record Builders
-------------------

These functions mirror the ``TLS_*`` built-ins available inside pcapsh
scripts.  They return raw TLS record bytes (:class:`bytes`) suitable for
embedding directly in a ``wrpcap`` packet chain via Python string
interpolation into ``fromhex()``, or for use alongside
:meth:`PcapSH.run_string`.

.. autofunction:: tls_client_hello
.. autofunction:: tls_server_hello
.. autofunction:: tls_certificate
.. autofunction:: tls_certificate_cn
.. autofunction:: tls_change_cipher_spec
.. autofunction:: tls_finished
.. autofunction:: tls_application_data

Environment Variables
---------------------

``PCAPSH_PROTOS_DIR``
    Directory containing ``.posa`` protocol definition files.  Checked
    first, before the compiled-in install and source-tree paths.  Set
    this before creating :class:`PcapSH` (or before importing the module
    via ``os.environ``).

Protocol Search Order
~~~~~~~~~~~~~~~~~~~~~

When :class:`PcapSH` is instantiated, protocol definitions are loaded
from the first directory that contains at least one ``.posa`` file:

1. ``$PCAPSH_PROTOS_DIR`` (environment variable)
2. ``{prefix}/share/pcapsh/protos/`` (installed location)
3. ``{source}/bin/protos/`` (in-tree build)

Additionally, ``~/.pcapsh_protos.posa`` is always loaded afterwards,
allowing per-user overrides.

Additional directories can be added at any time via
:meth:`PcapSH.load_protos` and :meth:`PcapSH.load_posa`.
