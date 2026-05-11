API Reference
=============

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
