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

TLS HTTPS with a self-signed certificate
-----------------------------------------

Generates an RSA certificate in Python (via ``openssl`` subprocess) and
injects it into the TLS Certificate record:

.. literalinclude:: ../../bindings/python/examples/pcapsh_tls_https.py
   :language: python
   :lines: 1-
