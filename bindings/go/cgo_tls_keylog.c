/* CGo compilation unit for tls_keylog.c — compiled separately to avoid symbol conflicts.
 *
 * dissect.c calls into this for the TLS keys a capture can carry in its DSB
 * blocks, so it must be compiled even though the decryption itself is behind
 * HAVE_OPENSSL, which this build does not define. Without it the link comes up
 * short of pcapng_tls_keylog_loaded and friends. */
#include "vendor/src/tls_keylog.c"
