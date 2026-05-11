/* pcapsh.c — global state definitions for the pcapsh interactive packet shell
 *
 * Scapy-like REPL: build, inspect, and write packets interactively.
 *
 * Examples:
 *   IP()
 *   Ether()/IP()/TCP()
 *   IP()/TCP()/"GET / HTTP/1.0\r\n\r\n"
 *   a = Ether(src="aa:bb:cc:dd:ee:ff")/IP(dst="8.8.8.8")/UDP()
 *   hexdump(a)
 *   raw(a)
 *   wrpcap("out.pcapng", a)
 *   ls(IP)
 *
 * Sub-modules (compiled separately via CMakeLists.txt):
 *   pcapsh_layer.c  — layer/field operations, session management, protocol registry
 *   pcapsh_posa.c   — dynamic protocol definitions (posa format)
 *   pcapsh_io.c     — serialization, dissection, hexdump, ls()
 *   pcapsh_eval.c   — variable storage, lexer, evaluator, TCP session builders
 *   pcapsh_main.c   — completion, for-loop, REPL, script runner, entry point
 */

#include "pcapsh.h"

sess_t      sessions[MAX_SESSIONS];
int         nsessions = 0;

proto_reg_t proto_reg[MAX_PROTO_REG];
int         nproto_reg = 0;

var_t       vars[MAX_VARS];
int         nvars = 0;

pdef_t      pdefs[MAX_PDEFS];
int         npdefs = 0;

char            wrpcap_override[MAXPATH] = "";
pcapsh_packet_cb g_packet_cb       = NULL;
void            *g_packet_cb_userdata = NULL;

void pcapsh_reset(void) {
    nsessions = 0;
    memset(sessions, 0, sizeof(sessions));
    nvars = 0;
    memset(vars, 0, sizeof(vars));
    wrpcap_override[0] = '\0';
    g_packet_cb = NULL;
    g_packet_cb_userdata = NULL;
    pcapsh_eval_reset();
}
