# Syslog — RFC 3164 (BSD syslog)
#
# "<PRI>TIMESTAMP HOSTNAME MSG". PRI is decimal ASCII between angle brackets
# and encodes both facility and severity: facility = PRI >> 3, severity is the
# low three bits. 34 = facility 4 (auth), severity 2 (critical).

name     Syslog RFC 3164 auth critical message

# The example message from RFC 3164 section 5.4, verbatim:
# "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick"
packet   udp 10.0.0.1:51400 > 10.0.0.2:514  3c33343e4f63742031312032323a31343a3135206d796d616368696e652073753a2027737520726f6f7427206661696c656420666f72206c6f6e7669636b
proto    Syslog
str      syslog.pri_raw    <34

# BUG: the Syslog group always picks SYSLOG_5424, so an RFC 3164 message is
# parsed with the wrong layout and every field after the priority is wrong —
# here the hostname comes out as "11", a fragment of the timestamp. Decoding
# this message as SYSLOG_3164 directly gives "mymachine", so the layout is
# right and only the discrimination is broken.
#
# syslog.posa intends `bytes<2> version_sp defaults("1 ")` to be the
# discriminator: RFC 5424 has the version digit and a space there, RFC 3164 has
# the start of a month name. But a fixed-width byte field only reads bytes, it
# never rejects, so SYSLOG_5424 always succeeds and the group never falls
# through. The variant needs a constraint the engine can fail on.
xfail    the Syslog group always chooses SYSLOG_5424, so RFC 3164 mis-parses
str      syslog.hostname   mymachine

# BUG: syslog.posa documents these two at length — "the runtime derives
# syslog.facility and syslog.severity from the text value of syslog.pri_raw" —
# and its info line and every one of its colour rules reference them. Nothing
# derives them. posa's `let` evaluates numeric expressions over fields already
# parsed, and pri_raw is a string, so this cannot be fixed in the .posa file;
# the engine needs a way to read a number out of a string field.
#
# The consequence is not only two missing fields: the info line renders its
# missing arguments as empty, so a syslog packet summarises as ". 11 22:14:15
# su::" instead of "auth.critical mymachine su: ...".
xfail    syslog.facility is documented and colour-ruled but never derived
field    syslog.facility   4
xfail    syslog.severity is documented and colour-ruled but never derived
field    syslog.severity   2
xfail    the info line renders empty facility/severity, mangling the summary
info~    mymachine
