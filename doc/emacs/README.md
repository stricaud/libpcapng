# pcapsh-mode — Emacs major mode for `.pcapsh` files

A full Emacs major mode for the pcapsh packet-scripting language with
syntax highlighting, Python-style block indentation, and convenient
editing commands.

## Features

| Feature | Detail |
|---|---|
| Syntax highlighting | Keywords, layer constructors, posa protocols, TLS/SSH helpers, variables, string/hex literals, backslash continuations |
| Indentation | Python-style: `for`/`protocol` lines ending with `:` open a new block; `end` closes it |
| Electric colon | Pressing `:` at the end of a block-opening line re-indents automatically |
| Backslash continuation | `C-c C-j` inserts ` \` and moves to a new indented line |
| Comments | `M-;` toggles a `# ` comment on the current line or region |
| `TAB` | Always re-indents the current line |

## Highlighted elements

**Keywords** (`font-lock-keyword-face`)
: `for` `in` `range` `protocol` `end`

**Built-in layer constructors** (`font-lock-type-face`)
: `Ether` `IP` `TCP` `UDP` `ICMP` `TLS` `ARP` `DHCP` `NTP` `GRE`
  `VXLAN` `RADIUS` `NBT` `SMB2` `DCERPC` `LDAP` `DNS` `DNSQR` `DNSRR` …

**Protocol names from `.posa` files** (`font-lock-type-face`)
: `KRB5` `KRB5_REP` `NBNS` `MQTT` `OSPF` `BGP` `IGMP` `ICMPv6` `IPv6`
  `SCTP` `LDAP` `AMQP` `CoAP` `MPLS` `VRRP` `STP` `LACP` `BFD` …

**TLS / SSH helpers** (`font-lock-preprocessor-face`)
: `TLS_CLIENT_HELLO` `TLS_SERVER_HELLO` `TLS_CERTIFICATE`
  `TLS_CHANGE_CIPHER_SPEC` `TLS_FINISHED` `TLS_APPLICATION_DATA`
  `SSH_KEXINIT` `SSH_NEWKEYS`

**Built-in functions** (`font-lock-builtin-face`)
: `wrpcap` `fromhex` `frompcapng` `replacepkt` `show` `hexdump` `ls`
  `TCPSession` `syn` `syn_ack` `tcp_ack` `client_send` `server_send`
  `client_fin` `server_fin_ack` `RandShort`

**Variables** (`font-lock-variable-name-face`)
: Any identifier starting with `$` — e.g. `$i`, `$pkt`

**Named parameters** (`font-lock-constant-face`)
: `src=` `dst=` `dport=` `flags=` … (identifier immediately followed by `=`)

---

## Installation

### Automatic (recommended)

```bash
bash doc/emacs/install-pcapsh-mode.sh
```

The script:
1. Copies `pcapsh-mode.el` to `~/.emacs.d/`
2. Appends the necessary `autoload` and `auto-mode-alist` lines to
   `~/.emacs.d/init.el` (or `~/.emacs`) — idempotent, safe to run
   multiple times
3. Byte-compiles the file if `emacs` is found in `PATH`

After installation every file ending in `.pcapsh` will open in
`pcapsh-mode` automatically.

### Manual

Copy `pcapsh-mode.el` to a directory on your Emacs `load-path`, then
add to your `init.el`:

```elisp
(autoload 'pcapsh-mode "pcapsh-mode" "Major mode for pcapsh scripts." t)
(add-to-list 'auto-mode-alist '("\\.pcapsh\\'" . pcapsh-mode))
```

If you use `use-package` and keep the file in `~/.emacs.d/`:

```elisp
(use-package pcapsh-mode
  :load-path "~/.emacs.d"
  :mode "\\.pcapsh\\'")
```

---

## Indentation

The mode follows the same indentation rules as Python:

- A line ending with `:` (such as `for $i in range(10):` or
  `protocol MyHeader`) opens a new block — the next line is indented by
  `pcapsh-indent-offset` (default **4 spaces**).
- A bare `end` line closes the enclosing `protocol` block.
- Otherwise indentation is inherited from the previous non-blank line.
- `TAB` always re-indents the current line to the computed level.

To change the indentation step:

```elisp
(setq pcapsh-indent-offset 2)
```

---

## Key bindings

| Key | Action |
|---|---|
| `TAB` | Re-indent current line |
| `:` | Electric — insert `:` and re-indent block openers |
| `C-c C-j` | Insert ` \` continuation and move to new indented line |
| `M-;` | Toggle `# ` comment on line or region |

---

## Example

```pcapsh
# Three-way handshake + HTTP GET
for $i in range(3):
    wrpcap("handshake.pcapng", \
           Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/ \
           TCP(sport=12345, dport=80, flags="S"))

# Inline protocol definition
protocol MyApp
    required uint16 version = 1
    required uint32 length  = 0
end

wrpcap("app.pcapng", Ether()/IP()/UDP(dport=9999)/MyApp(version=2))
```

---

## Updating

Re-run the install script whenever `pcapsh-mode.el` is updated.  The
script overwrites the old copy and byte-recompiles automatically.
