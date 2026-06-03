;;; pcapsh-mode.el --- Major mode for pcapsh packet-scripting files  -*- lexical-binding: t; -*-

;; Keywords: languages pcap network packets
;; Version: 1.0

;;; Commentary:

;; Major mode for editing .pcapsh files.
;;
;; Features:
;;   - Syntax highlighting for built-in layer constructors, TLS/SSH helpers,
;;     posa protocol names shipped with libpcapng, keywords, variables ($name),
;;     comments, and string literals
;;   - Python-style indentation: TAB indents by `pcapsh-indent-offset' spaces;
;;     the colon at the end of a `for' or `protocol' line opens a new block
;;   - Electric colon: pressing `:' at end of a for/protocol line auto-indents
;;   - `M-;'  inserts a line comment (`# ')
;;   - `C-c C-j'  inserts a backslash continuation and a newline
;;
;; Indentation rules (mirrors Python):
;;   - Lines ending with `:' increase indentation for the next line.
;;   - Lines matching `end' (posa protocol terminator) decrease indentation
;;     back to the enclosing level.
;;   - Otherwise indentation is inherited from the previous non-blank line.
;;   - TAB always re-indents the current line.

;;; Code:

(require 'rx)
(require 'font-lock)
(require 'smie nil t)

;;; ── Face compatibility (font-lock-number-face / font-lock-escape-face added in Emacs 28) ───

(unless (facep 'font-lock-number-face)
  (defface font-lock-number-face '((t :inherit font-lock-constant-face))
    "Fallback face for numbers (Emacs < 28)." :group 'font-lock-faces))
(unless (boundp 'font-lock-number-face)
  (defvar font-lock-number-face 'font-lock-number-face))

(unless (facep 'font-lock-escape-face)
  (defface font-lock-escape-face '((t :inherit font-lock-string-face))
    "Fallback face for escape sequences (Emacs < 28)." :group 'font-lock-faces))
(unless (boundp 'font-lock-escape-face)
  (defvar font-lock-escape-face 'font-lock-escape-face))

;;; ── Customisation ────────────────────────────────────────────────────────────

(defgroup pcapsh nil
  "Major mode for pcapsh packet-scripting files."
  :group 'languages
  :prefix "pcapsh-")

(defcustom pcapsh-indent-offset 4
  "Number of spaces per indentation level in pcapsh-mode."
  :type 'integer
  :group 'pcapsh)

;;; ── Keyword / identifier lists ───────────────────────────────────────────────

;; Language keywords
(defconst pcapsh-keywords
  '("for" "in" "range" "protocol" "end"))

;; Core built-in layer constructors (hardcoded in pcapsh_eval.c)
(defconst pcapsh-builtin-layers
  '("Ether" "IP" "TCP" "UDP" "ICMP" "TLS" "Raw"
    "ARP" "DHCP" "NTP" "GRE" "VXLAN" "RADIUS" "SYSLOG"
    "NBT" "SMB2" "DCERPC" "LDAP" "TFTP" "Telnet"
    "TFTP_RRQ" "TFTP_WRQ" "TFTP_DATA" "TFTP_ACK" "TFTP_ERROR"
    "DNS" "DNSQR" "DNSRR"))

;; Protocol names from .posa files shipped in bin/protos/
(defconst pcapsh-posa-protocols
  '("AH" "AMQP" "BACnet" "BFD" "BGP" "CDP" "CoAP" "DCCP"
    "DHCPv6" "DNP3" "Dot1Q" "EAP" "EAPOL" "EAPOL_KEY" "EIGRP"
    "ESP" "HSRP" "ICMPv6" "IGMP" "IKEv2" "IPv6" "ISAKMP"
    "KRB5" "KRB5_REP" "L2TP" "LACP" "LLC" "MPLS" "MQTT"
    "ModbusTCP" "NBNS" "NetFlowV5" "OSPF" "OpenFlow" "PIM"
    "PPP" "PPPoE" "PTPv2" "RIPv2" "RSVP" "RTP" "SCTP"
    "SNAP" "SOCKS5_CONNECT" "SOCKS5_HELLO" "SOCKS5_REPLY" "SOCKS5_SERVER"
    "STP" "STUN" "VRRP" "WOL"))

;; TLS and SSH record helpers
(defconst pcapsh-tls-ssh-helpers
  '("TLS_CLIENT_HELLO" "TLS_SERVER_HELLO" "TLS_CERTIFICATE"
    "TLS_CHANGE_CIPHER_SPEC" "TLS_FINISHED" "TLS_APPLICATION_DATA"
    "SSH_KEXINIT" "SSH_NEWKEYS"))

;; General built-in functions
(defconst pcapsh-builtin-functions
  '("wrpcap" "fromhex" "frompcapng" "replacepkt" "show"
    "hexdump" "raw" "ls" "load" "help" "exit" "quit"
    "RandShort"
    "TCPSession" "syn" "syn_ack" "tcp_ack"
    "client_send" "server_send" "client_fin" "server_fin_ack"))

;;; ── Syntax table ─────────────────────────────────────────────────────────────

(defvar pcapsh-mode-syntax-table
  (let ((st (make-syntax-table)))
    ;; # starts a line comment
    (modify-syntax-entry ?# "<" st)
    (modify-syntax-entry ?\n ">" st)
    ;; String delimiters
    (modify-syntax-entry ?\" "\"" st)
    (modify-syntax-entry ?\' "\"" st)
    ;; $ is part of variable names
    (modify-syntax-entry ?$ "_" st)
    ;; Operators / punctuation
    (modify-syntax-entry ?/ "." st)
    (modify-syntax-entry ?= "." st)
    (modify-syntax-entry ?: "." st)
    (modify-syntax-entry ?, "." st)
    (modify-syntax-entry ?\\ "\\" st)
    st)
  "Syntax table for `pcapsh-mode'.")

;;; ── Font-lock ────────────────────────────────────────────────────────────────

(defvar pcapsh-font-lock-keywords
  (let ((kw-re      (regexp-opt pcapsh-keywords          'symbols))
        (layer-re   (regexp-opt pcapsh-builtin-layers     'symbols))
        (posa-re    (regexp-opt pcapsh-posa-protocols     'symbols))
        (tls-re     (regexp-opt pcapsh-tls-ssh-helpers    'symbols))
        (fn-re      (regexp-opt pcapsh-builtin-functions  'symbols)))
    `(
      ;; Keywords: for / in / range / protocol / end
      (,kw-re . font-lock-keyword-face)

      ;; Variables: $name
      (,(rx "$" (1+ (or word "_"))) . font-lock-variable-name-face)

      ;; TLS / SSH helpers — highlight before generic functions
      (,tls-re . font-lock-preprocessor-face)

      ;; posa protocol names (loaded from .posa files)
      (,posa-re . font-lock-type-face)

      ;; Core built-in layer constructors: Ether / IP / TCP / …
      (,layer-re . font-lock-type-face)

      ;; Built-in functions: wrpcap / fromhex / TCPSession / …
      (,fn-re . font-lock-builtin-face)

      ;; Named parameters inside calls: name=
      (,(rx (group (1+ (or word "_"))) "=") 1 font-lock-constant-face)

      ;; Hex literals: 0x…
      (,(rx (or "0x" "0X") (1+ hex-digit)) . font-lock-number-face)

      ;; Backslash continuation at end of line
      (,(rx "\\" (0+ space) eol) . font-lock-escape-face)
      ))
  "Font-lock keywords for `pcapsh-mode'.")

;;; ── Indentation ──────────────────────────────────────────────────────────────

(defun pcapsh--current-line-string ()
  "Return the current line as a string, stripped of leading/trailing whitespace."
  (string-trim (buffer-substring-no-properties
                (line-beginning-position)
                (line-end-position))))

(defun pcapsh--previous-non-blank-line ()
  "Move point to the previous non-blank, non-continuation line.
Returns the indentation column of that line, or 0 if none found."
  (let ((found nil))
    (save-excursion
      (forward-line -1)
      (while (and (not found) (not (bobp)))
        (let ((line (string-trim (buffer-substring-no-properties
                                  (line-beginning-position)
                                  (line-end-position)))))
          (if (string-empty-p line)
              (forward-line -1)
            (setq found (current-indentation)))))
      (or found 0))))

(defun pcapsh--previous-code-line ()
  "Return (INDENT . LINE-STRING) for the previous non-blank line."
  (save-excursion
    (forward-line -1)
    (while (and (not (bobp))
                (string-empty-p
                 (string-trim (buffer-substring-no-properties
                               (line-beginning-position)
                               (line-end-position)))))
      (forward-line -1))
    (cons (current-indentation)
          (string-trim (buffer-substring-no-properties
                        (line-beginning-position)
                        (line-end-position))))))

(defun pcapsh--line-opens-block-p (line)
  "Return non-nil if LINE ends with `:' (opens a new indentation block)."
  ;; Strip trailing backslash-continuation and whitespace before checking.
  (let ((s (replace-regexp-in-string "\\\\[ \t]*$" "" line)))
    (string-match-p ":[ \t]*$" s)))

(defun pcapsh--line-closes-block-p (line)
  "Return non-nil if LINE is an `end' keyword (closes a posa protocol block)."
  (string-match-p "^end[ \t]*$" line))

(defun pcapsh-indent-line ()
  "Indent the current line according to pcapsh indentation rules."
  (interactive)
  (let* ((cur-line   (pcapsh--current-line-string))
         (prev       (pcapsh--previous-code-line))
         (prev-ind   (car prev))
         (prev-line  (cdr prev))
         (target-ind
          (cond
           ;; `end' dedents to the level of the matching `protocol' line
           ((pcapsh--line-closes-block-p cur-line)
            (max 0 (- prev-ind pcapsh-indent-offset)))
           ;; previous line opened a block → increase
           ((pcapsh--line-opens-block-p prev-line)
            (+ prev-ind pcapsh-indent-offset))
           ;; otherwise inherit
           (t prev-ind))))
    (indent-line-to target-ind)))

;;; ── Electric colon ───────────────────────────────────────────────────────────

(defun pcapsh-electric-colon ()
  "Insert `:' and re-indent when at end of a for/protocol line."
  (interactive)
  (insert ":")
  (when (pcapsh--line-opens-block-p (pcapsh--current-line-string))
    (pcapsh-indent-line)))

;;; ── Backslash continuation ───────────────────────────────────────────────────

(defun pcapsh-insert-continuation ()
  "Insert a backslash continuation and start a new indented line."
  (interactive)
  (end-of-line)
  (unless (eq (char-before) ?\\)
    (insert " \\"))
  (newline-and-indent))

;;; ── Comment handling ─────────────────────────────────────────────────────────

(defun pcapsh-comment-dwim (arg)
  "Comment or uncomment region/line; insert `# ' when no region active."
  (interactive "*P")
  (require 'newcomment)
  (let ((comment-start "# ")
        (comment-end   ""))
    (comment-dwim arg)))

;;; ── Mode definition ──────────────────────────────────────────────────────────

(defvar pcapsh-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd ":")       #'pcapsh-electric-colon)
    (define-key map (kbd "C-c C-j") #'pcapsh-insert-continuation)
    (define-key map (kbd "M-;")     #'pcapsh-comment-dwim)
    (define-key map (kbd "TAB")     #'pcapsh-indent-line)
    map)
  "Keymap for `pcapsh-mode'.")

;;;###autoload
(define-derived-mode pcapsh-mode prog-mode "pcapsh"
  "Major mode for editing pcapsh packet-scripting files.

Syntax:
  Packets are built by chaining layer constructors with `/':
    wrpcap(\"out.pcapng\", Ether()/IP(src=\"1.2.3.4\")/TCP(dport=80, flags=\"S\"))

  Loops (Python-style, colon + indented block):
    for $i in range(10):
        wrpcap(\"x\", Ether()/IP()/ICMP())

  Inline protocol definition:
    protocol MyHeader
        required uint16 version = 1
        required uint32 length  = 0
    end

  Variables start with `$':
    $pkt = Ether()/IP()/UDP()

  Backslash continues a line:
    wrpcap(\"x\", Ether()/ \\
                IP()/TCP())

  Comments start with `#'.

Key bindings:
  TAB       re-indent current line
  :         electric colon — inserts `:' and re-indents block openers
  C-c C-j   insert backslash continuation and new line
  M-;       toggle comment

See `pcapsh-indent-offset' to change the indentation step (default 4)."
  (set-syntax-table pcapsh-mode-syntax-table)
  (set (make-local-variable 'comment-start)      "# ")
  (set (make-local-variable 'comment-end)        "")
  (set (make-local-variable 'comment-start-skip) "#+\\s-*")
  (set (make-local-variable 'indent-line-function) #'pcapsh-indent-line)
  (set (make-local-variable 'tab-width)          pcapsh-indent-offset)
  (set (make-local-variable 'indent-tabs-mode)   nil)
  (setq font-lock-defaults '((pcapsh-font-lock-keywords)))
  (font-lock-mode 1))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.pcapsh\\'" . pcapsh-mode))

(provide 'pcapsh-mode)

;;; pcapsh-mode.el ends here
