"""
Tests for the pycapng.pcapsh Python binding.

Run with:
    python3 -m pytest bindings/python/tests/          # from repo root
    python3 -m unittest discover -s bindings/python/tests
"""

import os
import sys
import struct
import unittest

# ── PYTHONPATH: find the libpcapng/ package ──────────────────────────────────
_HERE   = os.path.dirname(__file__)
_BINDIR = os.path.normpath(os.path.join(_HERE, ".."))      # bindings/python/
sys.path.insert(0, _BINDIR)

from pycapng import pcapsh

# ── Embedded script buffers ───────────────────────────────────────────────────

# Windows AD LAN simulation (DHCP/ARP/DNS/Kerberos/LDAP/SMB2/NTP/HTTPS).
# Mirrors the lan_corp scenario; produces 286 packets.
LAN_CORP = """\
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x0001,htype=1,hlen=6,flags=0x8000)/"\x63\x82\x53\x63\x35\x01\x01\xff")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="255.255.255.255",ttl=64)/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0x0001,yiaddr="10.0.1.1",siaddr="10.0.0.1")/"\x63\x82\x53\x63\x35\x01\x02\xff")
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x0001,htype=1,hlen=6)/"\x63\x82\x53\x63\x35\x01\x03\xff")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="255.255.255.255",ttl=64)/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0x0001,yiaddr="10.0.1.1",siaddr="10.0.0.1")/"\x63\x82\x53\x63\x35\x01\x05\xff")
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x0006,htype=1,hlen=6,flags=0x8000)/"\x63\x82\x53\x63\x35\x01\x01\xff")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:06")/IP(src="10.0.0.1",dst="255.255.255.255",ttl=64)/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0x0006,yiaddr="10.0.1.6",siaddr="10.0.0.1")/"\x63\x82\x53\x63\x35\x01\x02\xff")
wrpcap("x", Ether(src="02:00:00:01:00:14",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x0014,htype=1,hlen=6,flags=0x8000)/"\x63\x82\x53\x63\x35\x01\x01\xff")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:14")/IP(src="10.0.0.1",dst="255.255.255.255",ttl=64)/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0x0014,yiaddr="10.0.1.20",siaddr="10.0.0.1")/"\x63\x82\x53\x63\x35\x01\x02\xff")
wrpcap("x", Ether(src="02:00:00:01:00:14",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x0014,htype=1,hlen=6)/"\x63\x82\x53\x63\x35\x01\x03\xff")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:14")/IP(src="10.0.0.1",dst="255.255.255.255",ttl=64)/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0x0014,yiaddr="10.0.1.20",siaddr="10.0.0.1")/"\x63\x82\x53\x63\x35\x01\x05\xff")
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:01:00:01",spa="10.0.1.1",tpa="10.0.0.254"))
wrpcap("x", Ether(src="02:00:00:00:00:fe",dst="02:00:00:01:00:01",type=0x0806)/ARP(op=REPLY,sha="02:00:00:00:00:fe",spa="10.0.0.254",tha="02:00:00:01:00:01",tpa="10.0.1.1"))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:01:00:01",spa="10.0.1.1",tpa="10.0.0.1"))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01",type=0x0806)/ARP(op=REPLY,sha="02:00:00:00:00:01",spa="10.0.0.1",tha="02:00:00:01:00:01",tpa="10.0.1.1"))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:01:00:03",spa="10.0.1.3",tpa="10.0.0.254"))
wrpcap("x", Ether(src="02:00:00:00:00:fe",dst="02:00:00:01:00:03",type=0x0806)/ARP(op=REPLY,sha="02:00:00:00:00:fe",spa="10.0.0.254",tha="02:00:00:01:00:03",tpa="10.0.1.3"))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:01:00:06",spa="10.0.1.6",tpa="10.0.0.10"))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:06",type=0x0806)/ARP(op=REPLY,sha="02:00:00:00:00:0a",spa="10.0.0.10",tha="02:00:00:01:00:06",tpa="10.0.1.6"))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:00:00:01",spa="10.0.0.1",tha="00:00:00:00:00:00",tpa="10.0.0.1"))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:00:00:0a",spa="10.0.0.10",tha="00:00:00:00:00:00",tpa="10.0.0.10"))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.1",dst="10.0.1.255",ttl=1)/UDP(sport=137,dport=137)/NBNS(trans_id=0x0001,flags=NAME_REGISTRATION_REQUEST,qdcount=0,ancount=0,nscount=0,arcount=0))
wrpcap("x", Ether(src="02:00:00:01:00:02",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.2",dst="10.0.1.255",ttl=1)/UDP(sport=137,dport=137)/NBNS(trans_id=0x0002,flags=NAME_QUERY_REQUEST,qdcount=0,ancount=0,nscount=0,arcount=0))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:02")/IP(src="10.0.0.1",dst="10.0.1.2",ttl=64)/UDP(sport=137,dport=137)/NBNS(trans_id=0x0002,flags=NAME_QUERY_RESPONSE_POS,qdcount=0,ancount=0,nscount=0,arcount=0))
wrpcap("x", Ether(src="02:00:00:01:00:05",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.5",dst="10.0.1.255",ttl=1)/UDP(sport=137,dport=137)/NBNS(trans_id=0x0005,flags=NAME_QUERY_REQUEST,qdcount=0,ancount=0,nscount=0,arcount=0))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:05")/IP(src="10.0.0.10",dst="10.0.1.5",ttl=64)/UDP(sport=137,dport=137)/NBNS(trans_id=0x0005,flags=NAME_QUERY_RESPONSE_POS,qdcount=0,ancount=0,nscount=0,arcount=0))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=50100,dport=53)/DNS(id=0x0010,rd=1,qd=DNSQR(qname="_kerberos._tcp.corp.local",qtype=SRV)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=53,dport=50100)/DNS(id=0x0010,qr=1,rd=1,ra=1,an=DNSRR(rrname="_kerberos._tcp.corp.local",type=A,ttl=600,rdata="10.0.0.1"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=50101,dport=53)/DNS(id=0x0011,rd=1,qd=DNSQR(qname="_ldap._tcp.corp.local",qtype=SRV)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=53,dport=50101)/DNS(id=0x0011,qr=1,rd=1,ra=1,an=DNSRR(rrname="_ldap._tcp.corp.local",type=A,ttl=600,rdata="10.0.0.1"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=50102,dport=53)/DNS(id=0x0012,rd=1,qd=DNSQR(qname="_gc._tcp.corp.local",qtype=SRV)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=53,dport=50102)/DNS(id=0x0012,qr=1,rd=1,ra=1,an=DNSRR(rrname="_gc._tcp.corp.local",type=A,ttl=600,rdata="10.0.0.1"),qdcount=0,ancount=1))
for $i in range(20):
    wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=50200,dport=53)/DNS(id=$i,rd=1,qd=DNSQR(qname="dc01.corp.local",qtype=A)))
    wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=53,dport=50200)/DNS(id=$i,qr=1,rd=1,ra=1,an=DNSRR(rrname="dc01.corp.local",type=A,ttl=300,rdata="10.0.0.1"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=50300,dport=53)/DNS(id=0x0030,rd=1,qd=DNSQR(qname="fs01.corp.local",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=53,dport=50300)/DNS(id=0x0030,qr=1,rd=1,ra=1,an=DNSRR(rrname="fs01.corp.local",type=A,ttl=300,rdata="10.0.0.10"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:02",dst="02:00:00:00:00:01")/IP(src="10.0.1.2",dst="10.0.0.1",ttl=64)/UDP(sport=50400,dport=53)/DNS(id=0x0040,rd=1,qd=DNSQR(qname="ap.spotify.com",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:02")/IP(src="10.0.0.1",dst="10.0.1.2",ttl=64)/UDP(sport=53,dport=50400)/DNS(id=0x0040,qr=1,rd=1,ra=1,an=DNSRR(rrname="ap.spotify.com",type=A,ttl=60,rdata="35.186.224.25"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:04",dst="02:00:00:00:00:01")/IP(src="10.0.1.4",dst="10.0.0.1",ttl=64)/UDP(sport=50401,dport=53)/DNS(id=0x0041,rd=1,qd=DNSQR(qname="onedrive.live.com",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:04")/IP(src="10.0.0.1",dst="10.0.1.4",ttl=64)/UDP(sport=53,dport=50401)/DNS(id=0x0041,qr=1,rd=1,ra=1,an=DNSRR(rrname="onedrive.live.com",type=A,ttl=60,rdata="52.115.0.25"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:07",dst="02:00:00:00:00:01")/IP(src="10.0.1.7",dst="10.0.0.1",ttl=64)/UDP(sport=50402,dport=53)/DNS(id=0x0042,rd=1,qd=DNSQR(qname="teams.microsoft.com",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:07")/IP(src="10.0.0.1",dst="10.0.1.7",ttl=64)/UDP(sport=53,dport=50402)/DNS(id=0x0042,qr=1,rd=1,ra=1,an=DNSRR(rrname="teams.microsoft.com",type=A,ttl=60,rdata="13.107.42.14"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:09",dst="02:00:00:00:00:01")/IP(src="10.0.1.9",dst="10.0.0.1",ttl=64)/UDP(sport=50403,dport=53)/DNS(id=0x0043,rd=1,qd=DNSQR(qname="login.microsoftonline.com",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:09")/IP(src="10.0.0.1",dst="10.0.1.9",ttl=64)/UDP(sport=53,dport=50403)/DNS(id=0x0043,qr=1,rd=1,ra=1,an=DNSRR(rrname="login.microsoftonline.com",type=A,ttl=60,rdata="20.190.128.1"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:0b",dst="02:00:00:00:00:01")/IP(src="10.0.1.11",dst="10.0.0.1",ttl=64)/UDP(sport=50404,dport=53)/DNS(id=0x0044,rd=1,qd=DNSQR(qname="windowsupdate.microsoft.com",qtype=A)))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0b")/IP(src="10.0.0.1",dst="10.0.1.11",ttl=64)/UDP(sport=53,dport=50404)/DNS(id=0x0044,qr=1,rd=1,ra=1,an=DNSRR(rrname="windowsupdate.microsoft.com",type=A,ttl=60,rdata="13.89.179.10"),qdcount=0,ancount=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=52001,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=88,dport=52001)/KRB5_REP(app_tag=KRB_ERROR,msg_type=KRB_ERROR_VAL))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=52001,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=88,dport=52001)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/UDP(sport=52001,dport=88)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/UDP(sport=88,dport=52001)/KRB5_REP(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:05",dst="02:00:00:00:00:01")/IP(src="10.0.1.5",dst="10.0.0.1",ttl=64)/UDP(sport=52005,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:05")/IP(src="10.0.0.1",dst="10.0.1.5",ttl=64)/UDP(sport=88,dport=52005)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:05",dst="02:00:00:00:00:01")/IP(src="10.0.1.5",dst="10.0.0.1",ttl=64)/UDP(sport=52005,dport=88)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:05")/IP(src="10.0.0.1",dst="10.0.1.5",ttl=64)/UDP(sport=88,dport=52005)/KRB5_REP(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/UDP(sport=52010,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/UDP(sport=88,dport=52010)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/UDP(sport=52010,dport=88)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/UDP(sport=88,dport=52010)/KRB5_REP(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:0f",dst="02:00:00:00:00:01")/IP(src="10.0.1.15",dst="10.0.0.1",ttl=64)/UDP(sport=52015,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0f")/IP(src="10.0.0.1",dst="10.0.1.15",ttl=64)/UDP(sport=88,dport=52015)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:0f",dst="02:00:00:00:00:01")/IP(src="10.0.1.15",dst="10.0.0.1",ttl=64)/UDP(sport=52015,dport=88)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0f")/IP(src="10.0.0.1",dst="10.0.1.15",ttl=64)/UDP(sport=88,dport=52015)/KRB5_REP(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:14",dst="02:00:00:00:00:01")/IP(src="10.0.1.20",dst="10.0.0.1",ttl=64)/UDP(sport=52020,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:14")/IP(src="10.0.0.1",dst="10.0.1.20",ttl=64)/UDP(sport=88,dport=52020)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:14",dst="02:00:00:00:00:01")/IP(src="10.0.1.20",dst="10.0.0.1",ttl=64)/UDP(sport=52020,dport=88)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:14")/IP(src="10.0.0.1",dst="10.0.1.20",ttl=64)/UDP(sport=88,dport=52020)/KRB5_REP(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:02",dst="02:00:00:00:00:01")/IP(src="10.0.1.2",dst="10.0.0.1",ttl=64)/UDP(sport=52002,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:02")/IP(src="10.0.0.1",dst="10.0.1.2",ttl=64)/UDP(sport=88,dport=52002)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:08",dst="02:00:00:00:00:01")/IP(src="10.0.1.8",dst="10.0.0.1",ttl=64)/UDP(sport=52008,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:08")/IP(src="10.0.0.1",dst="10.0.1.8",ttl=64)/UDP(sport=88,dport=52008)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:0e",dst="02:00:00:00:00:01")/IP(src="10.0.1.14",dst="10.0.0.1",ttl=64)/UDP(sport=52014,dport=88)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0e")/IP(src="10.0.0.1",dst="10.0.1.14",ttl=64)/UDP(sport=88,dport=52014)/KRB5_REP(app_tag=AS_REP,msg_type=AS_REPLY))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="PA",seq=1,ack=1)/LDAP(op_tag=BIND_REQUEST,message_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="PA",seq=1,ack=8)/LDAP(op_tag=BIND_RESPONSE,message_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="PA",seq=8,ack=8)/LDAP(op_tag=SEARCH_REQUEST,message_id=2))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="PA",seq=8,ack=15)/LDAP(op_tag=SEARCH_RESULT_ENTRY,message_id=2))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="PA",seq=15,ack=15)/LDAP(op_tag=SEARCH_RESULT_DONE,message_id=2))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="PA",seq=15,ack=22)/LDAP(op_tag=SEARCH_REQUEST,message_id=3))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="PA",seq=22,ack=22)/LDAP(op_tag=SEARCH_RESULT_DONE,message_id=3))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=54001,dport=389,flags="FA",seq=22,ack=29))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=389,dport=54001,flags="FA",seq=29,ack=23))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/TCP(sport=54010,dport=389,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/TCP(sport=389,dport=54010,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/TCP(sport=54010,dport=389,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/TCP(sport=54010,dport=389,flags="PA",seq=1,ack=1)/LDAP(op_tag=BIND_REQUEST,message_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/TCP(sport=389,dport=54010,flags="PA",seq=1,ack=8)/LDAP(op_tag=BIND_RESPONSE,message_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/TCP(sport=54010,dport=389,flags="PA",seq=8,ack=8)/LDAP(op_tag=SEARCH_REQUEST,message_id=2))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/TCP(sport=389,dport=54010,flags="PA",seq=8,ack=15)/LDAP(op_tag=SEARCH_RESULT_ENTRY,message_id=2))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/TCP(sport=389,dport=54010,flags="PA",seq=15,ack=15)/LDAP(op_tag=SEARCH_RESULT_DONE,message_id=2))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:01")/IP(src="10.0.1.10",dst="10.0.0.1",ttl=64)/TCP(sport=54010,dport=389,flags="FA",seq=15,ack=22))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:0a")/IP(src="10.0.0.1",dst="10.0.1.10",ttl=64)/TCP(sport=389,dport=54010,flags="FA",seq=22,ack=16))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55001,dport=135,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=135,dport=55001,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55001,dport=135,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55001,dport=135,flags="PA",seq=1,ack=1)/DCERPC(type=BIND,call_id=1,frag_len=72))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=135,dport=55001,flags="PA",seq=1,ack=17)/DCERPC(type=BIND_ACK,call_id=1,frag_len=60))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55001,dport=135,flags="PA",seq=17,ack=17)/DCERPC(type=REQUEST,call_id=2,frag_len=84))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=135,dport=55001,flags="PA",seq=17,ack=33)/DCERPC(type=RESPONSE,call_id=2,frag_len=76))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55002,dport=49152,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=49152,dport=55002,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55002,dport=49152,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55002,dport=49152,flags="PA",seq=1,ack=1)/DCERPC(type=BIND,call_id=1,frag_len=72))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=49152,dport=55002,flags="PA",seq=1,ack=17)/DCERPC(type=BIND_ACK,call_id=1,frag_len=60))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55002,dport=49152,flags="PA",seq=17,ack=17)/DCERPC(type=REQUEST,call_id=2,frag_len=120))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=49152,dport=55002,flags="PA",seq=17,ack=33)/DCERPC(type=RESPONSE,call_id=2,frag_len=96))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/TCP(sport=55002,dport=49152,flags="FA",seq=33,ack=33))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/TCP(sport=49152,dport=55002,flags="FA",seq=33,ack=34))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:02")/IP(src="10.0.1.1",dst="10.0.0.2",ttl=64)/UDP(sport=49152,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:01")/IP(src="10.0.0.2",dst="10.0.1.1",ttl=64)/UDP(sport=123,dport=49152)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:02",dst="02:00:00:00:00:02")/IP(src="10.0.1.2",dst="10.0.0.2",ttl=64)/UDP(sport=49153,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:02")/IP(src="10.0.0.2",dst="10.0.1.2",ttl=64)/UDP(sport=123,dport=49153)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:02")/IP(src="10.0.1.3",dst="10.0.0.2",ttl=64)/UDP(sport=49154,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:03")/IP(src="10.0.0.2",dst="10.0.1.3",ttl=64)/UDP(sport=123,dport=49154)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:04",dst="02:00:00:00:00:02")/IP(src="10.0.1.4",dst="10.0.0.2",ttl=64)/UDP(sport=49155,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:04")/IP(src="10.0.0.2",dst="10.0.1.4",ttl=64)/UDP(sport=123,dport=49155)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:05",dst="02:00:00:00:00:02")/IP(src="10.0.1.5",dst="10.0.0.2",ttl=64)/UDP(sport=49156,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:05")/IP(src="10.0.0.2",dst="10.0.1.5",ttl=64)/UDP(sport=123,dport=49156)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:02")/IP(src="10.0.1.6",dst="10.0.0.2",ttl=64)/UDP(sport=49157,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:06")/IP(src="10.0.0.2",dst="10.0.1.6",ttl=64)/UDP(sport=123,dport=49157)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:07",dst="02:00:00:00:00:02")/IP(src="10.0.1.7",dst="10.0.0.2",ttl=64)/UDP(sport=49158,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:07")/IP(src="10.0.0.2",dst="10.0.1.7",ttl=64)/UDP(sport=123,dport=49158)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:08",dst="02:00:00:00:00:02")/IP(src="10.0.1.8",dst="10.0.0.2",ttl=64)/UDP(sport=49159,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:08")/IP(src="10.0.0.2",dst="10.0.1.8",ttl=64)/UDP(sport=123,dport=49159)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:09",dst="02:00:00:00:00:02")/IP(src="10.0.1.9",dst="10.0.0.2",ttl=64)/UDP(sport=49160,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:09")/IP(src="10.0.0.2",dst="10.0.1.9",ttl=64)/UDP(sport=123,dport=49160)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0a",dst="02:00:00:00:00:02")/IP(src="10.0.1.10",dst="10.0.0.2",ttl=64)/UDP(sport=49161,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0a")/IP(src="10.0.0.2",dst="10.0.1.10",ttl=64)/UDP(sport=123,dport=49161)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0b",dst="02:00:00:00:00:02")/IP(src="10.0.1.11",dst="10.0.0.2",ttl=64)/UDP(sport=49162,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0b")/IP(src="10.0.0.2",dst="10.0.1.11",ttl=64)/UDP(sport=123,dport=49162)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0c",dst="02:00:00:00:00:02")/IP(src="10.0.1.12",dst="10.0.0.2",ttl=64)/UDP(sport=49163,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0c")/IP(src="10.0.0.2",dst="10.0.1.12",ttl=64)/UDP(sport=123,dport=49163)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0d",dst="02:00:00:00:00:02")/IP(src="10.0.1.13",dst="10.0.0.2",ttl=64)/UDP(sport=49164,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0d")/IP(src="10.0.0.2",dst="10.0.1.13",ttl=64)/UDP(sport=123,dport=49164)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0e",dst="02:00:00:00:00:02")/IP(src="10.0.1.14",dst="10.0.0.2",ttl=64)/UDP(sport=49165,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0e")/IP(src="10.0.0.2",dst="10.0.1.14",ttl=64)/UDP(sport=123,dport=49165)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:0f",dst="02:00:00:00:00:02")/IP(src="10.0.1.15",dst="10.0.0.2",ttl=64)/UDP(sport=49166,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:0f")/IP(src="10.0.0.2",dst="10.0.1.15",ttl=64)/UDP(sport=123,dport=49166)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:10",dst="02:00:00:00:00:02")/IP(src="10.0.1.16",dst="10.0.0.2",ttl=64)/UDP(sport=49167,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:10")/IP(src="10.0.0.2",dst="10.0.1.16",ttl=64)/UDP(sport=123,dport=49167)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:11",dst="02:00:00:00:00:02")/IP(src="10.0.1.17",dst="10.0.0.2",ttl=64)/UDP(sport=49168,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:11")/IP(src="10.0.0.2",dst="10.0.1.17",ttl=64)/UDP(sport=123,dport=49168)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:12",dst="02:00:00:00:00:02")/IP(src="10.0.1.18",dst="10.0.0.2",ttl=64)/UDP(sport=49169,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:12")/IP(src="10.0.0.2",dst="10.0.1.18",ttl=64)/UDP(sport=123,dport=49169)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:13",dst="02:00:00:00:00:02")/IP(src="10.0.1.19",dst="10.0.0.2",ttl=64)/UDP(sport=49170,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:13")/IP(src="10.0.0.2",dst="10.0.1.19",ttl=64)/UDP(sport=123,dport=49170)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:14",dst="02:00:00:00:00:02")/IP(src="10.0.1.20",dst="10.0.0.2",ttl=64)/UDP(sport=49171,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
wrpcap("x", Ether(src="02:00:00:00:00:02",dst="02:00:00:01:00:14")/IP(src="10.0.0.2",dst="10.0.1.20",ttl=64)/UDP(sport=123,dport=49171)/NTP(li_vn_mode=SERVER,stratum=1,ref_id=0x47505300))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=1,ack=1)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,credit_request=1,message_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=1,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,flags=1,message_id=1,session_id=0x100))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=69,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,credit_request=1,message_id=2,session_id=0x100))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=69,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,flags=1,message_id=2,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=137,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=CREATE,message_id=3,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=137,ack=205)/NBT(type=SESSION_MESSAGE)/SMB2(command=CREATE,flags=1,message_id=3,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=205,ack=205)/NBT(type=SESSION_MESSAGE)/SMB2(command=READ,message_id=4,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=205,ack=273)/NBT(type=SESSION_MESSAGE)/SMB2(command=READ,flags=1,message_id=4,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=273,ack=273)/NBT(type=SESSION_MESSAGE)/SMB2(command=WRITE,message_id=5,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=273,ack=341)/NBT(type=SESSION_MESSAGE)/SMB2(command=WRITE,flags=1,message_id=5,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="PA",seq=341,ack=341)/NBT(type=SESSION_MESSAGE)/SMB2(command=CLOSE,message_id=6,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="PA",seq=341,ack=409)/NBT(type=SESSION_MESSAGE)/SMB2(command=CLOSE,flags=1,message_id=6,session_id=0x100,tree_id=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:0a")/IP(src="10.0.1.1",dst="10.0.0.10",ttl=64)/TCP(sport=56001,dport=445,flags="FA",seq=409,ack=409))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:01")/IP(src="10.0.0.10",dst="10.0.1.1",ttl=64)/TCP(sport=445,dport=56001,flags="FA",seq=409,ack=410))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:03")/IP(src="10.0.0.10",dst="10.0.1.3",ttl=64)/TCP(sport=445,dport=56003,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="PA",seq=1,ack=1)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,message_id=1,session_id=0x200))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:03")/IP(src="10.0.0.10",dst="10.0.1.3",ttl=64)/TCP(sport=445,dport=56003,flags="PA",seq=1,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,flags=1,message_id=1,session_id=0x200))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="PA",seq=69,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,message_id=2,session_id=0x200))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:03")/IP(src="10.0.0.10",dst="10.0.1.3",ttl=64)/TCP(sport=445,dport=56003,flags="PA",seq=69,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,flags=1,message_id=2,session_id=0x200,tree_id=2))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="PA",seq=137,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=READ,message_id=3,session_id=0x200,tree_id=2))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:03")/IP(src="10.0.0.10",dst="10.0.1.3",ttl=64)/TCP(sport=445,dport=56003,flags="PA",seq=137,ack=205)/NBT(type=SESSION_MESSAGE)/SMB2(command=READ,flags=1,message_id=3,session_id=0x200,tree_id=2))
wrpcap("x", Ether(src="02:00:00:01:00:03",dst="02:00:00:00:00:0a")/IP(src="10.0.1.3",dst="10.0.0.10",ttl=64)/TCP(sport=56003,dport=445,flags="FA",seq=205,ack=205))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:03")/IP(src="10.0.0.10",dst="10.0.1.3",ttl=64)/TCP(sport=445,dport=56003,flags="FA",seq=205,ack=206))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="S",seq=0))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:06")/IP(src="10.0.0.10",dst="10.0.1.6",ttl=64)/TCP(sport=445,dport=56006,flags="SA",seq=0,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="A",seq=1,ack=1))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="PA",seq=1,ack=1)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,message_id=1,session_id=0x300))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:06")/IP(src="10.0.0.10",dst="10.0.1.6",ttl=64)/TCP(sport=445,dport=56006,flags="PA",seq=1,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=SESSION_SETUP,flags=1,message_id=1,session_id=0x300))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="PA",seq=69,ack=69)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,message_id=2,session_id=0x300))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:06")/IP(src="10.0.0.10",dst="10.0.1.6",ttl=64)/TCP(sport=445,dport=56006,flags="PA",seq=69,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=TREE_CONNECT,flags=1,message_id=2,session_id=0x300,tree_id=3))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="PA",seq=137,ack=137)/NBT(type=SESSION_KEEPALIVE))
wrpcap("x", Ether(src="02:00:00:01:00:06",dst="02:00:00:00:00:0a")/IP(src="10.0.1.6",dst="10.0.0.10",ttl=64)/TCP(sport=56006,dport=445,flags="PA",seq=141,ack=137)/NBT(type=SESSION_MESSAGE)/SMB2(command=ECHO,message_id=10,session_id=0x300,tree_id=3))
wrpcap("x", Ether(src="02:00:00:00:00:0a",dst="02:00:00:01:00:06")/IP(src="10.0.0.10",dst="10.0.1.6",ttl=64)/TCP(sport=445,dport=56006,flags="PA",seq=137,ack=209)/NBT(type=SESSION_MESSAGE)/SMB2(command=ECHO,flags=1,message_id=10,session_id=0x300,tree_id=3))
spotify_ws02 = TCPSession("10.0.1.2", "35.186.224.25", 57002, 443)
wrpcap("x", syn(spotify_ws02))
wrpcap("x", syn_ack(spotify_ws02))
wrpcap("x", tcp_ack(spotify_ws02))
wrpcap("x", client_send(spotify_ws02, "GET /track/7ouMYWpwJ422jRcDASZB7P HTTP/1.1\\r\\nHost: ap.spotify.com\\r\\nUser-Agent: Spotify/8.8.0\\r\\n\\r\\n"))
wrpcap("x", server_send(spotify_ws02, "HTTP/1.1 200 OK\\r\\nContent-Type: audio/ogg\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"))
wrpcap("x", client_fin(spotify_ws02))
wrpcap("x", server_fin_ack(spotify_ws02))
onedrive_ws04 = TCPSession("10.0.1.4", "52.115.0.25", 57004, 443)
wrpcap("x", syn(onedrive_ws04))
wrpcap("x", syn_ack(onedrive_ws04))
wrpcap("x", tcp_ack(onedrive_ws04))
wrpcap("x", client_send(onedrive_ws04, "POST /v1.0/me/drive/root/children HTTP/1.1\\r\\nHost: onedrive.live.com\\r\\nAuthorization: Bearer eyJhbGciOiJSUzI1NiJ9...\\r\\n\\r\\n"))
wrpcap("x", server_send(onedrive_ws04, "HTTP/1.1 201 Created\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\"id\\":\\"01BYE5RZ\\"}"))
wrpcap("x", client_fin(onedrive_ws04))
wrpcap("x", server_fin_ack(onedrive_ws04))
teams_ws07 = TCPSession("10.0.1.7", "13.107.42.14", 57007, 443)
wrpcap("x", syn(teams_ws07))
wrpcap("x", syn_ack(teams_ws07))
wrpcap("x", tcp_ack(teams_ws07))
wrpcap("x", client_send(teams_ws07, "GET /v2/users/ME/conversations?pageSize=20 HTTP/1.1\\r\\nHost: teams.microsoft.com\\r\\nAuthorization: Bearer eyJhbGciOiJSUzI1NiJ9...\\r\\n\\r\\n"))
wrpcap("x", server_send(teams_ws07, "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\"value\\":[]}"))
wrpcap("x", client_fin(teams_ws07))
wrpcap("x", server_fin_ack(teams_ws07))
aad_ws09 = TCPSession("10.0.1.9", "20.190.128.1", 57009, 443)
wrpcap("x", syn(aad_ws09))
wrpcap("x", syn_ack(aad_ws09))
wrpcap("x", tcp_ack(aad_ws09))
wrpcap("x", client_send(aad_ws09, "POST /common/oauth2/token HTTP/1.1\\r\\nHost: login.microsoftonline.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\ngrant_type=refresh_token&client_id=d3590ed6-52b3&refresh_token=AQAB..."))
wrpcap("x", server_send(aad_ws09, "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\"token_type\\":\\"Bearer\\",\\"expires_in\\":3599}"))
wrpcap("x", client_fin(aad_ws09))
wrpcap("x", server_fin_ack(aad_ws09))
wu_ws11 = TCPSession("10.0.1.11", "13.89.179.10", 57011, 443)
wrpcap("x", syn(wu_ws11))
wrpcap("x", syn_ack(wu_ws11))
wrpcap("x", tcp_ack(wu_ws11))
wrpcap("x", client_send(wu_ws11, "POST /v9/ClientWebService/client.asmx HTTP/1.1\\r\\nHost: fe3.delivery.mp.microsoft.com\\r\\nContent-Type: text/xml\\r\\nSOAPAction: GetExtendedUpdateInfo2\\r\\n\\r\\n<?xml version=\\"1.0\\"?><soap:Envelope/>"))
wrpcap("x", server_send(wu_ws11, "HTTP/1.1 200 OK\\r\\nContent-Type: text/xml\\r\\n\\r\\n<?xml version=\\"1.0\\"?><soap:Envelope/>"))
wrpcap("x", client_fin(wu_ws11))
wrpcap("x", server_fin_ack(wu_ws11))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:fe")/IP(src="10.0.1.1",dst="10.0.0.254",ttl=64)/ICMP(type=8,id=1,seq=1))
wrpcap("x", Ether(src="02:00:00:00:00:fe",dst="02:00:00:01:00:01")/IP(src="10.0.0.254",dst="10.0.1.1",ttl=64)/ICMP(type=0,id=1,seq=1))
wrpcap("x", Ether(src="02:00:00:01:00:08",dst="02:00:00:00:00:fe")/IP(src="10.0.1.8",dst="10.0.0.254",ttl=64)/ICMP(type=8,id=8,seq=1))
wrpcap("x", Ether(src="02:00:00:00:00:fe",dst="02:00:00:01:00:08")/IP(src="10.0.0.254",dst="10.0.1.8",ttl=64)/ICMP(type=0,id=8,seq=1))
wrpcap("x", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1",ttl=64)/ICMP(type=8,id=2,seq=1))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1",ttl=64)/ICMP(type=0,id=2,seq=1))
for $i in range(5):
    wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op=REQUEST,sha="02:00:00:01:00:01",spa="10.0.1.1",tpa="10.0.0.1"))
    wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01",type=0x0806)/ARP(op=REPLY,sha="02:00:00:00:00:01",spa="10.0.0.1",tha="02:00:00:01:00:01",tpa="10.0.1.1"))
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:fe")/IP(src="10.0.0.1",dst="10.0.0.254",ttl=64)/UDP(sport=514,dport=514)/"<38>May 11 10:00:01 dc01 Netlogon[1234]: CORP\\WS01$ machine account authenticated")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:fe")/IP(src="10.0.0.1",dst="10.0.0.254",ttl=64)/UDP(sport=514,dport=514)/"<37>May 11 10:00:02 dc01 Netlogon[1234]: CORP domain replication complete")
wrpcap("x", Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:fe")/IP(src="10.0.0.1",dst="10.0.0.254",ttl=64)/UDP(sport=514,dport=514)/"<36>May 11 10:00:03 dc01 Netlogon[1234]: Warning: replication latency 320ms exceeds threshold")
for $i in range(5):
    wrpcap("x", Ether(src="02:00:00:01:00:01",dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.1",dst="10.0.1.255",ttl=1)/UDP(sport=137,dport=137)/NBNS(trans_id=$i,flags=NAME_REFRESH_REQUEST,qdcount=0,ancount=0,nscount=0,arcount=0))
"""

# LDAP DirSync over LDAPS (TLS) — 18 packets
LDAP_DIRSYNC = """\
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4373,flags=2)/TCP(sport=4066,dport=636,seq=3857412636,flags="S",window=64240,mss=1460,sack_perm=1))
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec2f,flags=2)/TCP(sport=636,dport=4066,seq=2688871124,ack=3857412637,flags="SA",window=64240,mss=1460,sack_perm=1))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4374,flags=2)/TCP(sport=4066,dport=636,seq=3857412637,ack=2688871125,flags="A",window=64240))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4375,flags=2)/TCP(sport=4066,dport=636,seq=3857412637,ack=2688871125,flags="PA",window=64240)/TLS_CLIENT_HELLO())
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec30,flags=2)/TCP(sport=636,dport=4066,seq=2688871125,ack=3857412687,flags="PA",window=64240)/TLS_SERVER_HELLO())
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec31,flags=2)/TCP(sport=636,dport=4066,seq=2688871172,ack=3857412687,flags="PA",window=64240)/TLS_CERTIFICATE())
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4376,flags=2)/TCP(sport=4066,dport=636,seq=3857412687,ack=2688871184,flags="PA",window=64240)/TLS_CHANGE_CIPHER_SPEC())
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4377,flags=2)/TCP(sport=4066,dport=636,seq=3857412693,ack=2688871184,flags="PA",window=64240)/TLS_FINISHED())
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec32,flags=2)/TCP(sport=636,dport=4066,seq=2688871184,ack=3857412714,flags="PA",window=64240)/TLS_CHANGE_CIPHER_SPEC())
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec33,flags=2)/TCP(sport=636,dport=4066,seq=2688871190,ack=3857412714,flags="PA",window=64240)/TLS_FINISHED())
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4378,flags=2)/TCP(sport=4066,dport=636,seq=3857412714,ack=2688871211,flags="PA",window=64240)/TLS()/LDAP(op_tag=BIND_REQUEST,message_id=7))
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec34,flags=2)/TCP(sport=636,dport=4066,seq=2688871211,ack=3857412726,flags="PA",window=64240)/TLS()/LDAP(op_tag=BIND_RESPONSE,message_id=7))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x4379,flags=2)/TCP(sport=4066,dport=636,seq=3857412726,ack=2688871223,flags="PA",window=64240)/TLS()/LDAP(op_tag=SEARCH_REQUEST,message_id=8))
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec35,flags=2)/TCP(sport=636,dport=4066,seq=2688871223,ack=3857412738,flags="PA",window=64240)/TLS()/LDAP(op_tag=SEARCH_RESULT_DONE,message_id=8))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x437a,flags=2)/TCP(sport=4066,dport=636,seq=3857412738,ack=2688871235,flags="PA",window=64240)/TLS()/LDAP(op_tag=UNBIND_REQUEST,message_id=9))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x437b,flags=2)/TCP(sport=4066,dport=636,seq=3857412750,ack=2688871235,flags="FA",window=64240))
wrpcap("x", Ether(src="00:50:56:c0:00:01",dst="00:0c:29:09:4d:fa")/IP(src="172.31.1.101",dst="192.168.0.3",ttl=128,id=0xec36,flags=2)/TCP(sport=636,dport=4066,seq=2688871235,ack=3857412751,flags="FA",window=64240))
wrpcap("x", Ether(src="00:0c:29:09:4d:fa",dst="00:50:56:c0:00:01")/IP(src="192.168.0.3",dst="172.31.1.101",ttl=126,id=0x437c,flags=2)/TCP(sport=4066,dport=636,seq=3857412751,ack=2688871236,flags="A",window=64240))
"""


# ── Unit tests — no external files needed ─────────────────────────────────────

class TestInstantiation(unittest.TestCase):
    def test_create(self):
        sh = pcapsh.PcapSH()
        self.assertIsNotNone(sh)

    def test_docstring(self):
        self.assertIn("PCAPSH_PROTOS_DIR", pcapsh.__doc__)


class TestRunString(unittest.TestCase):
    def setUp(self):
        self.sh = pcapsh.PcapSH()

    def test_single_packet(self):
        pkts = self.sh.run_string(
            'wrpcap("x", Ether()/IP(src="1.2.3.4", dst="5.6.7.8")'
            '/TCP(sport=1234, dport=80, flags="S"))'
        )
        self.assertEqual(len(pkts), 1)
        self.assertIsInstance(pkts[0], bytes)
        self.assertGreater(len(pkts[0]), 40)  # Ether(14) + IP(20) + TCP(20)

    def test_two_packets(self):
        pkts = self.sh.run_string("""\
wrpcap("x", Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=100, dport=200, flags="S"))
wrpcap("x", Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=200, dport=100, flags="SA"))
""")
        self.assertEqual(len(pkts), 2)

    def test_udp_packet(self):
        pkts = self.sh.run_string(
            'wrpcap("x", Ether()/IP()/UDP(sport=53, dport=1234)/fromhex("deadbeef"))'
        )
        self.assertEqual(len(pkts), 1)
        # UDP = 8 bytes; payload = 4 bytes
        self.assertEqual(len(pkts[0]), 14 + 20 + 8 + 4)

    def test_empty_script(self):
        pkts = self.sh.run_string("# just a comment\n")
        self.assertEqual(len(pkts), 0)

    def test_backslash_continuation(self):
        pkts = self.sh.run_string("""\
wrpcap("x", Ether()/ \\
            IP(src="1.1.1.1", dst="2.2.2.2")/ \\
            TCP(sport=80, dport=9999, flags="PA")/ \\
            fromhex("48454c4c4f"))
""")
        self.assertEqual(len(pkts), 1)
        self.assertIn(b"HELLO", pkts[0])

    def test_for_loop(self):
        pkts = self.sh.run_string("""\
for $i in range(5):
    wrpcap("x", Ether()/IP()/ICMP())
""")
        self.assertEqual(len(pkts), 5)

    def test_returns_bytes(self):
        pkts = self.sh.run_string(
            'wrpcap("x", Ether()/IP()/TCP(flags="S"))'
        )
        self.assertIsInstance(pkts[0], bytes)

    def test_ethernet_header(self):
        pkts = self.sh.run_string(
            'wrpcap("x", Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")'
            '/IP()/UDP())'
        )
        frame = pkts[0]
        # Bytes 0-5: dst MAC, 6-11: src MAC
        self.assertEqual(frame[0:6], bytes.fromhex("112233445566"))
        self.assertEqual(frame[6:12], bytes.fromhex("aabbccddeeff"))

    def test_tcp_seq_ack_auto(self):
        # SYN → SYN-ACK: autotracker should fill seq/ack without errors
        pkts = self.sh.run_string("""\
wrpcap("x", Ether()/IP(src="1.0.0.1", dst="1.0.0.2")/TCP(sport=1, dport=2, flags="S"))
wrpcap("x", Ether()/IP(src="1.0.0.2", dst="1.0.0.1")/TCP(sport=2, dport=1, flags="SA"))
wrpcap("x", Ether()/IP(src="1.0.0.1", dst="1.0.0.2")/TCP(sport=1, dport=2, flags="A"))
""")
        self.assertEqual(len(pkts), 3)


class TestCallback(unittest.TestCase):
    def setUp(self):
        self.sh = pcapsh.PcapSH()

    def test_callback_fires_per_packet(self):
        seen = []
        self.sh.run_string("""\
wrpcap("x", Ether()/IP()/TCP(flags="S"))
wrpcap("x", Ether()/IP()/TCP(flags="SA"))
wrpcap("x", Ether()/IP()/TCP(flags="A"))
""", on_packet=seen.append)
        self.assertEqual(len(seen), 3)

    def test_callback_and_return_consistent(self):
        seen = []
        pkts = self.sh.run_string(
            'wrpcap("x", Ether()/IP(src="9.9.9.9")/UDP()/fromhex("cafebabe"))',
            on_packet=seen.append,
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], pkts[0])

    def test_callback_receives_bytes(self):
        seen = []
        self.sh.run_string(
            'wrpcap("x", Ether()/IP()/ICMP())',
            on_packet=seen.append,
        )
        self.assertIsInstance(seen[0], bytes)

    def test_callback_order(self):
        sizes = []
        self.sh.run_string("""\
wrpcap("x", Ether()/IP()/TCP()/fromhex("01"))
wrpcap("x", Ether()/IP()/TCP()/fromhex("0102"))
wrpcap("x", Ether()/IP()/TCP()/fromhex("010203"))
""", on_packet=lambda p: sizes.append(len(p)))
        # each subsequent packet has 1 more byte of payload
        self.assertEqual(sizes[1] - sizes[0], 1)
        self.assertEqual(sizes[2] - sizes[1], 1)

    def test_no_callback_still_works(self):
        pkts = self.sh.run_string('wrpcap("x", Ether()/IP()/UDP())')
        self.assertEqual(len(pkts), 1)


class TestTlsBuilders(unittest.TestCase):
    def test_client_hello(self):
        rec = pcapsh.tls_client_hello()
        self.assertIsInstance(rec, bytes)
        self.assertGreater(len(rec), 10)
        self.assertEqual(rec[0], 0x16)  # TLS Handshake

    def test_client_hello_sni(self):
        rec = pcapsh.tls_client_hello("example.com")
        self.assertIn(b"example.com", rec)

    def test_server_hello(self):
        rec = pcapsh.tls_server_hello()
        self.assertEqual(rec[0], 0x16)

    def test_certificate_cn(self):
        rec = pcapsh.tls_certificate_cn("test.local")
        self.assertEqual(rec[0], 0x16)
        self.assertGreater(len(rec), 50)

    def test_certificate_der(self):
        # Minimal valid DER: SEQUENCE { } — just checks we don't crash
        fake_der = bytes.fromhex("3000")
        rec = pcapsh.tls_certificate(fake_der)
        self.assertEqual(rec[0], 0x16)

    def test_change_cipher_spec(self):
        rec = pcapsh.tls_change_cipher_spec()
        self.assertEqual(rec[0], 0x14)  # TLS ChangeCipherSpec

    def test_finished(self):
        rec = pcapsh.tls_finished()
        self.assertEqual(rec[0], 0x16)

    def test_application_data(self):
        payload = b"GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"
        rec = pcapsh.tls_application_data(payload)
        self.assertEqual(rec[0], 0x17)  # TLS ApplicationData
        self.assertIn(payload, rec)


class TestLoadProtos(unittest.TestCase):
    def test_load_posa_nonexistent(self):
        sh = pcapsh.PcapSH()
        n = sh.load_posa("/nonexistent/path.posa")
        self.assertEqual(n, 0)

    def test_load_protos_nonexistent(self):
        sh = pcapsh.PcapSH()
        n = sh.load_protos("/nonexistent/dir/")
        self.assertEqual(n, 0)


class TestLanCorp(unittest.TestCase):
    """AD LAN simulation run entirely from an embedded buffer."""

    @classmethod
    def setUpClass(cls):
        sh = pcapsh.PcapSH()
        seen = []
        cls.pkts = sh.run_string(LAN_CORP, on_packet=seen.append)
        cls.seen = seen

    def test_packet_count(self):
        self.assertEqual(len(self.pkts), 286)

    def test_callback_count(self):
        self.assertEqual(len(self.seen), 286)

    def test_callback_consistent(self):
        for i, (cb_pkt, ret_pkt) in enumerate(zip(self.seen, self.pkts)):
            self.assertEqual(cb_pkt, ret_pkt, f"packet {i} mismatch")

    def test_all_ethernet(self):
        for i, frame in enumerate(self.pkts):
            ethertype = struct.unpack_from(">H", frame, 12)[0]
            self.assertIn(ethertype, (0x0800, 0x0806),
                          f"packet {i}: unexpected EtherType 0x{ethertype:04x}")

    def test_all_bytes(self):
        for frame in self.pkts:
            self.assertIsInstance(frame, bytes)
            self.assertGreater(len(frame), 0)


class TestLdapDirSync(unittest.TestCase):
    """LDAP DirSync over LDAPS — embedded buffer, 18 packets."""

    @classmethod
    def setUpClass(cls):
        sh = pcapsh.PcapSH()
        cls.pkts = sh.run_string(LDAP_DIRSYNC)

    def test_packet_count(self):
        self.assertEqual(len(self.pkts), 18)

    def test_all_bytes(self):
        for frame in self.pkts:
            self.assertIsInstance(frame, bytes)
            self.assertGreater(len(frame), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
