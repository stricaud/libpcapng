#!/usr/bin/env python3
import sys
import pycapng

pcapng = pycapng.PcapNG()
pcapng.OpenFileLinkType(sys.argv[1], "w", pycapng.LINKTYPE_ETHERNET)
pcapng.WriteTcpPacket("00:01:02:03:04:05", "99:fa:ce:00:70:00",
                      "192.168.1.2", "192.168.32.4", 43284, 445, 123456, 123455, 2, b"")
pcapng.CloseFile()

