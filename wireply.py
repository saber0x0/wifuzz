#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/11/15 0:49


import sys
import os
import getopt

from scapy.arch import get_if_raw_hwaddr
from scapy.config import *
from scapy.data import ARPHDR_ETHER, ARPHDR_LOOPBACK
from scapy.layers.dot11 import *
from scapy.utils import *

conf.verb = 0

DEFAULT_CHECK = 100
DEFAULT_IFACE = "wlan0"


def waitForBeacon(ssid):
    print("[*] Waiting for Beacon from SSID=[%s]" % ssid)

    beacon = False
    mac = None

    while not beacon:
        p = sniff(count=1)[0]

        # Check if beacon comes from the AP we want to connect to
        if p.haslayer(Dot11Elt) and p.getlayer(Dot11Elt).info == ssid:
            beacon = True
            mac = p.addr3
            print("[*] Beacon from SSID=[%s] found (MAC=[%s])" % (ssid, mac))

    return mac


def replypackets(pcapfile, sourcemac, ssid, start=0, check=100, outfile=None):
    print("[*] Reading packets...")
    pkts = rdpcap(pcapfile)
    print("[*] Read %d packets!" % len(pkts))

    print("[*] Starting reply from packet #%d, check every %d packets, source MAC %s" % (start, check, sourcemac))
    pkts = pkts[start:]

    destmac = waitForBeacon(ssid)

    print("[*] Sending packets...")

    i = 0
    for p in pkts:
        i += 1
        if p is None or not p.haslayer(Dot11):
            continue

        # Fix source & destination MAC addresses
        dot11 = p.getlayer(Dot11)
        dot11.addr2 = sourcemac
        dot11.addr1 = dot11.addr3 = destmac

        sendp(p)

        if (i % check) == 0 or i == len(pkts):
            print("[*] Sent %d packet(s) [%d-%d]. Checking if the AP is still up..." % (
            check, start + i - check, start + i))
            try:
                waitForBeacon(ssid)
            except KeyboardInterrupt:
                print("[*] Control-C detected!")
                if outfile is not None:
                    wrpcap(outfile, pkts[:i])
                    print("[*] %d packets wrote to '%s'" % (len(pkts[:i]), outfile))
                break


def showhelp():
    print("""\
-=- WiFuzz test-case replayer -=-
Syntax: python3 %s -s <ssid> [options] <pcapfile>

Available options:
-c <interval>       Every <interval> packets check if the AP is still up (default: %d)
-f <index>          Start from packet #<index> (default: 0)
-h                  Show this help screen
-i <iface>          Set network interface (default: %s)
-m <source mac>     Spoof source MAC address
-o <filename>       Write replayed packets to PCAP
-s <ssid>           Set AP SSID

Remember to put your Wi-Fi card in monitor mode. Your driver must support traffic injection.
""" % (sys.argv[0], DEFAULT_CHECK, DEFAULT_IFACE))


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:f:hi:m:o:s:")
    except getopt.GetoptError as e:
        print(str(e))
        showhelp()
        exit(1)

    opts = dict([(k.lstrip('-'), v) for (k, v) in opts])

    if 'h' in opts or len(args) != 1 or 's' not in opts:
        showhelp()
        exit(0)

    conf.iface = opts.get('i', DEFAULT_IFACE)
    ssid = opts.get('s')
    sourcemac = opts.get('m', None)
    start = int(opts.get('f', 0))
    check = int(opts.get('c', DEFAULT_CHECK))
    outf = opts.get('o', None)
    pcapfile = args[0]

    if sourcemac is None:
        # Get local MAC address
        sourcemac = str2mac(get_if_raw_hwaddr(conf.iface)[1])

    replypackets(pcapfile,
                 sourcemac=sourcemac, ssid=ssid,
                 start=start, check=check,
                 outfile=outf)


if __name__ == "__main__":
    main()
