#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/11/14 23:56

import warnings

from scapy.arch import get_if_raw_hwaddr
from scapy.data import ARPHDR_ETHER, ARPHDR_LOOPBACK

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
import getopt
from scapy.utils import *

from common import log, WiExceptionTimeout
from widriver import WifiDriver
import wifuzzer
import inspect

conf.verb = 0


DEFAULT_IFACE = "wlan0"
DEFAULT_PCAP_DIR = "/dev/shm"
DEFAULT_PING_TIMOUT = "60"

"""
def str2mac(mac):
    return ':'.join(mac.encode('utf-8').hex()[i:i+2] for i in range(0, 11, 2)).upper()

def get_if_hwaddr(iff):
    addrfamily, mac = get_if_raw_hwaddr(iff)  # noqa: F405
    if addrfamily in [ARPHDR_ETHER, ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Scapy_Exception("Unsupported address family (%i) for interface [%s]" % (addrfamily, iff))  # noqa: E501
"""


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:p:s:t")
    except getopt.GetoptError as e:
        print(str(e))
        showhelp()
        exit(1)

    opts = dict([(k.lstrip('-'), v) for (k, v) in opts])

    if 'h' in opts or 's' not in opts or len(args) != 1:
        showhelp()
        exit(0)

    fuzztype = args[0]
    conf.iface = opts.get('i', DEFAULT_IFACE)
    conf.tping = opts.get('p', DEFAULT_PING_TIMOUT)

    if not conf.tping.isdigit():
        log("[!] Ping timeout (-p) must be a valid integer", "MAIN")
        exit(2)

    conf.tping = int(conf.tping)
    if conf.tping <= 0:
        log("[!] Ping timeout (-p) must be greater than zero", "MAIN")
        exit(2)

    conf.outdir = opts.get('o', DEFAULT_PCAP_DIR)
    ssid = opts.get('s')
    localmac = str2mac(get_if_raw_hwaddr(conf.iface)[1])
    testmode = 't' in opts

    log("Target SSID: %s; Interface: %s; Ping timeout: %d; PCAP directory: %s; Test mode? %s; Fuzzer(s): %s;" % \
        (ssid, conf.iface, conf.tping, conf.outdir, testmode, fuzztype), "MAIN")

    wifi = WifiDriver(ssid=ssid, tping=conf.tping, outdir=conf.outdir,
                      localmac=localmac, testmode=testmode, verbose=1)

    # Get the MAC address of the AP
    #try:
        # mac = wifi.waitForBeacon()
    # except WiExceptionTimeout as e:
        # log("No beacon from target AP after %d seconds" % conf.tping, "MAIN")
        # sys.exit(1)
    # TODO: add mac address 传参
    # wifi.apmac = mac
    wifi.apmac = "14:9F:4F:85:91:31"
    # Fuzz!
    wifi.fuzz(fuzztype=fuzztype)


def showhelp():

    print(
        """\
-=- WiFuzz: Access Point 802.11 STACK FUZZER -=-
Syntax: python3 %s -s <ssid> [options] <fuzzer>(,<fuzzer>)*

Available options:
-h       Show this help screen
-i       Network interface (default: %s)
-o       Output directory for PCAP files (default: %s)
-p       Ping timeout (default: %d seconds)
-s       Set target AP SSID
-t       Enable test mode

Remember to put your Wi-Fi card in monitor mode. Your driver must support traffic injection.
""" % (sys.argv[0], DEFAULT_IFACE, DEFAULT_PCAP_DIR, int(DEFAULT_PING_TIMOUT)))

    l = []
    for m in dir(wifuzzer):
        o = getattr(wifuzzer, m)
        if not inspect.isclass(o) or o == wifuzzer.WifiFuzzer or not issubclass(o, wifuzzer.WifiFuzzer):
            continue
        l.append((o.getName(), o.state, o.__doc__.strip(".")))
    l.sort()
    m = max([len(x[2]) for x in l])
    s = "| %s | %s | %s |" % ("Name".center(10), "State".center(20), "Description".center(m))
    print("Available fuzzers:")
    print("-" * len(s))
    print(s)
    print("-" * len(s))
    for name, state, desc in l:
        print("| %s | %s | %s |" % (name.center(10), wifuzzer.state_to_name(state).center(20), desc.ljust(m)))
    print("-" * len(s))
    print()



if __name__ == "__main__":
    main()
