#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/11/15 0:37
import inspect
import random
import tempfile
import time

from scapy.layers.dot11 import *
from scapy.sendrecv import srp1
from scapy.utils import wrpcap

import wifuzzer
from common import log, WiExceptionTimeout

# This fake MAC address is used as the AP MAC when "test mode" is enabled
FAKE_AP_MAC = "aa:bb:cc:dd:ee:ff"

# recv() timeout, in seconds
RECV_TIMEOUT = 20


def skip_testmode(callee):
    """Decorator to skip invokation of some members when testmode is enabled."""

    def f(*args, **kwargs):
        obj = args[0]
        if obj.testmode:
            obj.log("Testmode skips call to '%s'" % callee.__name__)
            r = None
        else:
            r = callee(*args, **kwargs)
        return r

    return f


class WifiDriver:
    def __init__(self, ssid, tping, outdir, apmac=None, localmac=None, verbose=0, testmode=False):
        self.ssid = ssid  # Target SSID
        self.tping = tping  # Ping timeout
        self.outdir = outdir  # Destination directory for PCAP files
        self.apmac = apmac  # MAC address of the Access Point
        self.localmac = localmac  # MAC address of the local Wi-Fi station
        self.sn = random.randint(0, 4096)  # Current 802.11 sequence number
        self.verbose = verbose  # Verbosity level
        self.tc = []  # Test-case packets
        self.testmode = testmode

    def finalizePacket(self, p):
        """Finalize a packet (in place), before sending it on the wire."""
        m = p.getlayer(Dot11)

        # Set the frame control field
        m.FCfield = (m.FCfield & 0xcfff) | 0x0020  # Set to_DS=1 for To DS frames

        m.SC = (self.sn << 4) | (m.SC & 0x0f00)  # Sequence number
        m.addr1 = self.apmac  # Receiver
        m.addr2 = self.localmac  # Sender
        m.addr3 = self.apmac  # BSSID

        # Update the sequence number for next packets
        self.sn = (self.sn + 1) % 4096

    def log(self, msg):
        """Log a debug message."""
        log(msg, module="WIFI")

    def send(self, p, recv=False):
        """Send out a packet and optionally read back a reply."""
        try:
            self.finalizePacket(p)
            self.tc.append(p)

            if self.testmode:
                print(repr(p))
                # time.sleep(1)
                r = None
            elif not recv:
                sendp(p)
                r = None
            else:
                r = srp1(p, timeout=RECV_TIMEOUT)
                if r is None:
                    raise WiExceptionTimeout("recv() timeout exceeded!")
        except IndexError as e:
            self.log(f"Error sending packet: {e}")
            r = None
        return r

    @skip_testmode
    def probe(self):
        # 1. Probe request
        p = RadioTap() / Dot11() / Dot11ProbeReq() / Dot11Elt(ID='SSID', info=self.ssid) / Dot11Elt(ID='Rates',
                                                                                                    info="\x82\x84\x0b\x16")
        r = self.send(p, recv=True)

    @skip_testmode
    def authenticate(self):
        # FIXME: Commented out because some APs sometimes do not respond to
        # probe requests

        # First we need to send out a probe request...
        # self.probe()

        # 2. Authentication request (open system)
        p = RadioTap() / Dot11() / Dot11Auth(algo="open", seqnum=1)
        r = self.send(p, recv=True)
        assert r.haslayer(Dot11Auth) and r.getlayer(Dot11Auth).status == 0

    @skip_testmode
    def associate(self):
        # First we need to authenticate ourselves...
        self.authenticate()

        # 3. Association request
        p = RadioTap() / Dot11() / Dot11AssoReq(cap="short-slot+ESS+privacy+short-preamble", listen_interval=5) / \
            Dot11Elt(ID='SSID', info=self.ssid) / Dot11Elt(ID='Rates', info="\x82\x84\x0b\x16")
        r = self.send(p, recv=True)
        assert r.haslayer(Dot11AssoResp) and r.getlayer(Dot11AssoResp).status == 0

    def waitForBeacon(self):
        """Waits for a 802.11 beacon from an AP with our SSID."""
        global RECV_TIMEOUT

        if self.testmode:
            return FAKE_AP_MAC

        self.log("Waiting for a beacon from SSID=[%s]" % self.ssid)

        beacon = False
        mac = None
        starttime = time.time()

        while not beacon:
            """
            p = sniff(count=1, timeout=RECV_TIMEOUT)[0]
            if p is None or len(p) == 0 or (time.time() - starttime) > self.tping:
                # Timeout!
                raise WiExceptionTimeout("waitForBeacon() timeout exceeded!")
            # self.log("Received packet: %s" % repr(p))
            # Check if beacon comes from the AP we want to connect to
            if p.haslayer(Dot11Elt) and p.getlayer(Dot11Elt).info == self.ssid:
                beacon = True
                mac = p.addr3
                self.log("Beacon from SSID=[%s] found (MAC=[%s])" % (self.ssid, mac))
            pkts = sniff(count=1, timeout=RECV_TIMEOUT)
            """
            pkts = sniff(count=1, timeout=RECV_TIMEOUT)
            if not pkts:
                if (time.time() - starttime) > self.tping:
                    # Timeout!
                    raise WiExceptionTimeout("waitForBeacon() timeout exceeded!")
                continue
            for p in pkts:
                # 打印接收到的数据包
                # self.log("Received packet: %s\n" % repr(p))
                if p.haslayer(Dot11) and p.getlayer(Dot11).type == 0 and p.getlayer(Dot11).subtype == 8:  # Beacon frame
                    ssid_found = False
                    beacon_elements = p.getlayer(Dot11Beacon)
                    elements = Dot11Elt(p[Dot11Beacon].info)
                    for elem in elements:
                        if elem.ID == 'SSID' and elem.info.decode() == self.ssid:
                            ssid_found = True
                            break
                    if ssid_found:
                        beacon = True
                        mac = p.addr3
                        self.log("Beacon from SSID=[%s] found (MAC=[%s])" % (self.ssid, mac))
                        break
        return mac

    def testcaseStart(self):
        del self.tc[:]

    def testcaseStop(self):
        return self.tc

    def fuzz(self, check_interval=100, fuzztype="any"):
        self.log("Starting fuzz '%s'" % fuzztype)

        fuzztypes = {}
        for m in dir(wifuzzer):
            o = getattr(wifuzzer, m)
            if not inspect.isclass(o) or o == wifuzzer.WifiFuzzer or not issubclass(o, wifuzzer.WifiFuzzer):
                continue
            fuzztypes[o.getName()] = o

        fuzzset = []
        for f in set(fuzztype.split(",")):
            assert f in fuzztypes, "[!] Unknown fuzz type '%s'" % f
            fuzzer = fuzztypes[f](self)
            fuzzset.append(fuzzer)

        assert len(fuzzset) > 0

        alldone = False
        roundz = 0
        npkts = 0
        while not alldone:
            roundz += 1
            # Send out check_interval packets
            self.log("[R%.5d] Sending packets %d-%d" % (roundz, npkts + 1, npkts + check_interval))

            # Start this test-case
            self.testcaseStart()

            for i in range(check_interval):
                npkts += 1

                # Choose a random element within the set of active fuzzers
                fuzzer = random.choice(fuzzset)

                try:
                    fuzzer.fuzz()
                except WiExceptionTimeout as e:
                    self.log("[R%.5d] %s (packet #%d)" % (roundz, e.msg, npkts))
                    break

            # Stop this test-case
            tc = self.testcaseStop()

            # Check the AP is still up
            self.log("[R%.5d] Checking if the AP is still up..." % roundz)
            try:
                # mac = self.waitForBeacon()
                #TODO:add mac address 传参
                mac = "14:9F:4F:85:91:31"
            except WiExceptionTimeout as e:
                mac = None
            except Exception as e:
                print(e)
                mac = None

            if mac is None:
                #  Timeout! Write sent packets into a pcap file & exit
                f = tempfile.NamedTemporaryFile(dir=self.outdir, prefix="wifuzz-", suffix=".pcap", delete=False)
                pcapname = f.name
                f.close()
                wrpcap(pcapname, tc)
                self.log("[!] The AP does not respond anymore. Latest test-case has been written to '%s'" % pcapname)
                exit(0)

    @skip_testmode
    def waitForPacket(self, condition):
        r = None
        while True:
            p = sniff(count=1, timeout=20)[0]
            if p is None or len(p) == 0:
                break

            if condition(p):
                r = p
                break
        return r
