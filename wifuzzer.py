#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/11/15 0:23
import random

# process 802.11
from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL, EAP
# layer 2
from scapy.layers.l2 import *
from scapy.packet import fuzz, Raw

# log
from common import log

# WiFi设备的四个状态：未连接、已探测、已认证、已关联
WIFI_STATE_NONE = 0
WIFI_STATE_PROBED = 1
WIFI_STATE_AUTHENTICATED = 2
WIFI_STATE_ASSOCIATED = 3


def state_to_name(s):
    if s == WIFI_STATE_NONE:
        n = "none"
    elif s == WIFI_STATE_PROBED:
        n = "probed"
    elif s == WIFI_STATE_AUTHENTICATED:
        n = "authenticated"
    elif s == WIFI_STATE_ASSOCIATED:
        n = "associated"
    return n


# fuzz 基类
class WifiFuzzer:
    state = WIFI_STATE_NONE

    """The WifiFuzzer class is the parent of all the fuzzers."""

    def __init__(self, driver):
        # 网卡
        self.driver = driver

    # check
    def _preconditions(self):
        """This method is invoked by the fuzzer driver before sending out the
        fuzzed packets, but after the target 802.11 state has been
        reached. Concrete fuzzer instances should use this function to enforce
        additional checks before allowing packets to go out (e.g., wait for
        packets from the AP)."""
        return

    # 生成发送的包
    def genPackets(self):
        pass

    # debug message
    def log(self, msg):
        """Log a debug message."""
        log(msg, module="FUZZ")

    # 提供一个实现了的fuzzer名称
    @staticmethod
    def getName():
        pass

    def fuzz(self):
        # Move into the target 802.11 state...
        if self.state == WIFI_STATE_PROBED:
            self.driver.probe()
        elif self.state == WIFI_STATE_AUTHENTICATED:
            self.driver.authenticate()
        elif self.state == WIFI_STATE_ASSOCIATED:
            self.driver.associate()

        # ...check for preconditions...
        self._preconditions()

        # ...and fuzz!
        for p in self.genPackets():
            self.driver.send(p)


class WifiFuzzerAny(WifiFuzzer):
    """Random 802.11 frame fuzzer."""

    def genPackets(self):
        return [RadioTap() / fuzz(Dot11()), ]

    @staticmethod
    def getName():
        return "any"


# Beacon fuzz
class WifiFuzzerBeacon(WifiFuzzer):
    """Beacon request fuzzer."""

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11Beacon()), ]

    @staticmethod
    def getName():
        return "beacon"


# Association fuzz
class WifiFuzzerAssoc(WifiFuzzer):
    """Association request fuzzer."""
    state = WIFI_STATE_AUTHENTICATED

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11AssoReq()), ]

    @staticmethod
    def getName():
        return "assoc"


# Deauthentication fuzz
class WifiFuzzerDessoc(WifiFuzzer):
    """Deassociation request fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11Disas()), ]

    @staticmethod
    def getName():
        return "deassoc"


# Auth fuzz
class WifiFuzzerAuth(WifiFuzzer):
    """Authentication request fuzzer."""
    state = WIFI_STATE_PROBED

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11Auth()), ]

    @staticmethod
    def getName():
        return "auth"


# Deauth fuzz
class WifiFuzzerDeauth(WifiFuzzer):
    """Deauthentication request fuzzer."""
    state = WIFI_STATE_AUTHENTICATED

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11Deauth()), ]

    @staticmethod
    def getName():
        return "deauth"


# Probe fuzz
class WifiFuzzerProbe(WifiFuzzer):
    """Probe request fuzzer."""

    def genPackets(self):
        return [RadioTap() / Dot11() / fuzz(Dot11ProbeReq()) / Dot11Elt(ID='SSID', info=self.driver.ssid) / fuzz(
            Dot11Elt(ID='Rates')), ]

    @staticmethod
    def getName():
        return "probe"


# EAP fuzz
class WifiFuzzerEAP(WifiFuzzer):
    """EAP protocol fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        p = RadioTap() / Dot11(FCfield="to-DS") / LLC() / SNAP() / fuzz(EAP())
        return [p, ]

    @staticmethod
    def getName():
        return "eap"


# EAPOL fuzz
class WifiFuzzerEAPOL(WifiFuzzer):
    """EAPOL (EAP-over-LAN) protocol fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        # EAPOL version
        version = random.choice([1, 2])  # Use valid EAPOL version

        # EAPOL packet type
        typez = random.choice(["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"])  # Use valid EAPOL packet type

        # Make a random body, leave it empty with 0.5 probability. At this
        # layer we have only 1470 bytes left for the body
        bodylen = random.randint(0, 1470) if random.randint(1, 2) == 1 else 0

        body = "".join([chr(random.randint(0, 255)) for i in range(bodylen)])

        # EAPOL packet type
        typez = random.choice(["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"])
        # 将 EAPOL 类型字符串映射到对应的整数值
        eapol_types = {
            "EAP_PACKET": 0,
            "START": 1,
            "LOGOFF": 2,
            "KEY": 3,
            "ASF": 4
        }
        typez = eapol_types[typez]

        p = RadioTap() / Dot11(FCfield="to-DS") / LLC() / SNAP() / EAPOL(version=version, type=typez, len=bodylen)
        if bodylen > 0:
            p /= Raw(load=body)

        return [p, ]

    @staticmethod
    def getName():
        return "eapol"
