#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/11/15 0:24


import time


def log(msg, module=None):
    print("%s {%s} %s" % (time.ctime(), module, msg))


class WiException(BaseException):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "%s" % self.msg


class WiExceptionTimeout(WiException):
    pass
