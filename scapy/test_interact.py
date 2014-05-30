#! /usr/bin/env python

# Set log level to benefit from Scapy warnings

import sys
import logging
from scapy.all import *
from scapy.layers.inet6 import *

logging.getLogger("scapy").setLevel(1)

from scapy.all import *

class Test(Packet):
    name = "Test packet"
    fields_desc = [ ShortField("test1", 1),
                    ShortField("test2", 2) ]

class TestICMPv6MLQuery_MLDv2(Packet):
    name = "TestICMPv6MLQuery_MLDv2 packet"
    fields_desc = [ ShortField("test1", 1),
                    ShortField("test2", 2) ]

def make_test(x,y):
    return Ether()/IPv6()/Test(test1=x,test2=y)

def make_test_ICMPv6MLQuery_MLDv2(x,y):
    e = Ether()
    e.src = "11:22:33:44:55:66"
    e.dst = "66:55:44:33:22:11"
    i = IPv6()
    c = TestICMPv6MLQuery_MLDv2(test1=x,test2=y)
    
    return e/i/c

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on v3.14")