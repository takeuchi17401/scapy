# samplesend.py
from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers import inet6
import data



if __name__ == '__main__':
####### ICMPv6MLQuery Send ########
    """
    src = "11:22:33:44:55:66"
    dst = "66:55:44:33:22:11"
    srcip = "11::"
    dstip= "::11"

    conf.iface = "eth0"
    myMacAddr = "00:00:00:00:00:02"

    e = Ether()
    e.src = src
    e.dst = dst
    d = Dot1Q()
    d.prio = 0
    d.id = 0
    d.vlan = 100
    i = IPv6()
    i.src = srcip
    i.dst = dstip
    i.nh = data.IPPROTO_ICMPV6
    c = ICMPv6MLQuery()
    c.mladdr='ff38::1'

    sendpkt = e / d / i / c
    """
####### ICMPv6MLQuery Send ########

####### ICMPv6MLReport_MLDv2 Send ########
    src = "11:22:33:44:55:66"
    dst = "66:55:44:33:22:11"
    srcip = "11::"
    dstip = "::11"

    e = Ether()
    e.src = src
    e.dst = dst
    h = IPv6ExtHdrHopByHop(options = RouterAlert())
    i = IPv6()
    i.src = srcip
    i.dst = dstip
    i.nh = data.IPPROTO_ICMPV6
#    c = ICMPv6MLReport_MLDv2()
    c = ICMPv6MLReport_MLDv2()
    c.mladdr = 'ff38::1'
    
    #sendpkt=e/i/c
    sendpkt = e / h / i / c
####### ICMPv6MLReport_MLDv2 Send ########

    print ("sendpkt %s", sendpkt)
    sendp(sendpkt)

"""
class ICMPv6MLReport_MLDv2(ICMPv6MLReport):  # RFC 3810

    name = "MLD - Multicast Listener Report v2"
    type = 143
    overload_fields = {IPv6: {"hlim": 1}}

    def __init__(self):
        pass
"""