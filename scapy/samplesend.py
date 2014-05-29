# -*- coding: utf-8 -*-
from scapy import sendrecv
from scapy.layers import inet6
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6 #,ICMPv6MLReport_MLDv2 
from scapy.packet import Packet
import data 
#import threading

if __name__ == '__main__':
    src = "fe80::200:ff:fe00:1"
    dst = "fe80::200:ff:fe00:2"
    srcip = "11::"
    dstip= "::11"
#    fe80::d63d:7eff:fe4a:460c #self
#    fe80::200:ff:fe00:1 #mininet h1
#    fe80::200:ff:fe00:2 #mininet h2
#    ICMPv6MLReport_MLDv2()
#    sendpkt = Packet()
#    sendpkt = IPv6(dst="ff38::1")/ICMPv6MLReport_MLDv2(sendpkt)
    e=Ether()
    e.dst=dst
    e.src=src
#    e.type='0x8100'
    i=IPv6()
    i.src=src
    i.dst=dst
#    h=ICMPv6MLReport_MLDv2()
#    h.addresses=[srcip,dstip]
    """
    fields_desc = [ ByteEnumField("type", 130, icmp6types),
                    ByteField("code", 0),
                    XShortField("cksum", None),
                    ShortField("mrd", 0),
                    ShortField("reserved", 0),
                    IP6Field("mladdr",None)]
    """
    sendpkt=e/i
    #sendpkt=e/i/h
#    sendpkt=(i/h)
#    e = ethernet.ethernet(ethertype='0x8100', dst=dst, src=src)
#    v = vlan.vlan(pcp=0, cfi=0, vid=100, ethertype='0x86dd')
#    u = ipv6.ipv6(src=srcip, dst=dstip, nxt='58')
#    c = icmpv6.icmpv6(type_='130',data=icmpv6.mldv2_query(address='ff38::1'))
    
#    e = (ethertype='0x8100', dst=dst, src=src)
#    v = (pcp=0, cfi=0, vid=100, ethertype='0x86dd'()
#    u = (src=srcip, dst=dstip, nxt='58')
#    p = (type_='130',data=icmpv6.mldv2_query(address='ff38::1')
#    sendpkt = e/u/p

    print ('sendpkt %s', sendpkt)
    inet6.send(sendpkt)
    #inet6.sndrcv(sendpkt)
    #sendrecv(sendpkt)
#    inet6.send(sendpkt)

