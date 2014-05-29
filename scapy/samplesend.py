# -*- coding: utf-8 -*-

from scapy.layers import inet6
from scapy.layers.inet6 import ICMPv6MLReport_MLDv2, IPv6
from scapy.packet import Packet
import data 
#import threading

"""
def _createPacket(self, src, dst, srcip, dstip):
     create send packet
    sendpkt = packet.Packet()
    sendpkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
    sendpkt.add_protocol(vlan.vlan(pcp=0, cfi=0, vid=100, ethertype=ether.ETH_TYPE_IPV6))
    sendpkt.add_protocol(ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
    sendpkt.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address='ff38::1')))
    sendpkt = IPv6(dst="ff38::1")/ICMPv6MLReport_MLDv2(sendpkt)
#        sendpkt.serialize()
    return sendpkt
"""
if __name__ == '__main__':
    src = "11:22:33:44:55:66"
    dst = "66:55:44:33:22:11"
    srcip = "11::"
    dstip= "::11"

#    ICMPv6MLReport_MLDv2()
#    sendpkt = Packet()
#    sendpkt = IPv6(dst="ff38::1")/ICMPv6MLReport_MLDv2(sendpkt)
    
    i=IPv6()
    i.dst="2001:db8:dead::1"
    h=ICMPv6MLReport_MLDv2()
    h.addresses=["2001:db8:dead::1","2001:db8:dead::1","2001:db8:dead::1"]
    sendpkt=(i/h)

#    sendpkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
#    sendpkt.add_protocol(vlan.vlan(pcp=0, cfi=0, vid=100, ethertype=ether.ETH_TYPE_IPV6))
#    sendpkt.add_protocol(ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
#    sendpkt.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
#                            data=icmpv6.mldv2_query(address='ff38::1')))
    """
    sendpkt.add_protocol(ethernet.ethernet(ethertype=data.ETH_P_IPV6, dst=dst, src=src))
    sendpkt.add_protocol(ipv6.ipv6(src=srcip, dst=dstip, nxt=data.IPPROTO_ICMPV6))
    sendpkt.add_protocol(icmpv6.icmpv6(type_= inet6.ICMPv6MLQuery,
                            data=icmpv6.mldv2_query(address='ff38::1')))
    """
    
    print ('sendpkt %s', sendpkt)
    #a=IPv6(dst="66:55:44:33:22:11", src="11:22:33:44:55:66")
    """
    sendpkt = packet.Packet()
    sendpkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
    sendpkt.add_protocol(vlan.vlan(pcp=0, cfi=0, vid=100, ethertype=ether.ETH_TYPE_IPV6))
    sendpkt.add_protocol(ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
    sendpkt.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                            data=icmpv6.mldv2_query(address='ff38::1')))
    """
    #/inet6.ICMPv6MLReport_MLDv2()
    #print ('test %s', a)
    #send(a)
    
    
    src = "11:22:33:44:55:66"
    dst = "66:55:44:33:22:11"
    srcip = "11::"
    dstip= "::11"
    
#    e = ethernet.ethernet(ethertype='0x8100', dst=dst, src=src)
#    v = vlan.vlan(pcp=0, cfi=0, vid=100, ethertype='0x86dd')
#    u = ipv6.ipv6(src=srcip, dst=dstip, nxt='58')
#    c = icmpv6.icmpv6(type_='130',data=icmpv6.mldv2_query(address='ff38::1'))
    
#    e = (ethertype='0x8100', dst=dst, src=src)
#    v = (pcp=0, cfi=0, vid=100, ethertype='0x86dd'()
#    u = (src=srcip, dst=dstip, nxt='58')
#    p = (type_='130',data=icmpv6.mldv2_query(address='ff38::1')

#    sendpkt = e/u/p
#    sendpkt.add_protocol(icmpv6.icmpv6(type_='130',
#                            data=icmpv6.mldv2_query(address='ff38::1')))
#    sendpkt = main.createPacket(src, dst, srcip, dstip)
#    sendpkt = inet6.IPv6(dst="ff38::1", sendpkt)/inet6.ICMPv6ND_Redirect(sendpkt)
    
    print ('test %s', sendpkt)
#    sendrecv()
#    inet6.send(sendpkt)

