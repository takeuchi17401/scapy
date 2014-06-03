from scapy.all import *
from ryu.lib.packet import *
from ryu.ofproto import ether, inet
 
src = "11:22:33:44:55:66"
dst = "66:55:44:33:22:11"
srcip = "11::"
dstip= "::11"


## ICMPV6_ECHO_REQUEST = 128 ##
eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
ip6 = ipv6.ipv6(dst=dstip, src=srcip, nxt=inet.IPPROTO_ICMPV6)
mld = icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REQUEST, data=icmpv6.mldv2_report())
ryu_pkt = eth / ip6 / mld

"""
## ICMPV6_ECHO_REPLY = 129 ##
eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
ip6 = ipv6.ipv6(dst=dstip, src=srcip, nxt=inet.IPPROTO_ICMPV6)
mld = icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REPLY, csum=0, data=icmpv6.mldv2_query())
ryu_pkt = eth / ip6 / mld
"""

"""
## ICMPV6_MEMBERSHIP_QUERY = 130 ##
eth = ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q)
vln = vlan.vlan(ethertype=ether.ETH_TYPE_IPV6)
ip6 = ipv6.ipv6(dst="::1", src="::1", nxt=58)
mld = icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=icmpv6.mldv2_query())
ryu_pkt = eth /vln /ip6 /mld
"""

ryu_pkt.serialize()

print "*** Ryu Packet ***"
print type(ryu_pkt)
print ryu_pkt
print type(ryu_pkt.data)
print

sendpkt = Packet(ryu_pkt.data)
print "### scapy Packet ###"
print type(sendpkt)
sendpkt.show()
print

sendp(sendpkt)

