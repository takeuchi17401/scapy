# samplesend.py
from scapy import *
from scapy.all import *
from scapy.config import conf
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.fields import *
from scapy.packet import *
from scapy.volatile import *
from scapy.sendrecv import sr,sr1,srp1
from scapy.as_resolvers import AS_resolver_riswhois
from scapy.supersocket import SuperSocket,L3RawSocket
from scapy.arch import *
from scapy.utils6 import *
from scapy.layers.inet6 import *
from scapy.packet import Packet
from scapy.layers import inet6
import data 

if __name__ == '__main__':
    src = "fe80::200:ff:fe00:1"
    dst = "ff02::1:ff00:2"
    srcip = "11::"
    dstip= "::11"
#    fe80::d63d:7eff:fe4a:460c #self
#    fe80::200:ff:fe00:1 #mininet h1
#    fe80::200:ff:fe00:2 #mininet h2
#    ff02::1:ff00:2 (ff02::1:ff00:2)
#    ICMPv6MLReport_MLDv2()

    #conf.verb = 0
    conf.iface = "eth0"
    #myMacAddr = get_if_hwaddr(conf.iface)
    myMacAddr = "fe80::d63d:7eff:fe4a:460c"
    
    e = Ether()
    e.dst = dst
    e.src = src
#    v = vlan.vlan(pcp=0, cfi=0, vid=100, ethertype='0x86dd')
    u = IPv6()
    u.src=srcip
    u.dst=dstip
    u.payload = "Hello world"
    c = ICMPv6MLQuery()
    c.mladdr='ff38::1'
    sendpkt=e/u/c
    
#    sendpkt=Ether()/IPv6()/ICMPv6MLQuery()
#    sendpkt=Ether()/IPv6()/ICMPv6MLQuery_MLDv2()
    
    print ('sendpkt %s', sendpkt)
#    send(sendpkt)
#    sendp(x=sendpkt, iface=myMacAddr)
    sendp(x=sendpkt)
