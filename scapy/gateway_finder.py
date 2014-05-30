import sys
import threading
import time
from scapy.all import *
import socket
import fcntl
import struct
 
ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_TTL_EXCEEDED = 11
END_POINT_ADDR = "8.8.8.8"
conf.iface = "eth0"
conf.verb = 0
 
if len(sys.argv) != 2:
    print "Usage: gateway.py   eg: sudo python gateway-finder.py 192.168.1.0/24"
    sys.exit(1)
 
def get_ip_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
      0x8915,struct.pack('256s', ifname[:15]))[20:24])
 
iface_ip = get_ip_addr(conf.iface)
iface_hw = get_if_hwaddr(conf.iface)
 
# arp
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=3)
mac2ip = {}
for snd,rcv in ans:
  mac2ip[rcv.src] = rcv.psrc
 
# sniff & handle icmp packet
class ICMPSniffer(threading.Thread):
 
  def __init__(self, mac2ip):
    threading.Thread.__init__(self)
    self.mac2ip = mac2ip
 
  def callbak(self, pkt):
    global iface_hw
    global iface_ip
    if ICMP in pkt:
      if pkt[ICMP].type == ICMP_TYPE_TTL_EXCEEDED:
        print "ROUTER?: %s\t%s" % (pkt[IP].src, pkt.src)
        icmp = Ether(src=iface_hw,dst=pkt.src)/IP(src=iface_ip,dst=END_POINT_ADDR)/ICMP()
        sendp(icmp)
      elif pkt[ICMP].type == ICMP_TYPE_ECHO_REPLY:
        print "GATEWAY: %s\t%s" % (self.mac2ip[pkt.src], pkt.src)
 
  def run(self):
    sniff(prn=self.callbak, filter="icmp", store=0)
 
icmpsniff = ICMPSniffer(mac2ip)
icmpsniff.daemon = True
icmpsniff.start()
time.sleep(1)
 
for mac,ip in mac2ip.iteritems():
  #print "IP NODE: %s\t%s" % (ip, mac)
  icmp = Ether(src=iface_hw,dst=mac)/IP(src=iface_ip,dst=END_POINT_ADDR,ttl=1)/ICMP()
  sendp(icmp)