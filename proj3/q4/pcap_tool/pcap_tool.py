#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl

def handle_packet(pkt):
    print pkt.show

    # If you wanted to send a packet back out, it might look something like... 
    # ip = IP(...)
    # tcp = TCP(...) 
    # app = ...
    # msg = ip / tcp / app 
    # send(msg) 
    

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')

