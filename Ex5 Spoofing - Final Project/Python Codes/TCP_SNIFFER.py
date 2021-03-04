# Capture only the ICMP packet

from scapy.all import *

def print_pkt(pkt):
	pkt.show()
	
pkt = sniff(iface=["br-8006ea08384e", "enp0s3"], filter="tcp", prn=print_pkt)

