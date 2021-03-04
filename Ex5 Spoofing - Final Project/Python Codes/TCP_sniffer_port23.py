# Capture any TCP packet that comes from a particular IP and with a destination port number 23.

from scapy.all import * 

def print_pkt(pkt):
	pkt.show()
	
print("*** Start sniffing ***")
pkt = sniff(iface=["br-8006ea08384e", "enp0s3"], filter="tcp and src 10.0.2.8 and port 23", prn=print_pkt)
print("*** Stop sniffing*** ")
