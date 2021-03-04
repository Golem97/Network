# Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to.

from scapy.all import * 

def print_pkt(pkt):
	pkt.show()
	
print("*** Start sniffing ***")
pkt = sniff(iface=["br-8006ea08384e", "enp0s3"], filter="tcp and not ip host 10.0.2.7", prn=print_pkt)

# pkt = sniff(iface=["br-8006ea08384e", "enp0s3"], filter="tcp and ip host 10.0.2.8", prn=print_pkt)
# host means choosing randomly one of the subnets
print("*** Stop sniffing*** ")

