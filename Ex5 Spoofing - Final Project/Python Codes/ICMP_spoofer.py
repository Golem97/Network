# ICMP Spoofer
from scapy.all import *

# Creates an IP object from the IP class
a = IP()

a.src = "192.168.1.10" # sets src address
a.dst = "10.0.2.8" # sets dst address
a.ttl = 255 # sets TTL

# Creates an ICMP object from the ICMP class
b = ICMP()

# The / operator is overloaded by the IP class, so it no longer represents division;instead, it means adding b as the payload field of a and modifying the fields of a accordingly. As a result, we get a new object that represent an ICMP packet
p = a/b

send(p)
ls(a) 
