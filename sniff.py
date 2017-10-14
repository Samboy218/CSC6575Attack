from scapy.all import *

def pkt_callback(packet):
    packet.show()

interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="ip proto tcp", store=0)
