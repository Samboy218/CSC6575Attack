from scapy.all import *

def pkt_callback(packet):
    if (TCP in packet):
        packet.show()

interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
