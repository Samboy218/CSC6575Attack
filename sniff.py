from scapy.all import *

def pkt_callback(packet):
    if (packet in TCP):
        packet.show()

interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
