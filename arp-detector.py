
#!usr/bin/env python

import scapy.all as scapy

def get_mac(ip):
    
    arp_packets = scapy.ARP(pdst=ip)
    broadcast  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    arp_broadcast_packets = broadcast/arp_packets

    answered_list = scapy.srp(arp_broadcast_packets, timeout=1,verbose =False)[0]
    return answered_list[0][1].hwsrc

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn= packet_sniffer)

def packet_sniffer(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac: 
               print("[+] you are under attack")
        except IndexError:
             pass
interface = input("enter your interface > ")


sniffer(interface)
