#! /usr/bin/env python

import scapy.all as scapy

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)

	# Ethernet frame has to be constructed for MAC
	bcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

	# appending both pcks
	arp_bcast_request = bcast/arp_request

	# To sent and recv pkt srp func is used where p stands for custom Ether pkt
	ans_list,unans_list = scapy.srp(arp_bcast_request,timeout=1,verbose=False)

	element = ans_list[0]
	return element[1].hwsrc

def sniff(interface):
	# store is false since it should not store the incoming packets
	scapy.sniff(iface=interface,store=False,prn=process_packets)


def process_packets(packet):
	# in order to filter the ARP packet scapy.ARP is installed
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try:
			real_mac = get_mac(packet[scapy.ARP].psrc)
			response_mac = packet[scapy.ARP].hwsrc

			if real_mac != response_mac:
				print('[-] You are under attack!!!')
		except IndexError:
			pass

		

sniff('eth0')