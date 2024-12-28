#!/usr/bin/env python
import argparse
import os
from scapy.all import *

parser = argparse.ArgumentParser(prog='proto_xtract.py', description='Extract all the packets')
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
parser.add_argument('--file', '-f', type=ascii, required=True, help='Packet capture filename')
parser.add_argument('--mac', '-m', type=ascii, required=True, help='Target devices Mac address')
parser.add_argument('--protocol', '-p', type=ascii, required=True, help='Target protocol to parse')
args = parser.parse_args()

name = os.path.splitext(args.file)[0]
def snip_packets(args.file, args.protocol, args.mac):
    packets = rdpcap(args.file)
    snipped_packets = []
    protocols_supported = {
        "Ether": "Ether",
        "ARP": "ARP",
        "Dot11": "Dot11",
        "IPv4": "IP",
        "IPv6": "IPv6",
        "ICMP": "ICMP",
        "TCP": "TCP",
        "UDP": "UDP",
        "DNS": "DNS",
        "HTTP": "HTTP",
        "FTP": "FTP",
        "SMTP": "SMTP",
        "POP3": "POP3",
        "IMAP": "IMAP",
        "BOOTP": "BOOTP",
        "DHCP": "DHCP",
        "SNMP": "SNMP",
        "Telnet": "Telnet",
        "SSH": "SSH",
        "NTP": "NTP",
        "TFTP": "TFTP",
        "LDAP": "LDAP",
    }

    if args.protocol not in protocols_supported:
        print(f"Protocol " + args.protocol + " is not supported.")
        print("\n")
        print("Protocols Supported: ", list(protocols_supported.values()))
        exit(1)

    protocol_layer = protocols_supported[args.protocol]

    for packet in packets:
        if packet.haslayer(protocol_layer):
            if args.protocol == "Ether":
                if packet[Ether].src == args.mac or packet[Ether].dst == args.mac:
                    snipped_packets.append(packet)
            elif args.protocol == "ARP":
                if packet[ARP].hwsrc == args.mac or packet[ARP].hwdst == args.mac:
                    snipped_packets.append(packet)
            elif args.protocol == "Dot11":
            elif args.protocol == "IP":
            elif args.protocol == "IPv6":
            elif args.protocol == "ICMP":
            elif args.protocol == "TCP":
            elif args.protocol == "UDP":
            elif args.protocol == "DNS":
            elif args.protocol == "HTTP":
            elif args.protocol == "FTP":
            elif args.protocol == "SMTP":
            elif args.protocol == "POP3":
            elif args.protocol == "IMAP":
            elif args.protocol == "BOOTP":
            elif args.protocol == "DHCP":
            elif args.protocol == "SNMP":
            elif args.protocol == "Telnet":
            elif args.protocol == "SSH":
            elif args.protocol == "NTP":
            elif args.protocol == "TFTP":
            elif args.protocol == "LDAP":
return snipped_packets

snipped = snip_packets(args.file, args.protocol, args.mac)
if snipped:
    wrpcap(name + "_snipped.pcap", snipped)
    print(f"Snipped packets saved to " name + "_snipped.pcap")
else:
    print("No packets related to the specified MAC and protocol identified.")

#def strip_packet(packet):
    # Test each packet and append to array
#    if packet.addr1 != args.mac:
#        return
#    packets.append(packets)
#sniff(offline = args.file, prn = strip_packet, filter=args.protocol)
#wrpcap(name + "_snipped.pcap", packets)
