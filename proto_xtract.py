#!/usr/bin/env python
import argparse
import os
from scapy.all import *

parser = argparse.ArgumentParser(prog='proto_xtract.py', description='Extract all the packets')
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
parser.add_argument('--file', '-f', type=ascii, required=True, help='Packet capture filename')
parser.add_argument('--mac', '-m', type=ascii, help='Target devices Mac address for Layer 2 protocols')
parser.add_argument('--ipv4addr', '-ip', type=ascii, help='Target devices IPv4 address for Layer 3 protocols')
parser.add_argument('--ipv6addr', '-ipv6', type=ascii, help='Target devices IPv6 address for Layer 3 protocols')
parser.add_argument('--port', '-p', type=ascii, help='Target port for Layer 3 traffic')
parser.add_argument('--qname', '-q', type=ascii, help='Target domain name for DNS traffic')
parser.add_argument('--protocol', '-r', type=ascii, required=True, help='Target protocol to parse')
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
        "DNS": "DNSQR",
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
                if ( 
                        packet[Dot11].addr1 == args.mac or
                        packet[Dot11].addr2 == args.mac or
                        packet[Dot11].addr3 == args.mac
                    ):
                    snipped_packets.append(packet)
            elif args.protocol == "IP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    snipped_packets.append(packet)
            elif args.protocol == "IPv6":
                if packet[IPv6].src == args.ipv6addr or packet[IPv6].dst == args.ipv6addr:
                    snipped_packets.append(packet)
            elif args.protocol == "ICMP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    snipped_packets.append(packet)
            elif args.protocol == "TCP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    snipped_packets.append(packet)
            elif args.protocol == "UDP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    snipped_packets.append(packet)
            elif args.protocol == "DNSQR":
                if packet[DNSQR].qname == args.qname:
                    snipped_packets.append(packet)
            elif args.protocol == "HTTP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if packet[RAW].load.startswith(b"GET") or packet[RAW].load.startswith(b"POST"):
                    snipped_packets.append(packet)
            elif args.protocol == "FTP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if packet[TCP].sport == 21 or packet[TCP].dport == 21:
                    snipped_packets.append(packet)
            elif args.protocol == "SMTP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if ( 
                            packet[TCP].sport == 587 or
                            packet[TCP].sport == 25 or 
                            packet[TCP].sport == 465 or
                            packet[TCP].sport == 2525 or
                            packet[TCP].dport == 587 or
                            packet[TCP].dport == 25 or
                            packet[TCP].dport == 465 or
                            packet[TCP].dport == 2525
                        ):
                        snipped_packets.append(packet)
            elif args.protocol == "POP3":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if (
                        packet[TCP].sport == 110 or
                        packet[TCP].sport == 995 or
                        packet[TCP].dport == 110 or
                        packet[TCP].dport == 995
                        ):
                        snipped_packets.append(packet)
            elif args.protocol == "IMAP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if (
                        packet[TCP].sport == 143 or
                        packet[TCP].sport == 993 or
                        packet[TCP].dport == 143 or
                        packet[TCP].dport == 993
                    )
                    snipped_packets.append(packet)
            elif args.protocol == "BOOTP":
                if packet[Ether].src == args.mac or packet[Ether].dst == args.mac:
                    snipped_packets.append(packet)
            elif args.protocol == "DHCP":
                if packet[Ether].src == args.mac or packet[Ether].dst == args.mac:
                    snipped_packets.append(packet)
            elif args.protocol == "SNMP":
                if packet[IP].src == args.ipv4addr or packet[IP].dst == args.ipv4addr:
                    if (
                        packet[UDP].sport == 161 or
                        packet[UDP].sport == 162 or
                        packet[UDP].dport == 161 or
                        packet[UDP].dport == 162
                    )
                    snipped_packets.append(packet)
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
