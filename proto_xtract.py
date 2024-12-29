#!/usr/bin/env python
import argparse
import os
import sys
from scapy.all import *

parser = argparse.ArgumentParser(prog='proto_xtract.py', description='Extract all the packets')
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
parser.add_argument('--pcap_file', '-f', type=ascii, required=True, help='Packet capture filename')
parser.add_argument('--mac', '-m', type=ascii, help='Target devices Mac address for Layer 2 protocols')
parser.add_argument('--ipv4addr', '-ip', type=ascii, help='Target devices IPv4 address for Layer 3 protocols')
parser.add_argument('--ipv6addr', '-ipv6', type=ascii, help='Target devices IPv6 address for Layer 3 protocols')
parser.add_argument('--port', '-p', type=ascii, help='Target port for Layer 3 traffic')
parser.add_argument('--qname', '-q', type=ascii, help='Target domain name for DNS traffic')
parser.add_argument('--protocol', '-r', type=ascii, required=True, help='Target protocol to parse')
args = parser.parse_args()

def snip_packets(pcap_file, protocol, mac=None, ipv4addr=None, ipv6addr=None, port=None, qname=None):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading packet capture file: {e}")
        sys.exit(1)
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

    if protocol not in protocols_supported:
        print(f"Protocol {protocol} is not supported.")
        print("\n")
        print("Protocols Supported: ", list(protocols_supported.values()))
        sys.exit(1)

    protocol_layer = protocols_supported[protocol]

    for packet in packets:
        if packet.haslayer(protocol_layer):
            if protocol == "Ether":
                if packet[Ether].src == mac or packet[Ether].dst == mac:
                    snipped_packets.append(packet)
            elif protocol == "ARP":
                if packet[ARP].hwsrc == mac or packet[ARP].hwdst == mac:
                    snipped_packets.append(packet)
            elif protocol == "Dot11":
                if ( 
                        packet[Dot11].addr1 == mac or
                        packet[Dot11].addr2 == mac or
                        packet[Dot11].addr3 == mac
                    ):
                    snipped_packets.append(packet)
            elif protocol == "IP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    snipped_packets.append(packet)
            elif protocol == "IPv6":
                if packet[IPv6].src == ipv6addr or packet[IPv6].dst == ipv6addr:
                    snipped_packets.append(packet)
            elif protocol == "ICMP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    snipped_packets.append(packet)
            elif protocol == "TCP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    snipped_packets.append(packet)
                elif packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                            packet[TCP].sport == port or
                            packet[UDP].sport == port or
                            packet[TCP].dport == port or
                            packet[UDP].dport == port
                    ):
                        snipped_packets.append(packet)
            elif protocol == "UDP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    snipped_packets.append(packet)
            elif protocol == "DNSQR":
                if packet[DNSQR].qname == qname:
                    snipped_packets.append(packet)
            elif protocol == "HTTP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if packet[RAW].load.startswith(b"GET") or packet[RAW].load.startswith(b"POST"):
                        snipped_packets.append(packet)
            elif protocol == "FTP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if packet[TCP].sport == 21 or packet[TCP].dport == 21:
                        snipped_packets.append(packet)
            elif protocol == "SMTP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
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
            elif protocol == "POP3":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[TCP].sport == 110 or
                        packet[TCP].sport == 995 or
                        packet[TCP].dport == 110 or
                        packet[TCP].dport == 995
                        ):
                            snipped_packets.append(packet)
            elif protocol == "IMAP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[TCP].sport == 143 or
                        packet[TCP].sport == 993 or
                        packet[TCP].dport == 143 or
                        packet[TCP].dport == 993
                    ):
                        snipped_packets.append(packet)
            elif protocol == "BOOTP":
                if packet[Ether].src == mac or packet[Ether].dst == mac:
                    snipped_packets.append(packet)
            elif protocol == "DHCP":
                if packet[Ether].src == mac or packet[Ether].dst == mac:
                    snipped_packets.append(packet)
            elif protocol == "SNMP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[UDP].sport == 161 or
                        packet[UDP].sport == 162 or
                        packet[UDP].dport == 161 or
                        packet[UDP].dport == 162
                    ):
                        snipped_packets.append(packet)
            elif protocol == "Telnet":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[TCP].sport == 23 or
                        packet[TCP].dport == 23
                    ):
                        snipped_packets.append(packet)
            elif protocol == "SSH":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[TCP].sport == 22 or
                        packet[TCP].dport == 22
                    ):
                        snipped_packets.append(packet)
            elif protocol == "NTP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[UDP].sport == 123 or
                        packet[UDP].dport == 123
                    ):
                        snipped_packets.append(packet)
            elif protocol == "TFTP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[UDP].sport == 68 or
                        packet[UDP].sport == 69 or
                        packet[UDP].dport == 68 or
                        packet[TCP].dport == 69
                    ):
                        snipped_packets.append(packet)
            elif protocol == "LDAP":
                if packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr:
                    if (
                        packet[TCP].sport == 389 or
                        packet[UDP].sport == 389 or
                        packet[TCP].sport == 636 or
                        packet[UDP].sport == 636 or
                        packet[TCP].dport == 389 or
                        packet[UDP].dport == 389 or
                        packet[TCP].dport == 636 or
                        packet[UDP].dport == 636 or
                    ):
                            snipped_packets.append(packet)
    return snipped_packets

snipped = snip_packets(file, protocol, mac)
name = os.path.splitext(args.pcap_file)[0]
if snipped:
    wrpcap("{name}_snipped.pcap", snipped)
    print(f"Snipped packets saved to {name}_snipped.pcap")
else:
    print("No packets related to the specified input and/or protocol identified.")

#def strip_packet(packet):
    # Test each packet and append to array
#    if packet.addr1 != mac:
#        return
#    packets.append(packets)
#sniff(offline = file, prn = strip_packet, filter=protocol)
#wrpcap(name + "_snipped.pcap", packets)
