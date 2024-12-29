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
        "RAW": "RAW"
    }

    if protocol not in protocols_supported:
        print(f"Protocol {protocol} is not supported.")
        print("\n")
        print("Protocols Supported: ", list(protocols_supported.values()))
        sys.exit(1)

    protocol_layer = protocols_supported[protocol]

    for packet in packets:
        if packet.haslayer(protocol_layer):
            if protocol == "Ether" and ( mac and ( packet[Ether].src == mac or packet[Ether].dst == mac )):
                snipped_packets.append(packet)
            elif protocol == "ARP" and ( mac and ( packet[ARP].hwsrc == mac or packet[ARP].hwdst == mac )):
                snipped_packets.append(packet)
            elif protocol == "Dot11" and ( mac and ( packet[Dot11].addr1 == mac or packet[Dot11].addr2 == mac or packet[Dot11].addr3 == mac )):
                snipped_packets.append(packet)
            elif protocol == "IP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                snipped_packets.append(packet)
            elif protocol == "IPv6" and (ipv6addr and ( packet[IPv6].src == ipv6addr or packet[IPv6].dst == ipv6addr )):
                snipped_packets.append(packet)
            elif protocol == "ICMP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                snipped_packets.append(packet)
            elif protocol == "TCP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if port:
                    if packet[TCP].sport == port or packet[TCP].dport == port:
                        snipped_packets.append(packet)
                else:
                    snipped_packets.append(packet)
            elif protocol == "UDP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if port:
                    if packet[UDP].sport == port or packet[UDP].dport == port:
                        snipped_packets.append(packet)
                else:
                    snipped_packets.append(packet)
            elif protocol == "DNSQR" and (qname and ( packet[DNSQR].qname == qname)):
                snipped_packets.append(packet)
            elif protocol == "HTTP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if packet.haslayer(RAW):
                    if packet[RAW].load.startswith(b"GET") or packet[RAW].load.startswith(b"POST"):
                        snipped_packets.append(packet)
                    else:
                        print("HTTP packet was neither GET or POST request.")
            elif protocol == "FTP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if packet[TCP].sport == 21 or packet[TCP].dport == 21:
                    snipped_packets.append(packet)
                else:
                    print(f"FTP detected, but appeared to be on a non-standard port. Port: {packet[TCP].sport}")
            elif protocol == "SMTP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
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
                else:
                    print(f"SMTP detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "POP3" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[TCP].sport == 110 or
                    packet[TCP].sport == 995 or
                    packet[TCP].dport == 110 or
                    packet[TCP].dport == 995
                    ):
                        snipped_packets.append(packet)
                else:
                    print(f"POP3 detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "IMAP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[TCP].sport == 143 or
                    packet[TCP].sport == 993 or
                    packet[TCP].dport == 143 or
                    packet[TCP].dport == 993
                ):
                    snipped_packets.append(packet)
                else:
                    print(f"IMAP detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "BOOTP" and ( mac and ( packet[Ether].src == mac or packet[Ether].dst == mac )):
                snipped_packets.append(packet)
            elif protocol == "DHCP" and ( mac and ( packet[Ether].src == mac or packet[Ether].dst == mac )):
                snipped_packets.append(packet)
            elif protocol == "SNMP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[UDP].sport == 161 or
                    packet[UDP].sport == 162 or
                    packet[UDP].dport == 161 or
                    packet[UDP].dport == 162
                ):
                    snipped_packets.append(packet)
                else:
                    print(f"SNMP detected, but appeard to be on a non-standard port. Port: {packet[UDP].sport}") 
            elif protocol == "Telnet" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[TCP].sport == 23 or
                    packet[TCP].dport == 23
                ):
                    snipped_packets.append(packet)
                else:
                    print(f"Telnet detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "SSH" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[TCP].sport == 22 or
                    packet[TCP].dport == 22
                ):
                    snipped_packets.append(packet)
                else:
                    print(f"SSH detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "NTP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[UDP].sport == 123 or
                    packet[UDP].dport == 123
                ):
                    snipped_packets.append(packet)
                else:
                    print(f"NTP detected, but appeard to be on a non-standard port. Port: {packet[TCP].sport}") 
            elif protocol == "TFTP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[UDP].sport == 68 or
                    packet[UDP].sport == 69 or
                    packet[TCP].dport == 68 or
                    packet[TCP].dport == 69
                ):
                    snipped_packets.append(packet)
                elif packet[UDP].sport != 68 or packet[UDP].dport != 69:
                    print(f"TFTP detected, but appeard to be on a non-standard port. Port: {packet[UDP].sport}") 
                else:
                    print(f"TFTP detected, but appeared to be on a non-standard port. Port: {packet[TCP].sport}")
            elif protocol == "LDAP" and ( ipv4addr and ( packet[IP].src == ipv4addr or packet[IP].dst == ipv4addr )):
                if (
                    packet[TCP].sport == 389 or
                    packet[UDP].sport == 389 or
                    packet[TCP].sport == 636 or
                    packet[UDP].sport == 636 or
                    packet[TCP].dport == 389 or
                    packet[UDP].dport == 389 or
                    packet[TCP].dport == 636 or
                    packet[UDP].dport == 636
                ):
                    snipped_packets.append(packet)
                elif packet[UDP].sport != 389 or packet[UDP].sport != 636:
                    print(f"LDAP detected, but appeard to be on a non-standard port. Port: {packet[UDP].sport}") 
                else:
                    print(f"LDAP detected, but appeared to be on a non-standard port. Port: {packet[TCP].sport}")
    return snipped_packets

snipped = snipped_packets(pcap_file, protocol, mac=None, ipv4addr=None, ipv6addr=None, port=None, qname=None)
if snipped:
    name = os.path.splitext(args.pcap_file)[0]
    wrpcap(f"{name}_snipped.pcap", snipped)
    print(f"Snipped packets saved to {name}_snipped.pcap")
else:
    print("No packets related to the specified input and/or protocol identified.")

#def strip_packet(packet):
    # Test each packet and append to array
#    if packet.addr1 != mac:
#        return
#    packets.append( packets)
#sniff(offline = file, prn = strip_packet, filter=protocol)
#wrpcap(name + "_snipped.pcap", packets)
