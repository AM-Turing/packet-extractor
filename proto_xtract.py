#!/usr/bin/env python
import argparse
import os
import sys
import re
from scapy.all import *
from scapy.layers.l2 import Ether, ARP  # Ethernet, ARP, BOOTP
from scapy.layers.dot11 import Dot11  # 802.11 (Wi-Fi)
from scapy.layers.inet import IP, ICMP, TCP, UDP  # IPv4, ICMP, TCP, UDP, Raw (HTTP, etc.)
from scapy.layers.inet6 import IPv6  # IPv6
from scapy.layers.dns import DNSQR  # DNS
from scapy.layers.http import HTTP  # HTTP
from scapy.layers.dhcp import DHCP  # DHCP

# Define regex patterns for MAC, IPv4, and IPv6
MAC_REGEX = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
IPV4_REGEX = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
IPV6_REGEX = r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"

# Function to validate MAC address
def validate_mac(mac):
    if re.match(MAC_REGEX, mac.strip("'\"")):
        return True
    else:
        print(f"Invalid MAC address: {mac}")
        return False

# Function to validate IPv4 address
def validate_ipv4(ipv4addr):
    if re.match(IPV4_REGEX, ipv4addr.strip("'\"")):
        return True
    else:
        print(f"Invalid IPv4 address: {ipv4addr}")
        return False

# Function to validate IPv6 address
def validate_ipv6(ipv6addr):
    if re.match(IPV6_REGEX, ipv6addr.strip("'\"")):
        return True
    else:
        print(f"Invalid IPv6 address: {ipv6addr}")
        return False

parser = argparse.ArgumentParser(prog='proto_xtract.py', description='Extract all the packets')
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
parser.add_argument('--pcap_file', '-f', type=ascii, required=True, help='Packet capture filename')
parser.add_argument('--mac', '-m', type=ascii, help='Target devices Mac address - required for Layer 2 protocols')
parser.add_argument('--ipv4addr', '-ip', type=ascii, help='Target devices IPv4 address - required for IPv4 Layer 3 protocols')
parser.add_argument('--ipv6addr', '-ipv6', type=ascii, help='Target devices IPv6 address - required for IPv6 Layer 3 protocols')
parser.add_argument('--port', '-p', type=ascii, help='Target port for Layer 3 traffic - ip address will also be required.')
parser.add_argument('--qname', '-q', type=ascii, help='Target domain name for DNS traffic')
parser.add_argument('--protocol', '-r', type=ascii, required=True, help='Target protocol to parse - Layer 2 requires MAC | Layer 3 requires IP address.')
args = parser.parse_args()

if args.mac and not validate_mac(args.mac):
    sys.exit(1)  # Exit the program if the MAC address is invalid

if args.ipv4addr and not validate_ipv4(args.ipv4addr):
    sys.exit(1)  # Exit the program if the IPv4 address is invalid

if args.ipv6addr and not validate_ipv6(args.ipv6addr):
    sys.exit(1)  # Exit the program if the IPv6 address is invalid

def snip_packets(pcap_file, protocol, mac=None, ipv4addr=None, ipv6addr=None, port=None, qname=None): 
    for key, value in vars(args).items():
        if value is not None:
            # Strip out any ' or " from input.
            if key == "protocol" and isinstance(value, str):
                protocol = args.protocol.strip("'\"")
            elif key == "pcap_file" and isinstance(value, str):
                pcap_file = args.pcap_file.strip("'\"")
            elif key == "mac" and isinstance(value, str):
                mac = args.mac.strip("'\"")
            elif key == "ipv4addr" and isinstance(value, str):
                ipv4addr = args.ipv4addr.strip("'\"")
            elif key == "ipv6addr" and isinstance(value, str):
                ipv6addr = args.ipv6addr.strip("'\"")
            elif key == "port" and isinstance(value, str):
                port = args.port.strip("'\"")
            elif key == "qname" and isinstance(value, str):
                qname = args.qname.strip("'\"")
            else:
                print("Your input was not recognized. Please use -h for assistance.")
                sys.exit(1)
    # Make sure the absolute path is used for the file supplied
    script_dir = os.path.dirname(os.path.realpath(__file__))
    pcap_file_path = os.path.join(script_dir, pcap_file)
    try:
        packets = rdpcap(pcap_file_path)
    except Exception as e:
        print(f"Error reading packet capture file: {e}")
        sys.exit(1)
    snipped_packets = []
    protocols_supported = {
        "Ether": Ether,
        "ARP": ARP,
        "Dot11": Dot11,
        "IPv4": IP,
        "IPv6": IPv6,
        "ICMP": ICMP,
        "TCP": TCP,
        "UDP": UDP,
        "DNS": DNSQR,
        "HTTP": HTTP,
        "FTP": TCP,
        "SMTP": TCP,
        "POP3": TCP,
        "IMAP": TCP,
        "DHCP": DHCP,
        "SNMP": UDP,
        "Telnet": TCP,
        "SSH": TCP,
        "NTP": UDP,
        "TFTP": [UDP, TCP],
        "LDAP": [TCP, UDP],
    }
    if protocol not in protocols_supported:
        print(f"Protocol {protocol} is not supported.")
        print("\n")
        print("Protocols Supported: ", list(protocols_supported.values()))
        sys.exit(1)
    # Begin parsing for specific protocols and ports. Update here and the protocols_supported list for more variations.
    protocol_layer = protocols_supported[protocol]
    for pkt in packets:
        if pkt.haslayer(protocol_layer): 
            if protocol == "Ether" and pkt.haslayer(Ether):
                if mac:
                    if pkt[Ether].src == mac or pkt[Ether].dst == mac:
                        snipped_packets.append(pkt)
            elif protocol == "ARP" and pkt.haslayer(ARP):    
                if ipv4addr:
                    if pkt[Ether].src == mac or pkt[Ether].dst == mac:
                        snipped_packets.append(pkt)
            elif protocol == "Dot11" and pkt.haslayer(Dot11):
                if mac:
                    if pkt[Dot11].addr1 == mac or pkt[Dot11].addr2 == mac or pkt[Dot11].addr3 == mac:
                        snipped_packets.append(pkt)
            elif protocol == "IP" and pkt.haslayer(IP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        snipped_packets.append(pkt)
            elif protocol == "IPv6" and pkt.haslayer(IPv6):
                if ipv6addr:
                    if pkt[IPv6].src == ipv6addr or pkt[IPv6].dst == ipv6addr:
                        snipped_packets.append(pkt)
            elif protocol == "ICMP" and pkt.haslayer(ICMP):
                print(pkt)
                if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                    print(ipv4addr)
                    snipped_packets.append(pkt)
            elif protocol == "TCP" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if port:
                            if pkt[TCP].sport == port or pkt[TCP].dport == port:
                                snipped_packets.append(pkt)
                        else:
                            snipped_packets.append(pkt)
            elif protocol == "UDP" and pkt.haslayer(UDP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if port:
                            if pkt[UDP].sport == port or pkt[UDP].dport == port:
                                snipped_packets.append(pkt)
                        else:
                            snipped_packets.append(pkt)
            elif protocol == "DNSQR" and pkt.haslayer(DNSQR):
                if qname:
                    if pkt[DNSQR].qname == qname:
                        snipped_packets.append(pkt)
            elif protocol == "HTTP" and pkt.haslayer(HTTP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if pkt.haslayer(Raw):
                            if pkt[Raw].load.startswith(b"GET") or pkt[Raw].load.startswith(b"POST"):
                                snipped_packets.append(pkt)
                        else:
                            print("HTTP packet was neither GET or POST request.")
            elif protocol == "FTP" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
                            snipped_packets.append(pkt)
                        else:
                            print(f"FTP detected, but appeared to be on a non-standard port. Port: {pkt[TCP].sport}")
            elif protocol == "SMTP" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                                pkt[TCP].sport == 587 or
                                pkt[TCP].sport == 25 or
                                pkt[TCP].sport == 465 or
                                pkt[TCP].sport == 2525 or
                                pkt[TCP].dport == 587 or
                                pkt[TCP].dport == 25 or
                                pkt[TCP].dport == 465 or
                                pkt[TCP].dport == 2525
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"SMTP detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "POP3" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[TCP].sport == 110 or
                            pkt[TCP].sport == 995 or
                            pkt[TCP].dport == 110 or
                            pkt[TCP].dport == 995
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"POP3 detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "IMAP" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[TCP].sport == 143 or
                            pkt[TCP].sport == 993 or
                            pkt[TCP].dport == 143 or
                            pkt[TCP].dport == 993
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"IMAP detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "DHCP" and pkt.haslayer(DHCP):
                if mac:
                    if pkt[Ether].src == mac or pkt[Ether].dst == mac:
                        snipped_packets.append(pkt)
            elif protocol == "SNMP" and pkt.haslayer(UDP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[UDP].sport == 161 or
                            pkt[UDP].sport == 162 or
                            pkt[UDP].dport == 161 or
                            pkt[UDP].dport == 162
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"SNMP detected, but appeard to be on a non-standard port. Port: {pkt[UDP].sport}") 
            elif protocol == "Telnet" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[TCP].sport == 23 or
                            pkt[TCP].dport == 23
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"Telnet detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "SSH" and pkt.haslayer(TCP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[TCP].sport == 22 or
                            pkt[TCP].dport == 22
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"SSH detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "NTP" and pkt.haslayer(UDP):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[UDP].sport == 123 or
                            pkt[UDP].dport == 123
                        ):
                            snipped_packets.append(pkt)
                        else:
                            print(f"NTP detected, but appeard to be on a non-standard port. Port: {pkt[TCP].sport}") 
            elif protocol == "TFTP" and (pkt.haslayer(UDP) or pkt.haslayer(TCP)):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[UDP].sport == 68 or
                            pkt[UDP].sport == 69 or
                            pkt[TCP].dport == 68 or
                            pkt[TCP].dport == 69
                        ):
                            snipped_packets.append(pkt)
                        elif pkt[UDP].sport != 68 or pkt[UDP].dport != 69:
                            print(f"TFTP detected, but appeard to be on a non-standard port. Port: {pkt[UDP].sport}") 
                        else:
                            print(f"TFTP detected, but appeared to be on a non-standard port. Port: {pkt[TCP].sport}")
            elif protocol == "LDAP" and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                if ipv4addr:
                    if pkt[IP].src == ipv4addr or pkt[IP].dst == ipv4addr:
                        if (
                            pkt[TCP].sport == 389 or
                            pkt[UDP].sport == 389 or
                            pkt[TCP].sport == 636 or
                            pkt[UDP].sport == 636 or
                            pkt[TCP].dport == 389 or
                            pkt[UDP].dport == 389 or
                            pkt[TCP].dport == 636 or
                            pkt[UDP].dport == 636
                        ):
                            snipped_packets.append(pkt)
                        elif pkt[UDP].sport != 389 or pkt[UDP].sport != 636:
                            print(f"LDAP detected, but appeard to be on a non-standard port. Port: {pkt[UDP].sport}") 
                        else:
                            print(f"LDAP detected, but appeared to be on a non-standard port. Port: {pkt[TCP].sport}")
    return snipped_packets
snipped = snip_packets(args.pcap_file, args.protocol, args.mac, args.ipv4addr, args.ipv6addr, args.port, args.qname)
if snipped:
    name = os.path.splitext(args.pcap_file)[0].strip("'\"")
    protocol = args.protocol.strip("'\"")
    wrpcap(f"{name}_{protocol}_snipped.pcap", snipped)
    print(f"Snipped packets saved to {name}_{protocol}_snipped.pcap")
else:
    print("No packets related to the specified input and/or protocol identified.")
