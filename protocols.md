
# Protocols Supported by Scapy

## Layer 2 (Data Link Layer)

Ethernet: Ether
802.3: Dot3
802.11 (Wi-Fi): Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11Deauth, etc.
ARP (Address Resolution Protocol): ARP
LLC (Logical Link Control): LLC
STP (Spanning Tree Protocol): STP

## Layer 3 (Network Layer)

IPv4: IP
IPv6: IPv6
ICMP (Internet Control Message Protocol): ICMP
ICMPv6: ICMPv6
GRE (Generic Routing Encapsulation): GRE
EIGRP (Enhanced Interior Gateway Routing Protocol): EIGRP
OSPF (Open Shortest Path First): OSPF
IPsec Headers: ESP (Encapsulating Security Payload), AH (Authentication Header)

## Layer 4 (Transport Layer)

TCP (Transmission Control Protocol): TCP
UDP (User Datagram Protocol): UDP
SCTP (Stream Control Transmission Protocol): SCTP
DCCP (Datagram Congestion Control Protocol): DCCP

## Layer 5-7 (Session, Presentation, Application Layers)

DNS (Domain Name System): DNS
HTTP: HTTP
HTTPS (requires SSL/TLS handling with libraries like pyOpenSSL)
FTP (File Transfer Protocol): FTP
SMTP (Simple Mail Transfer Protocol): SMTP
POP3: POP
IMAP: IMAP
DHCP (Dynamic Host Configuration Protocol): BOOTP, DHCP
SNMP (Simple Network Management Protocol): SNMP
Telnet: Telnet
SSH (some support, limited)
NTP (Network Time Protocol): NTP
TFTP (Trivial File Transfer Protocol): TFTP
LDAP: LDAP

## Security and VPN Protocols

SSL/TLS (basic parsing): SSL, TLS
IKE (Internet Key Exchange): ISAKMP
IPsec: ESP, AH
PPTP (Point-to-Point Tunneling Protocol): PPTP
OpenVPN: OpenVPN

## Routing Protocols

BGP (Border Gateway Protocol): BGP
RIP (Routing Information Protocol): RIP
OSPF (Open Shortest Path First): OSPF

## Industrial Protocols

Modbus: Modbus
BACnet: BACnet

## Other Protocols

Raw Sockets: Raw
VRRP (Virtual Router Redundancy Protocol): VRRP
MPLS (Multiprotocol Label Switching): MPLS
PPPoE (Point-to-Point Protocol over Ethernet): PPPoE
VXLAN (Virtual Extensible LAN): VXLAN
