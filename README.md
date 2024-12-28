
# Packet-Extractor

A python script for extracting specific protocol types from a pcap.

## Supported Protocols (Case Sensitive)

- Ethernet: Ether
- 802.11 (Wi-Fi): Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11Deauth, etc.
- ARP (Address Resolution Protocol): ARP
- IPv4: IP
- IPv6: IPv6
- ICMP (Internet Control Message Protocol): ICMP
- TCP (Transmission Control Protocol): TCP
- UDP (User Datagram Protocol): UDP
- DNS (Domain Name System): DNS
- HTTP: HTTP
- HTTPS (requires SSL/TLS handling with libraries like pyOpenSSL)
- FTP (File Transfer Protocol): FTP
- SMTP (Simple Mail Transfer Protocol): SMTP
- POP3: POP
- IMAP: IMAP
- BOOTP: BOOTP
- DHCP (Dynamic Host Configuration Protocol): DHCP
- SNMP (Simple Network Management Protocol): SNMP
- Telnet: Telnet
- SSH (some support, limited)
- NTP (Network Time Protocol): NTP
- TFTP (Trivial File Transfer Protocol): TFTP
- LDAP: LDAP
