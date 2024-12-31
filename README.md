
# Packet-Extractor

A python script for extracting packets with specific protocol types from a pcap utilizing scapy.

## Supported Protocols (Case Sensitive)

- Ethernet: Ether
- 802.11 (Wi-Fi): Dot11
- ARP (Address Resolution Protocol): ARP
- IPv4: IP
- IPv6: IPv6
- ICMP (Internet Control Message Protocol): ICMP
- TCP (Transmission Control Protocol): TCP
- UDP (User Datagram Protocol): UDP
- DNS (Domain Name System): DNS
- HTTP: HTTP
- FTP (File Transfer Protocol): FTP
- SMTP (Simple Mail Transfer Protocol): SMTP
- POP3: POP
- IMAP: IMAP
- DHCP (Dynamic Host Configuration Protocol): DHCP
- SNMP (Simple Network Management Protocol): SNMP
- Telnet: Telnet
- SSH (some support, limited)
- NTP (Network Time Protocol): NTP
- TFTP (Trivial File Transfer Protocol): TFTP
- LDAP: LDAP

## Additional Details:

- The created pcap will be put into the same directory as the original pcap. 
- I haven't tested every protocol...but it "should" work. 

