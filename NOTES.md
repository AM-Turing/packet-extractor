
# Notes on Protocol Interactions

    - Ether - Requires MAC (src/dst)
    - Dot11 - Requires MAC (addr1)
    - ARP   - Requires MAC (hwsrc/hwdst)
    - IPv4(IP) - Requires IP (src/dst)
    - IPv6  - Requires IP (src/dst)
    - ICMP  - Requires IP (addr_mask)
    - TCP   - Requires Port (sport/dport)
    - UDP   - Requires Port (sport/dport)
    - DNS   - Requires DNSQR (qname)
    - HTTP  - Researching...
    - Most others require TCP or UDP and then a specific port (or ports). 
