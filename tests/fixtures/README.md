# Synthetic offline packet fixture

`synthetic_mixed_traffic.pcap` is a deliberately constructed, classic-PCAP (Ethernet link type) test file. It is not a real capture, and includes no private user traffic. IPv4/TCP checksums are zero because parser testing does not validate checksums.

Records, in order:

1. IPv4/TCP request to localhost port 8765 containing synthetic HTTP request bytes
2. IPv4/TCP response from localhost port 8765 containing synthetic HTTP response bytes
3. IPv4/UDP packet using mDNS port 5353 and multicast address 224.0.0.251
4. Truncated Ethernet header (captured length differs from original length)
5. Truncated IPv4 header
6. Truncated TCP header with port fields still present
7. TCP header with invalid data offset
8. VLAN-tagged Ethernet / IPv4 / TCP packet
9. Non-IPv4 Ethernet (IPv6 EtherType)
10. Fragmented IPv4 packet
11. IPv4 packet with invalid header length
12. IPv4 packet with invalid total length

The `pcap_fixture_regressions` CTest target reads this file through libpcap, checks the decoded fields and expected errors, and checks BPF filter behavior. In particular, BPF can match a truncated TCP record whose port bytes are available even though the full TCP header is absent. This is one reason filtering and safe parsing must be tested independently.
