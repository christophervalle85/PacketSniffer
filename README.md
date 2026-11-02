# PacketSniffer

A small C++ packet sniffer built with **libpcap** to learn how network captures and TCP/IP headers work. It is intended for traffic I own or am explicitly authorized to inspect, including loopback experiments on my own computer.

## What it does

- Captures packets from a network interface selected on the command line.
- Detects the link-layer type at runtime instead of assuming macOS and Linux use different packet layouts.
- Supports Ethernet (including VLAN tags), BSD/macOS loopback, raw IP, and Linux cooked capture headers where available.
- Displays Ethernet MAC addresses, IPv4 source/destination addresses, and TCP source/destination ports when those headers are present and valid.
- Shows the original packet length, the captured length, and a hexadecimal/ASCII view of **only the captured bytes**.
- Stops with Ctrl-C and closes the capture handle.

Promiscuous mode is **disabled**. The sniffer does not send packets or attempt to decrypt encrypted traffic.

## Requirements

- macOS or Linux
- A C++17 compiler
- The libpcap headers and library
  - macOS: libpcap is usually available with the system developer tools; install Xcode Command Line Tools if needed.
  - Debian/Ubuntu: install g++ and libpcap-dev (for example, **sudo apt install g++ libpcap-dev**).
- Permission to capture on the selected interface (often requires sudo).

## Build

From the repository directory:

~~~bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -o packetSniffer packetSniffer.cpp -lpcap
~~~

## Safe localhost test

Only capture traffic you own or have permission to monitor. To test without capturing other devices' traffic, use the **loopback** interface and generate the requests yourself.

1. Start the sniffer in one terminal:

   **macOS:**
   ~~~bash
   sudo ./packetSniffer lo0
   ~~~

   **Linux:**
   ~~~bash
   sudo ./packetSniffer lo
   ~~~

2. Start a local HTTP server in a second terminal (in a directory with no private files):

   ~~~bash
   mkdir -p /tmp/packetsniffer-lab
   cd /tmp/packetsniffer-lab
   python3 -m http.server 8000 --bind 127.0.0.1
   ~~~

3. Generate your own traffic in a third terminal:

   ~~~bash
   curl http://127.0.0.1:8000/
   ~~~

4. Inspect the captured IPv4/TCP headers, then press **Ctrl-C** to stop the sniffer and the server.

**Privacy note:** Packet dumps can expose plaintext data. Use synthetic/local test traffic, do not capture other people's private communications, and do not upload real captures containing sensitive information.

## Parsing safeguards

The capture callback receives both the original wire length (**len**) and the number of bytes actually available (**caplen**). Every header access uses **caplen**, validates the link-layer offset, and checks the declared IPv4 and TCP header sizes. Invalid, truncated, and fragmented packets are reported or skipped without trying to read an absent transport header.

## Current limitations

- IPv4 parsing only; IPv6 packets are skipped.
- TCP port decoding only; other IPv4 protocols are identified by number but not decoded.
- Fragmented IPv4 traffic is not reassembled.
- Link-layer support is limited to the types listed above; unsupported capture types produce an error.
- Output is written to the terminal; there is no offline PCAP reader, command-line filtering, or automated test suite yet.

## Development plan

Phase 1 fixes input validation, capture-handle usage, packet bounds checks, link-layer detection, and cleanup. The next phases will separate capture/parsing/output, add offline fixtures and automated tests, then introduce optional filters and more protocol support.
