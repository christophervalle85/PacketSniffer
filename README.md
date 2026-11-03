# PacketSniffer

A small C++ packet sniffer built with **libpcap** to learn how network captures and TCP/IP headers work. It is intended for traffic I own or am explicitly authorized to inspect, including loopback experiments on my own computer.

## What it does

- Captures packets from a network interface selected on the command line.
- Detects the link-layer type at runtime instead of assuming macOS and Linux use different packet layouts.
- Supports Ethernet (including VLAN tags), BSD/macOS loopback, raw IP, and Linux cooked capture headers where available.
- Displays Ethernet MAC addresses, IPv4 source/destination addresses, and TCP source/destination ports when those headers are present and valid.
- Shows packet headers and capture lengths by default; optional hexadecimal/ASCII output is limited to **captured bytes only**.
- Supports BPF capture filters, bounded capture counts, and a built-in `--help` command.
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

## Command-line options

~~~text
Usage: ./packetSniffer [options] <network-interface>
       ./packetSniffer -i <network-interface> [options]

  -i, --interface <name>  Choose an interface (lo0 on macOS, lo on Linux)
  -f, --filter <expr>     Capture only packets matching a BPF filter
  -c, --count <number>   Stop after this many matching packets
  -x, --hex              Show the hex/ASCII captured-byte dump
  -h, --help             Print usage without opening an interface
~~~

The original interface argument still works: `sudo ./packetSniffer lo0`. By default the sniffer prints headers without hex/ASCII dumps, and runs until Ctrl-C.

To monitor only traffic for the local HTTP server on port 8765, and stop after ten matching packets:

~~~bash
sudo ./packetSniffer lo0 --filter "tcp port 8765" --count 10
~~~

Use `--hex` only if you intentionally need to inspect captured bytes. They may contain plaintext sensitive information, so avoid full dumps when they're not needed.

An invalid filter is reported and the capture exits; filters use standard libpcap/BPF expression syntax. Capture counts apply to packets **after filtering**.

## Safe localhost test

Only capture traffic you own or have permission to monitor. To test without capturing other devices' traffic, use the **loopback** interface and generate the requests yourself.

1. Start the sniffer in one terminal:

   **macOS:**
   ~~~bash
   sudo ./packetSniffer lo0 --filter "tcp port 8765" --count 20
   ~~~

   **Linux:**
   ~~~bash
   sudo ./packetSniffer lo --filter "tcp port 8765" --count 20
   ~~~

2. Start a local HTTP server in a second terminal (in a directory with no private files):

   ~~~bash
   mkdir -p /tmp/packetsniffer-lab
   cd /tmp/packetsniffer-lab
   python3 -m http.server 8765 --bind 127.0.0.1
   ~~~

3. Generate your own traffic in a third terminal:

   ~~~bash
   curl http://127.0.0.1:8765/
   ~~~

4. Inspect the captured IPv4/TCP headers. The sniffer stops after 20 matching packets; otherwise, press **Ctrl-C**. Press Ctrl-C separately to stop the Python server.

**Privacy note:** Packet dumps can expose plaintext data. Use synthetic/local test traffic, do not capture other people's private communications, and do not upload real captures containing sensitive information.

## Parsing safeguards

The capture callback receives both the original wire length (**len**) and the number of bytes actually available (**caplen**). Every header access uses **caplen**, validates the link-layer offset, and checks the declared IPv4 and TCP header sizes. Invalid, truncated, and fragmented packets are reported or skipped without trying to read an absent transport header.

## Current limitations

- IPv4 parsing only; IPv6 packets are skipped.
- TCP port decoding only; other IPv4 protocols are identified by number but not decoded.
- Fragmented IPv4 traffic is not reassembled.
- Link-layer support is limited to the types listed above; unsupported capture types produce an error.
- Output is written to the terminal; there is no offline PCAP reader or GUI yet.
- Local tests are available, but no GitHub Actions workflow is configured.

## Run tests locally (no GitHub Actions)

Compile and run the synthetic packet safety tests:

~~~bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -o phase1_safety_smoke tests/phase1_safety_smoke.cpp -lpcap
./phase1_safety_smoke
~~~

Compile and run CLI parser tests:

~~~bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -o cli_options_smoke tests/cli_options_smoke.cpp -lpcap
./cli_options_smoke
~~~

These tests don't open a live network interface, so no sudo is required. They verify specific parser and CLI behaviors, not all possible traffic or macOS versions.

## Development plan

Phase 1 fixes input validation, capture-handle usage, packet bounds checks, link-layer detection, and cleanup. The next phases will separate capture/parsing/output, add offline fixtures and broader tests, and support more protocols. BPF filters, packet limits, and optional hex output were brought forward after live testing showed how noisy unfiltered captures can be.
