# PacketSniffer

A C++ network packet analyzer built with **libpcap** to explore TCP/IP headers, defensive packet parsing, and authorized traffic inspection. I use it for traffic I own or am explicitly permitted to monitor, including localhost experiments.

## Features

- Capture traffic from a selected network interface, with promiscuous mode disabled.
- Apply libpcap/BPF filters, such as **tcp port 8765**.
- Stop after a specified number of matching packets, or press Ctrl-C.
- Decode Ethernet (including VLAN tags), macOS/BSD loopback, raw IP, and Linux cooked link-layer formats where supported.
- Display IPv4 addresses, TCP port numbers, captured lengths, and optional hexadecimal/ASCII dumps.
- Validate captured lengths before reading packet headers.

## Phase 2 architecture

The former single-file implementation is separated into components with one responsibility each:

| Component | Responsibility |
| --- | --- |
| src/main.cpp | Coordinates arguments and application startup |
| src/CliOptions.cpp | Validates CLI arguments |
| src/PacketCapture.cpp | Manages libpcap handles, BPF filters, callbacks, and cleanup |
| src/PacketParser.cpp | Decodes captured bytes without any network I/O |
| src/PacketFormatter.cpp | Prints readable packet summaries and optional hex dumps |

Public interfaces are declared in **include/**. Capture handles and interface lists use RAII to release resources automatically. The parser and formatter are testable with synthetic buffers without capturing live traffic.

## Requirements

- macOS or Linux
- CMake 3.16+, a C++17 compiler, and libpcap headers/library
- Permission to capture on the selected interface (often sudo)

On Debian/Ubuntu, install **cmake**, **g++**, and **libpcap-dev**. On macOS, install CMake if needed and use the system C++ compiler and libpcap development headers.

## Build and run tests locally

From the repository root:

~~~bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
~~~

There are no GitHub Actions workflows. The local tests use synthetic packets and CLI arguments, not real network interfaces, and do not require sudo.

Show the built-in help:

~~~bash
./build/packetSniffer --help
~~~

## Command-line options

~~~text
Usage: ./build/packetSniffer [options] <network-interface>
       ./build/packetSniffer -i <network-interface> [options]

  -i, --interface <name>  Network interface (e.g. lo0 on macOS)
  -f, --filter <expr>     BPF filter (e.g. 'tcp port 8765')
  -c, --count <number>   Stop after this many matching packets
  -x, --hex              Print packet bytes in hex and ASCII
  -h, --help             Show this help message
~~~

The original positional interface syntax still works.

## Safe localhost test

Run only on interfaces you are authorized to monitor. On macOS, use loopback **lo0** (Linux: **lo**) to keep traffic on your machine.

Terminal 1:

~~~bash
sudo ./build/packetSniffer lo0 --filter "tcp port 8765" --count 10
~~~

Terminal 2:

~~~bash
mkdir -p /tmp/packetsniffer-lab
cd /tmp/packetsniffer-lab
python3 -m http.server 8765 --bind 127.0.0.1
~~~

Terminal 3:

~~~bash
curl http://127.0.0.1:8765/
~~~

Repeat curl if the sniffer has not yet received ten packets. Look for IPv4 addresses **127.0.0.1** and TCP port **8765**. The sniffer stops at the count; Ctrl-C also stops it.

The optional **--hex** flag prints captured bytes, which may include plaintext private information. Avoid using it unless needed, and do not upload private real-world captures.

## Limitations and next steps

- IPv4 and TCP header decoding only; other protocols, including IPv6, are not decoded.
- Fragmented IPv4 datagrams are not reassembled.
- No offline PCAP reader or GUI.
- Supported link-layer formats are detected at runtime.
- Phase 1 fixed capture safety; Phase 2 separated code responsibilities and added CMake and local regression tests. Next: more offline fixtures, protocol support, and additional testing.
