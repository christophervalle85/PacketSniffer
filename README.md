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

## Phase 3: packet reliability tests

This branch adds two regression suites beyond the original parser and CLI smoke tests:

- **`parser_adversarial`**: tests every truncated prefix of a known valid packet, loopback byte-order variants, malformed header fields, VLANs, and 12,000 deterministic random byte sequences.
- **`pcap_fixture_regressions`**: reads **`tests/fixtures/synthetic_mixed_traffic.pcap`** using `pcap_open_offline`, verifies expected protocol fields and error handling, and applies an offline BPF filter. The fixture contains only constructed test traffic.

The standard local test command runs all four suites:

~~~bash
ctest --test-dir build --output-on-failure
~~~

To check for memory errors and undefined behavior locally, build with sanitizers:

~~~bash
cmake -S . -B build-sanitized -DPACKETSNIFFER_ENABLE_SANITIZERS=ON
cmake --build build-sanitized
ctest --test-dir build-sanitized --output-on-failure
~~~

These checks increase confidence in the tested paths but cannot establish that all possible malformed packets are safe. They do not start a live capture and do not require sudo. There is no GitHub Actions workflow.

### Filtering vs. reconstructed data

`--filter` selects packets using libpcap's BPF filter syntax (for example, `--filter "tcp port 8765"`). Normal output displays protocol metadata; `--hex` additionally prints captured bytes, potentially including plaintext payloads. **The sniffer does not currently extract payloads, reassemble TCP streams, or decrypt TLS.** Future reconstruction should be explicit and bounded, with tests for out-of-order segments, retransmissions, and missing data.

## Limitations and next steps

- IPv4 and TCP header decoding only; other protocols, including IPv6, are not decoded.
- Fragmented IPv4 datagrams are not reassembled.
- No offline PCAP reader or GUI.
- Supported link-layer formats are detected at runtime.
- Phase 1 fixed capture safety; Phase 2 separated code responsibilities and added CMake. Phase 3 adds offline PCAP fixtures, adversarial parser tests, and opt-in local sanitizer builds. Future work can add protocol decoding and optional bounded TCP reconstruction.
