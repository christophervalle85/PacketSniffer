// Offline PCAP regression tests; this reads synthetic fixture data, not real traffic.
#include "PacketFormatter.hpp"
#include "PacketParser.hpp"

#include <pcap.h>
#include <cstddef>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

using packetsniffer::PacketDetails;
using packetsniffer::PacketFormatter;
using packetsniffer::PacketParser;

namespace {

void require(bool condition, const std::string& explanation) {
    if (!condition) throw std::runtime_error(explanation);
}

bool has_notice(const PacketDetails& details, const std::string& expected) {
    for (const auto& notice : details.notices) {
        if (notice.find(expected) != std::string::npos) return true;
    }
    return false;
}

void inspect_record(std::size_t number, const pcap_pkthdr& header,
                    const unsigned char* packet, const PacketDetails& details) {
    std::ostringstream text;
    PacketFormatter::print(text, header, packet, details, false);
    require(text.str().find("Packet bytes (hex and ASCII") == std::string::npos,
            "Hex dump should stay off unless requested");

    if (number == 1) {
        require(details.has_ipv4_addresses && details.has_tcp_ports,
                "Record 1 should be a valid TCP request");
        require(details.source_ip == "127.0.0.1" &&
                details.destination_ip == "127.0.0.1",
                "Expected localhost addresses");
        require(details.source_port == 49152 && details.destination_port == 8765,
                "Expected HTTP request ports");
        std::ostringstream with_hex;
        PacketFormatter::print(with_hex, header, packet, details, true);
        require(with_hex.str().find("Packet bytes (hex and ASCII") != std::string::npos,
                "Hex dump should appear when explicitly requested");
    } else if (number == 2) {
        require(details.has_tcp_ports && details.source_port == 8765 &&
                details.destination_port == 49152, "Expected HTTP response ports");
    } else if (number == 3) {
        require(details.has_ipv4_addresses && details.ip_protocol == 17 &&
                !details.has_tcp_ports, "UDP must not have decoded TCP ports");
    } else if (number == 4) {
        require(header.caplen < header.len &&
                has_notice(details, "Truncated Ethernet header"),
                "Truncated Ethernet capture should be diagnosed");
    } else if (number == 5) {
        require(header.caplen < header.len &&
                has_notice(details, "Truncated IPv4 header"),
                "Truncated IPv4 capture should be diagnosed");
    } else if (number == 6) {
        require(header.caplen < header.len && details.has_ipv4_addresses &&
                !details.has_tcp_ports &&
                has_notice(details, "Truncated TCP header"),
                "Truncated TCP capture should not decode incomplete ports");
    } else if (number == 7) {
        require(!details.has_tcp_ports &&
                has_notice(details, "Invalid TCP data offset"),
                "Malformed TCP header should be diagnosed");
    } else if (number == 8) {
        require(details.has_tcp_ports && details.source_port == 1234 &&
                details.destination_port == 8080,
                "VLAN-tagged TCP packet should decode correctly");
    } else if (number == 9) {
        require(!details.has_ipv4_addresses &&
                has_notice(details, "Skipping non-IPv4 Ethernet frame"),
                "IPv6 Ethernet frame should not be parsed as IPv4");
    } else if (number == 10) {
        require(details.has_ipv4_addresses && !details.has_tcp_ports &&
                has_notice(details, "Fragmented IPv4 packet"),
                "Fragmented IPv4 must not expose TCP ports without reassembly");
    } else if (number == 11) {
        require(!details.has_ipv4_addresses &&
                has_notice(details, "Invalid or unsupported IPv4 header"),
                "Malformed IPv4 header size should be diagnosed");
    } else if (number == 12) {
        require(!details.has_ipv4_addresses &&
                has_notice(details, "Invalid IPv4 total length"),
                "Inconsistent IPv4 length should be diagnosed");
    }
}

} // namespace

int main(int argc, char* argv[]) {
    require(argc == 2, "Pass the synthetic PCAP fixture path as one argument");

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    std::unique_ptr<pcap_t, decltype(&pcap_close)> capture(
        pcap_open_offline(argv[1], error_buffer), &pcap_close);
    require(static_cast<bool>(capture),
            std::string("Could not open offline fixture: ") + error_buffer);
    const int link_type = pcap_datalink(capture.get());
    require(link_type == DLT_EN10MB, "Fixture must contain Ethernet frames");

    bpf_program program{};
    require(pcap_compile(capture.get(), &program, "tcp port 8765",
                         1, PCAP_NETMASK_UNKNOWN) == 0,
            std::string("Failed to compile offline BPF: ") + pcap_geterr(capture.get()));

    std::size_t total = 0;
    std::size_t matching = 0;
    pcap_pkthdr* header = nullptr;
    const unsigned char* bytes = nullptr;
    int status = 0;
    while ((status = pcap_next_ex(capture.get(), &header, &bytes)) == 1) {
        ++total;
        const PacketDetails details =
            PacketParser::parse(link_type, bytes, header->caplen);
        inspect_record(total, *header, bytes, details);

        if (pcap_offline_filter(&program, header, bytes) != 0) {
            ++matching;
            // BPF can match port bytes even when our parser rejects a short TCP header.
            require(total == 1 || total == 2 || total == 6,
                    "BPF selected an unrelated packet");
        }
    }
    pcap_freecode(&program);
    require(status == PCAP_ERROR_BREAK,
            std::string("PCAP read failed: ") + pcap_geterr(capture.get()));
    require(total == 12, "Fixture must contain all twelve expected records");
    require(matching == 3,
            "BPF should match two valid TCP packets and the truncated TCP record");

    std::cout << "Offline PCAP regression tests passed (12 packets, 3 BPF matches).\n";
}
