#include "PacketFormatter.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <iomanip>
#include <ostream>

namespace packetsniffer {
namespace {

void print_mac(std::ostream& out, const std::array<unsigned char, 6>& mac) {
    const auto flags = out.flags();
    const auto fill = out.fill();
    for (std::size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) out << ':';
        out << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned int>(mac[i]);
    }
    out.flags(flags);
    out.fill(fill);
}

void print_packet_bytes(std::ostream& out, const unsigned char* packet,
                        std::size_t captured_length) {
    const auto flags = out.flags();
    const auto fill = out.fill();
    out << "Packet bytes (hex and ASCII, captured bytes only):\n";
    for (std::size_t offset = 0; offset < captured_length; offset += 16) {
        out << std::hex << std::setfill('0') << std::setw(4) << offset << "  ";
        for (std::size_t j = 0; j < 16; ++j) {
            if (offset + j < captured_length) {
                out << std::setw(2)
                    << static_cast<unsigned int>(packet[offset + j]) << ' ';
            } else {
                out << "   ";
            }
        }
        out << " |";
        for (std::size_t j = 0; j < 16 && offset + j < captured_length; ++j) {
            const unsigned char byte = packet[offset + j];
            out << (std::isprint(byte) ? static_cast<char>(byte) : '.');
        }
        out << "|\n";
    }
    out.flags(flags);
    out.fill(fill);
}

} // namespace

void PacketFormatter::print(std::ostream& out, const pcap_pkthdr& header,
                            const unsigned char* packet,
                            const PacketDetails& details, bool show_hex) {
    out << "\n----------------- Packet Captured -----------------\n";
    out << "Original length: " << header.len << " bytes\n";
    out << "Captured length: " << header.caplen << " bytes\n";
    if (details.has_mac_addresses) {
        out << "Source MAC: ";
        print_mac(out, details.source_mac);
        out << "\nDestination MAC: ";
        print_mac(out, details.destination_mac);
        out << '\n';
    }
    if (details.has_ipv4_addresses) {
        out << "Source IP: " << details.source_ip << '\n';
        out << "Destination IP: " << details.destination_ip << '\n';
        out << "IP protocol: "
            << static_cast<unsigned int>(details.ip_protocol) << '\n';
    }
    if (details.has_tcp_ports) {
        out << "Source Port: " << details.source_port << '\n';
        out << "Destination Port: " << details.destination_port << '\n';
    }
    for (const auto& notice : details.notices) out << notice << '\n';
    if (show_hex && packet != nullptr) {
        print_packet_bytes(out, packet, header.caplen);
    }
    out << "------------------- Packet End -------------------\n";
}

} // namespace packetsniffer
