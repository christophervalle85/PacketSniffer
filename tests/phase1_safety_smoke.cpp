// Offline regression tests for malformed and truncated packet handling.
#include "PacketFormatter.hpp"
#include "PacketParser.hpp"

#include <pcap.h>
#include <netinet/in.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using packetsniffer::PacketFormatter;
using packetsniffer::PacketParser;

namespace {

std::vector<unsigned char> ipv4_tcp() {
    std::vector<unsigned char> bytes(40, 0);
    bytes[0] = 0x45;             // IPv4, 20-byte header
    bytes[3] = 40;               // IPv4 total length
    bytes[9] = IPPROTO_TCP;
    bytes[12] = 127;
    bytes[15] = 1;
    bytes[16] = 127;
    bytes[19] = 1;
    bytes[20] = 0x1f;
    bytes[21] = 0x90;            // 8080
    bytes[22] = 0x00;
    bytes[23] = 0x50;            // 80
    bytes[32] = 0x50;            // TCP header = 20 bytes
    return bytes;
}

std::vector<unsigned char> ethernet(const std::vector<unsigned char>& ip) {
    std::vector<unsigned char> frame(14, 0);
    frame[12] = 0x08;            // Ethernet EtherType: IPv4
    frame[13] = 0x00;
    frame.insert(frame.end(), ip.begin(), ip.end());
    return frame;
}

std::string inspect(int link_type, const std::vector<unsigned char>& data,
                    std::uint32_t original_length = 0, bool show_hex = false) {
    pcap_pkthdr header{};
    header.caplen = static_cast<bpf_u_int32>(data.size());
    header.len = original_length ? original_length : header.caplen;
    const auto details = PacketParser::parse(link_type, data.data(), data.size());
    std::ostringstream output;
    PacketFormatter::print(output, header, data.data(), details, show_hex);
    return output.str();
}

void includes(const std::string& value, const std::string& expected) {
    if (value.find(expected) == std::string::npos) {
        std::cerr << "Expected: " << expected << "\nActual:\n" << value;
        std::abort();
    }
}
void excludes(const std::string& value, const std::string& expected) {
    if (value.find(expected) != std::string::npos) {
        std::cerr << "Unexpected: " << expected << "\nActual:\n" << value;
        std::abort();
    }
}

} // namespace

int main() {
    const auto ip = ipv4_tcp();
    const auto frame = ethernet(ip);

    auto output = inspect(DLT_EN10MB, frame);
    includes(output, "Source IP: 127.0.0.1");
    includes(output, "Source Port: 8080");
    includes(output, "Destination Port: 80");
    excludes(output, "Packet bytes (hex and ASCII");
    includes(inspect(DLT_EN10MB, frame, 0, true), "Packet bytes (hex and ASCII");

    output = inspect(DLT_EN10MB,
                     std::vector<unsigned char>(frame.begin(), frame.begin() + 18),
                     1500);
    includes(output, "Truncated IPv4 header.");
    includes(output, "Captured length: 18 bytes");
    excludes(output, "Source IP:");

    includes(inspect(DLT_EN10MB, std::vector<unsigned char>(3, 0), 100),
             "Truncated Ethernet header.");
    auto vlan = std::vector<unsigned char>(14, 0);
    vlan[12] = 0x81;
    vlan[13] = 0x00;
    includes(inspect(DLT_EN10MB, vlan), "Truncated VLAN header.");
    vlan.push_back(0x00);
    vlan.push_back(0x01);
    vlan.push_back(0x08);
    vlan.push_back(0x00);
    vlan.insert(vlan.end(), ip.begin(), ip.end());
    includes(inspect(DLT_EN10MB, vlan), "Source Port: 8080");

    std::vector<unsigned char> loopback(4);
    const std::uint32_t family = AF_INET;
    std::memcpy(loopback.data(), &family, sizeof(family));
    loopback.insert(loopback.end(), ip.begin(), ip.end());
    includes(inspect(DLT_NULL, loopback), "Source Port: 8080");
    includes(inspect(DLT_RAW, ip), "Source Port: 8080");

    auto bad = ip;
    bad[0] = 0x44;
    includes(inspect(DLT_RAW, bad), "Invalid or unsupported IPv4 header.");
    bad = ip;
    bad[3] = 10;
    includes(inspect(DLT_RAW, bad), "Invalid IPv4 total length.");
    includes(inspect(DLT_RAW, std::vector<unsigned char>(ip.begin(), ip.begin()+20), 40),
             "Truncated TCP header.");
    bad = ip;
    bad[32] = 0x40;
    includes(inspect(DLT_RAW, bad), "Invalid TCP data offset.");
    bad = ip;
    bad[6] = 0x20;
    output = inspect(DLT_RAW, bad);
    includes(output, "Fragmented IPv4 packet");
    excludes(output, "Source Port:");

    assert(!PacketParser::supports_link_type(-999));
    const auto missing = PacketParser::parse(DLT_RAW, nullptr, 0);
    includes(missing.notices.front(), "Missing packet buffer.");
    std::cout << "Packet parser smoke tests passed.\n";
}
