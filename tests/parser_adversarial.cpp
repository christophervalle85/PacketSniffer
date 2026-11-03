// Deterministic malformed-input and captured-length regression tests.
// All test traffic is generated in memory; the tests do not open a network interface.
#include "PacketParser.hpp"

#include <pcap.h>
#include <netinet/in.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

using packetsniffer::PacketDetails;
using packetsniffer::PacketParser;

namespace {

void require(bool condition, const std::string& what) {
    if (!condition) throw std::runtime_error(what);
}

bool has_notice(const PacketDetails& details, const std::string& phrase) {
    for (const std::string& notice : details.notices) {
        if (notice.find(phrase) != std::string::npos) return true;
    }
    return false;
}

std::vector<unsigned char> make_tcp_frame() {
    std::vector<unsigned char> frame(14 + 20 + 20, 0);
    frame[12] = 0x08; // IPv4 EtherType
    frame[13] = 0x00;
    frame[14] = 0x45; // IPv4, no options
    frame[16] = 0;
    frame[17] = 40;   // IPv4 total length
    frame[22] = 64;   // TTL
    frame[23] = IPPROTO_TCP;
    frame[26] = frame[30] = 127; // 127.0.0.1 at both endpoints
    frame[29] = frame[33] = 1;
    frame[34] = 0xc0;
    frame[35] = 0x00; // source port 49152
    frame[36] = 0x22;
    frame[37] = 0x3d; // destination port 8765
    frame[46] = 0x50; // TCP data offset = 20 bytes
    return frame;
}

void test_all_prefixes(const std::vector<unsigned char>& frame) {
    // Every shorter captured prefix must be safe to inspect.
    for (std::size_t n = 0; n <= frame.size(); ++n) {
        const auto details = PacketParser::parse(DLT_EN10MB, frame.data(), n);
        require(details.has_tcp_ports == (n == frame.size()),
                "Ethernet prefix " + std::to_string(n) + " parsed an incomplete TCP header");
    }
    for (std::size_t n = 0; n <= frame.size() - 14; ++n) {
        const auto details = PacketParser::parse(DLT_RAW, frame.data() + 14, n);
        require(details.has_tcp_ports == (n == frame.size() - 14),
                "Raw IPv4 prefix " + std::to_string(n) + " parsed an incomplete TCP header");
    }
}

void test_loopback(const std::vector<unsigned char>& frame) {
    std::vector<unsigned char> native(4, 0);
    const std::uint32_t family = AF_INET;
    std::memcpy(native.data(), &family, 4);
    native.insert(native.end(), frame.begin() + 14, frame.end());
    require(PacketParser::parse(DLT_NULL, native.data(), native.size()).has_tcp_ports,
            "DLT_NULL should decode a complete native-endian IPv4/TCP packet");

    std::vector<unsigned char> network = native;
    network[0] = static_cast<unsigned char>((family >> 24) & 0xff);
    network[1] = static_cast<unsigned char>((family >> 16) & 0xff);
    network[2] = static_cast<unsigned char>((family >> 8) & 0xff);
    network[3] = static_cast<unsigned char>(family & 0xff);
    require(PacketParser::parse(DLT_LOOP, network.data(), network.size()).has_tcp_ports,
            "DLT_LOOP should decode a complete network-endian IPv4/TCP packet");
    for (std::size_t n = 0; n < 4; ++n) {
        require(!PacketParser::parse(DLT_NULL, native.data(), n).has_tcp_ports,
                "Truncated loopback family header must be rejected");
    }
}

void test_mutations(const std::vector<unsigned char>& original) {
    auto frame = original;
    frame[14] = 0x44;
    require(has_notice(PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()),
                       "Invalid or unsupported IPv4 header"),
            "Invalid IPv4 IHL must be rejected");

    frame = original;
    frame[16] = 0;
    frame[17] = 10;
    require(has_notice(PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()),
                       "Invalid IPv4 total length"),
            "IPv4 total length below IHL must be rejected");

    frame = original;
    frame[20] = 0x20; // More fragments flag
    require(!PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()).has_tcp_ports,
            "IPv4 fragments must not be treated as complete TCP segments");

    frame = original;
    frame[46] = 0x40; // Invalid TCP data offset < 20 bytes
    require(has_notice(PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()),
                       "Invalid TCP data offset"),
            "Invalid TCP data offset must be rejected");

    frame = original;
    frame[23] = IPPROTO_UDP;
    require(!PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()).has_tcp_ports,
            "UDP must not be treated as TCP");

    frame = original;
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame.insert(frame.begin() + 14, {0x00, 0x01, 0x08, 0x00});
    require(PacketParser::parse(DLT_EN10MB, frame.data(), frame.size()).has_tcp_ports,
            "Tagged Ethernet frame should decode TCP");

    const auto missing = PacketParser::parse(DLT_RAW, nullptr, 0);
    require(has_notice(missing, "Missing packet buffer"), "Null buffer must be rejected");
    require(!PacketParser::supports_link_type(-999), "Unknown link type must be unsupported");
}

void test_deterministic_fuzzing() {
    std::mt19937 random(0xC0FFEEu);
    std::uniform_int_distribution<int> size(0, 128);
    std::uniform_int_distribution<int> byte(0, 255);
    const std::array<int, 4> link_types = {DLT_EN10MB, DLT_NULL, DLT_LOOP, DLT_RAW};
    for (int iteration = 0; iteration < 12000; ++iteration) {
        std::vector<unsigned char> packet(static_cast<std::size_t>(size(random)));
        for (auto& value : packet) {
            value = static_cast<unsigned char>(byte(random));
        }
        const int link_type = link_types[static_cast<std::size_t>(iteration) % link_types.size()];
        const PacketDetails details =
            PacketParser::parse(link_type, packet.data(), packet.size());
        require(!details.has_tcp_ports || details.has_ipv4_addresses,
                "TCP ports must never appear without a valid IPv4 header");
    }
}

} // namespace

int main() {
    const auto frame = make_tcp_frame();
    test_all_prefixes(frame);
    test_loopback(frame);
    test_mutations(frame);
    test_deterministic_fuzzing();
    std::cout << "Adversarial parser regressions passed (12,000 seeded packets).\n";
}
