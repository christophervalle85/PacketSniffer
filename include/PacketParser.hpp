#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packetsniffer {

struct PacketDetails {
    bool has_mac_addresses = false;
    std::array<unsigned char, 6> source_mac{};
    std::array<unsigned char, 6> destination_mac{};

    bool has_ipv4_addresses = false;
    std::string source_ip;
    std::string destination_ip;
    std::uint8_t ip_protocol = 0;

    bool has_tcp_ports = false;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;

    std::vector<std::string> notices;
};

class PacketParser {
public:
    static bool supports_link_type(int link_type);
    static PacketDetails parse(int link_type, const unsigned char* packet,
                               std::size_t captured_length);
};

} // namespace packetsniffer
