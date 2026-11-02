#include "PacketParser.hpp"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace packetsniffer {
namespace {

constexpr std::size_t ETHERNET_HEADER_LENGTH = 14;
constexpr std::size_t IPV4_MIN_HEADER_LENGTH = 20;
constexpr std::size_t TCP_MIN_HEADER_LENGTH = 20;

std::uint16_t read_be16(const unsigned char* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

std::uint32_t read_be32(const unsigned char* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

bool get_ipv4_offset(int link_type, const unsigned char* packet,
                     std::size_t length, PacketDetails& details,
                     std::size_t& offset) {
    offset = 0;
    switch (link_type) {
        case DLT_EN10MB: {
            if (length < ETHERNET_HEADER_LENGTH) {
                details.notices.emplace_back("Truncated Ethernet header.");
                return false;
            }
            details.has_mac_addresses = true;
            std::copy_n(packet, 6, details.destination_mac.begin());
            std::copy_n(packet + 6, 6, details.source_mac.begin());
            std::uint16_t ether_type = read_be16(packet + 12);
            offset = ETHERNET_HEADER_LENGTH;
            while (ether_type == 0x8100 || ether_type == 0x88a8 ||
                   ether_type == 0x9100) {
                if (length - offset < 4) {
                    details.notices.emplace_back("Truncated VLAN header.");
                    return false;
                }
                ether_type = read_be16(packet + offset + 2);
                offset += 4;
            }
            if (ether_type != 0x0800) {
                details.notices.emplace_back("Skipping non-IPv4 Ethernet frame.");
                return false;
            }
            return true;
        }
        case DLT_NULL:
        case DLT_LOOP: {
            if (length < 4) {
                details.notices.emplace_back("Truncated loopback header.");
                return false;
            }
            std::uint32_t family = 0;
            if (link_type == DLT_NULL) {
                // DLT_NULL uses host byte order; DLT_LOOP uses network byte order.
                std::memcpy(&family, packet, sizeof(family));
            } else {
                family = read_be32(packet);
            }
            if (family != AF_INET) {
                details.notices.emplace_back("Skipping non-IPv4 loopback packet.");
                return false;
            }
            offset = 4;
            return true;
        }
        case DLT_RAW:
            return true;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if (length < 16) {
                details.notices.emplace_back("Truncated Linux cooked header.");
                return false;
            }
            if (read_be16(packet + 14) != 0x0800) {
                details.notices.emplace_back("Skipping non-IPv4 cooked packet.");
                return false;
            }
            offset = 16;
            return true;
#endif
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2:
            if (length < 20) {
                details.notices.emplace_back("Truncated Linux cooked v2 header.");
                return false;
            }
            if (read_be16(packet) != 0x0800) {
                details.notices.emplace_back("Skipping non-IPv4 cooked packet.");
                return false;
            }
            offset = 20;
            return true;
#endif
        default:
            details.notices.emplace_back("Unsupported link-layer type.");
            return false;
    }
}

void parse_ipv4(const unsigned char* packet, std::size_t captured_length,
                std::size_t offset, PacketDetails& details) {
    if (offset > captured_length ||
        captured_length - offset < IPV4_MIN_HEADER_LENGTH) {
        details.notices.emplace_back("Truncated IPv4 header.");
        return;
    }

    const unsigned char* ip = packet + offset;
    const std::size_t available = captured_length - offset;
    const unsigned int version = ip[0] >> 4;
    const std::size_t ip_header_length =
        static_cast<std::size_t>(ip[0] & 0x0f) * 4;
    if (version != 4 || ip_header_length < IPV4_MIN_HEADER_LENGTH) {
        details.notices.emplace_back("Invalid or unsupported IPv4 header.");
        return;
    }
    if (available < ip_header_length) {
        details.notices.emplace_back("Truncated IPv4 options/header.");
        return;
    }

    const std::size_t ip_total_length = read_be16(ip + 2);
    if (ip_total_length < ip_header_length) {
        details.notices.emplace_back("Invalid IPv4 total length.");
        return;
    }

    char source_ip[INET_ADDRSTRLEN] = {};
    char destination_ip[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, ip + 12, source_ip, sizeof(source_ip)) == nullptr ||
        inet_ntop(AF_INET, ip + 16, destination_ip, sizeof(destination_ip)) == nullptr) {
        details.notices.emplace_back("Failed to format IPv4 addresses.");
        return;
    }
    details.has_ipv4_addresses = true;
    details.source_ip = source_ip;
    details.destination_ip = destination_ip;
    details.ip_protocol = ip[9];

    if (available < ip_total_length) {
        details.notices.emplace_back("Note: IPv4 packet is truncated in this capture.");
    }

    if ((read_be16(ip + 6) & 0x3fff) != 0) {
        details.notices.emplace_back(
            "Fragmented IPv4 packet; skipping transport header.");
        return;
    }
    if (ip[9] != IPPROTO_TCP) return;

    const std::size_t ip_payload_length = ip_total_length - ip_header_length;
    const std::size_t captured_payload_length =
        std::min(available, ip_total_length) - ip_header_length;
    if (ip_payload_length < TCP_MIN_HEADER_LENGTH) {
        details.notices.emplace_back("Invalid TCP length in IPv4 packet.");
        return;
    }
    if (captured_payload_length < TCP_MIN_HEADER_LENGTH) {
        details.notices.emplace_back("Truncated TCP header.");
        return;
    }

    const unsigned char* tcp = ip + ip_header_length;
    const std::size_t tcp_header_length =
        static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (tcp_header_length < TCP_MIN_HEADER_LENGTH ||
        tcp_header_length > ip_payload_length) {
        details.notices.emplace_back("Invalid TCP data offset.");
        return;
    }
    if (tcp_header_length > captured_payload_length) {
        details.notices.emplace_back("Truncated TCP options/header.");
        return;
    }
    details.has_tcp_ports = true;
    details.source_port = read_be16(tcp);
    details.destination_port = read_be16(tcp + 2);
}

} // namespace

bool PacketParser::supports_link_type(int link_type) {
    switch (link_type) {
        case DLT_EN10MB:
        case DLT_NULL:
        case DLT_LOOP:
        case DLT_RAW:
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
#endif
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2:
#endif
            return true;
        default:
            return false;
    }
}

PacketDetails PacketParser::parse(int link_type, const unsigned char* packet,
                                  std::size_t captured_length) {
    PacketDetails details;
    if (packet == nullptr) {
        details.notices.emplace_back("Missing packet buffer.");
        return details;
    }
    std::size_t offset = 0;
    if (get_ipv4_offset(link_type, packet, captured_length, details, offset)) {
        parse_ipv4(packet, captured_length, offset, details);
    }
    return details;
}

} // namespace packetsniffer
