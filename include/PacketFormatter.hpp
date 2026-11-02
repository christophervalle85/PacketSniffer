#pragma once

#include "PacketParser.hpp"
#include <pcap.h>
#include <iosfwd>

namespace packetsniffer {
class PacketFormatter {
public:
    static void print(std::ostream& out, const pcap_pkthdr& header,
                      const unsigned char* packet,
                      const PacketDetails& details, bool show_hex);
};
} // namespace packetsniffer
