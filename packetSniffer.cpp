#include <pcap.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <string>
#include <cctype>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

namespace {

constexpr std::size_t ETHERNET_HEADER_LENGTH = 14;
constexpr std::size_t IPV4_MIN_HEADER_LENGTH = 20;
constexpr std::size_t TCP_MIN_HEADER_LENGTH = 20;
constexpr int SNAP_LENGTH = 65535;

struct CaptureContext {
    int data_link_type;
    bool show_hex = false;
};

struct Options {
    std::string device;
    std::string filter;
    int count = 0;               // 0 means capture until interrupted.
    bool show_hex = false;
};

enum class ParseResult { ok, help, error };

void print_usage(const char* program, std::ostream& out) {
    out << "Usage: " << program << " [options] <network-interface>\n"
        << "       " << program << " -i <network-interface> [options]\n\n"
        << "Options:\n"
        << "  -i, --interface <name>  Network interface (e.g. lo0 on macOS)\n"
        << "  -f, --filter <expr>     BPF filter (e.g. 'tcp port 8765')\n"
        << "  -c, --count <number>   Stop after this many matching packets\n"
        << "  -x, --hex              Print packet bytes in hex and ASCII\n"
        << "  -h, --help             Show this help message\n"
        << "\nUse only network interfaces you're authorized to monitor.\n";
}

bool parse_positive_count(const char* value, int& result) {
    if (value == nullptr || *value == '\0') return false;
    errno = 0;
    char* end = nullptr;
    const long count = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        count <= 0 || count > INT_MAX) {
        return false;
    }
    result = static_cast<int>(count);
    return true;
}

ParseResult parse_arguments(int argc, char* argv[], Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "-h" || argument == "--help") {
            return ParseResult::help;
        }
        if (argument == "-x" || argument == "--hex") {
            options.show_hex = true;
            continue;
        }
        if (argument == "-i" || argument == "--interface") {
            if (!options.device.empty() || i + 1 >= argc ||
                argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
                std::cerr << "Invalid or duplicate interface argument.\n";
                return ParseResult::error;
            }
            options.device = argv[++i];
            continue;
        }
        if (argument == "-f" || argument == "--filter") {
            if (!options.filter.empty() || i + 1 >= argc ||
                argv[i + 1][0] == '\0') {
                std::cerr << "Missing or duplicate packet filter.\n";
                return ParseResult::error;
            }
            options.filter = argv[++i];
            continue;
        }
        if (argument == "-c" || argument == "--count") {
            if (options.count != 0 || i + 1 >= argc ||
                !parse_positive_count(argv[i + 1], options.count)) {
                std::cerr << "Packet count must be a positive integer.\n";
                return ParseResult::error;
            }
            ++i;
            continue;
        }
        if (!argument.empty() && argument[0] == '-') {
            std::cerr << "Unknown option: " << argument << '\n';
            return ParseResult::error;
        }
        if (!options.device.empty()) {
            std::cerr << "Only one interface can be specified.\n";
            return ParseResult::error;
        }
        options.device = argument;  // Preserve ./packetSniffer lo0 syntax.
    }
    if (options.device.empty()) {
        std::cerr << "A network interface is required.\n";
        return ParseResult::error;
    }
    return ParseResult::ok;
}

// pcap_breakloop() can be called from a signal handler on supported Unix systems.
pcap_t* volatile active_capture = nullptr;

void stop_capture(int) {
    if (active_capture != nullptr) {
        pcap_breakloop(active_capture);
    }
}

std::uint16_t read_be16(const unsigned char* data) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

std::uint32_t read_be32(const unsigned char* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

void print_mac(const unsigned char* mac) {
    const auto previous_flags = std::cout.flags();
    const auto previous_fill = std::cout.fill();
    for (std::size_t i = 0; i < 6; ++i) {
        if (i != 0) std::cout << ':';
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned int>(mac[i]);
    }
    std::cout.flags(previous_flags);
    std::cout.fill(previous_fill);
}

bool supported_link_type(int data_link_type) {
    switch (data_link_type) {
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

// Only return an IPv4 offset when the complete link-layer header is captured.
bool get_ipv4_offset(int data_link_type, const unsigned char* packet,
                     std::size_t captured_length, std::size_t& ip_offset) {
    ip_offset = 0;
    switch (data_link_type) {
        case DLT_EN10MB: {
            if (captured_length < ETHERNET_HEADER_LENGTH) {
                std::cout << "Truncated Ethernet header.\n";
                return false;
            }
            std::cout << "Source MAC: ";
            print_mac(packet + 6);
            std::cout << "\nDestination MAC: ";
            print_mac(packet);
            std::cout << '\n';

            std::uint16_t ether_type = read_be16(packet + 12);
            ip_offset = ETHERNET_HEADER_LENGTH;
            // An Ethernet frame may have one or more 802.1Q/802.1ad VLAN tags.
            while (ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100) {
                if (captured_length - ip_offset < 4) {
                    std::cout << "Truncated VLAN header.\n";
                    return false;
                }
                ether_type = read_be16(packet + ip_offset + 2);
                ip_offset += 4;
            }
            if (ether_type != 0x0800) {
                std::cout << "Skipping non-IPv4 Ethernet frame.\n";
                return false;
            }
            return true;
        }
        case DLT_NULL:
        case DLT_LOOP: {
            if (captured_length < 4) {
                std::cout << "Truncated loopback header.\n";
                return false;
            }
            std::uint32_t family = 0;
            if (data_link_type == DLT_NULL) {
                // DLT_NULL stores the address family in host byte order.
                std::memcpy(&family, packet, sizeof(family));
            } else {
                // DLT_LOOP stores the address family in network byte order.
                family = read_be32(packet);
            }
            if (family != AF_INET) {
                std::cout << "Skipping non-IPv4 loopback packet.\n";
                return false;
            }
            ip_offset = 4;
            return true;
        }
        case DLT_RAW:
            return true;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if (captured_length < 16) {
                std::cout << "Truncated Linux cooked header.\n";
                return false;
            }
            if (read_be16(packet + 14) != 0x0800) {
                std::cout << "Skipping non-IPv4 cooked packet.\n";
                return false;
            }
            ip_offset = 16;
            return true;
#endif
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2:
            if (captured_length < 20) {
                std::cout << "Truncated Linux cooked v2 header.\n";
                return false;
            }
            if (read_be16(packet) != 0x0800) {
                std::cout << "Skipping non-IPv4 cooked packet.\n";
                return false;
            }
            ip_offset = 20;
            return true;
#endif
        default:
            std::cout << "Unsupported data link type: " << data_link_type << '\n';
            return false;
    }
}

void print_ipv4_and_tcp(const unsigned char* packet, std::size_t captured_length,
                        std::size_t ip_offset) {
    if (ip_offset > captured_length ||
        captured_length - ip_offset < IPV4_MIN_HEADER_LENGTH) {
        std::cout << "Truncated IPv4 header.\n";
        return;
    }

    const unsigned char* ip = packet + ip_offset;
    const std::size_t available = captured_length - ip_offset;
    const unsigned int version = ip[0] >> 4;
    const std::size_t ip_header_length = static_cast<std::size_t>(ip[0] & 0x0f) * 4;
    if (version != 4 || ip_header_length < IPV4_MIN_HEADER_LENGTH) {
        std::cout << "Invalid or unsupported IPv4 header.\n";
        return;
    }
    if (available < ip_header_length) {
        std::cout << "Truncated IPv4 options/header.\n";
        return;
    }

    const std::size_t ip_total_length = read_be16(ip + 2);
    if (ip_total_length < ip_header_length) {
        std::cout << "Invalid IPv4 total length.\n";
        return;
    }

    char source_ip[INET_ADDRSTRLEN] = {};
    char destination_ip[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, ip + 12, source_ip, sizeof(source_ip)) == nullptr ||
        inet_ntop(AF_INET, ip + 16, destination_ip, sizeof(destination_ip)) == nullptr) {
        std::cout << "Failed to format IPv4 addresses.\n";
        return;
    }
    std::cout << "Source IP: " << source_ip << '\n';
    std::cout << "Destination IP: " << destination_ip << '\n';
    std::cout << "IP protocol: " << static_cast<unsigned int>(ip[9]) << '\n';

    if (available < ip_total_length) {
        std::cout << "Note: IPv4 packet is truncated in this capture.\n";
    }

    // Fragmented datagrams require reassembly before safe transport parsing.
    if ((read_be16(ip + 6) & 0x3fff) != 0) {
        std::cout << "Fragmented IPv4 packet; skipping transport header.\n";
        return;
    }
    if (ip[9] != IPPROTO_TCP) {
        return;
    }

    const std::size_t ip_payload_length = ip_total_length - ip_header_length;
    const std::size_t captured_payload_length =
        std::min(available, ip_total_length) - ip_header_length;
    if (ip_payload_length < TCP_MIN_HEADER_LENGTH) {
        std::cout << "Invalid TCP length in IPv4 packet.\n";
        return;
    }
    if (captured_payload_length < TCP_MIN_HEADER_LENGTH) {
        std::cout << "Truncated TCP header.\n";
        return;
    }

    const unsigned char* tcp = ip + ip_header_length;
    const std::size_t tcp_header_length = static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (tcp_header_length < TCP_MIN_HEADER_LENGTH ||
        tcp_header_length > ip_payload_length) {
        std::cout << "Invalid TCP data offset.\n";
        return;
    }
    if (tcp_header_length > captured_payload_length) {
        std::cout << "Truncated TCP options/header.\n";
        return;
    }
    std::cout << "Source Port: " << read_be16(tcp) << '\n';
    std::cout << "Destination Port: " << read_be16(tcp + 2) << '\n';
}

void print_packet_bytes(const unsigned char* packet, std::size_t captured_length) {
    const auto previous_flags = std::cout.flags();
    const auto previous_fill = std::cout.fill();
    std::cout << "Packet bytes (hex and ASCII, captured bytes only):\n";
    for (std::size_t offset = 0; offset < captured_length; offset += 16) {
        std::cout << std::hex << std::setfill('0') << std::setw(4) << offset << "  ";
        for (std::size_t j = 0; j < 16; ++j) {
            if (offset + j < captured_length) {
                std::cout << std::setw(2) << static_cast<unsigned int>(packet[offset + j])
                          << ' ';
            } else {
                std::cout << "   ";
            }
        }
        std::cout << " |";
        for (std::size_t j = 0; j < 16 && offset + j < captured_length; ++j) {
            const unsigned char byte = packet[offset + j];
            std::cout << (std::isprint(byte) ? static_cast<char>(byte) : '.');
        }
        std::cout << "|\n";
    }
    std::cout.flags(previous_flags);
    std::cout.fill(previous_fill);
}

void packet_handler(unsigned char* user_data, const pcap_pkthdr* header,
                    const unsigned char* packet) {
    if (user_data == nullptr || header == nullptr || packet == nullptr) return;
    const auto* context = reinterpret_cast<const CaptureContext*>(user_data);
    const std::size_t captured_length = header->caplen;

    std::cout << "\n----------------- Packet Captured -----------------\n";
    std::cout << "Original length: " << header->len << " bytes\n";
    std::cout << "Captured length: " << captured_length << " bytes\n";
    std::size_t ip_offset = 0;
    if (get_ipv4_offset(context->data_link_type, packet, captured_length, ip_offset)) {
        print_ipv4_and_tcp(packet, captured_length, ip_offset);
    }
    if (context->show_hex) {
        print_packet_bytes(packet, captured_length);
    }
    std::cout << "------------------- Packet End -------------------\n";
}

void print_interface_address(const char* device) {
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) {
        std::cerr << "Warning: could not list local interface addresses.\n";
        return;
    }
    for (const ifaddrs* current = interfaces; current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr || current->ifa_addr->sa_family != AF_INET ||
            std::strcmp(current->ifa_name, device) != 0) {
            continue;
        }
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(current->ifa_addr);
        char address[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &ipv4->sin_addr, address, sizeof(address)) != nullptr) {
            std::cout << "Your IPv4 address on " << device << ": " << address << '\n';
        }
    }
    freeifaddrs(interfaces);
}

}  // namespace

int main(int argc, char* argv[]) {
    Options options;
    const ParseResult parsed = parse_arguments(argc, argv, options);
    if (parsed == ParseResult::help) {
        print_usage(argv[0], std::cout);
        return 0;
    }
    if (parsed == ParseResult::error) {
        print_usage(argv[0], std::cerr);
        return 1;
    }

    print_interface_address(options.device.c_str());

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    // Promiscuous mode is off; the selected interface is the only capture source.
    pcap_t* handle = pcap_open_live(options.device.c_str(), SNAP_LENGTH, 0,
                                    1000, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Could not open interface '" << options.device
                  << "': " << error_buffer << '\n';
        return 1;
    }

    const int data_link_type = pcap_datalink(handle);
    if (!supported_link_type(data_link_type)) {
        std::cerr << "Unsupported link-layer type " << data_link_type
                  << ". Use an Ethernet, loopback, raw IP, or Linux cooked interface.\n";
        pcap_close(handle);
        return 1;
    }

    if (!options.filter.empty()) {
        bpf_program compiled_filter{};
        if (pcap_compile(handle, &compiled_filter, options.filter.c_str(),
                         1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
            std::cerr << "Invalid capture filter: " << pcap_geterr(handle) << '\n';
            pcap_close(handle);
            return 1;
        }
        const int filter_result = pcap_setfilter(handle, &compiled_filter);
        pcap_freecode(&compiled_filter);
        if (filter_result == PCAP_ERROR) {
            std::cerr << "Could not apply capture filter: " << pcap_geterr(handle) << '\n';
            pcap_close(handle);
            return 1;
        }
    }

    const char* link_type_name = pcap_datalink_val_to_name(data_link_type);
    std::cout << "Capturing on " << options.device << " ("
              << (link_type_name != nullptr ? link_type_name : "unknown")
              << "), promiscuous mode off.\n";
    if (!options.filter.empty()) {
        std::cout << "Filter: " << options.filter << '\n';
    }
    if (options.count > 0) {
        std::cout << "Packet limit: " << options.count << '\n';
    } else {
        std::cout << "Press Ctrl-C to stop.\n";
    }
    std::cout << "Packet hex/ASCII dump: "
              << (options.show_hex ? "enabled" : "disabled (use --hex)") << '\n';

    CaptureContext context{data_link_type, options.show_hex};
    active_capture = handle;
    const auto previous_signal_handler = std::signal(SIGINT, stop_capture);
    const int result = pcap_loop(handle, options.count, packet_handler,
                                 reinterpret_cast<unsigned char*>(&context));
    active_capture = nullptr;
    std::signal(SIGINT, previous_signal_handler);

    if (result == PCAP_ERROR) {
        std::cerr << "Capture failed: " << pcap_geterr(handle) << '\n';
    }
    pcap_close(handle);
    return result == PCAP_ERROR ? 1 : 0;
}
