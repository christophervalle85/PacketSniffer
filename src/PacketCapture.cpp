#include "PacketCapture.hpp"
#include "PacketFormatter.hpp"
#include "PacketParser.hpp"

#include <pcap.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>

namespace packetsniffer {
namespace {

constexpr int SNAP_LENGTH = 65535;

// libpcap supports calling pcap_breakloop() from Unix signal handlers.
pcap_t* volatile active_capture = nullptr;

void stop_capture(int) {
    if (active_capture != nullptr) pcap_breakloop(active_capture);
}

struct CaptureContext {
    int data_link_type;
    bool show_hex;
};

void packet_handler(unsigned char* user_data, const pcap_pkthdr* header,
                    const unsigned char* packet) {
    if (user_data == nullptr || header == nullptr || packet == nullptr) return;
    const auto* context = reinterpret_cast<const CaptureContext*>(user_data);
    const PacketDetails details =
        PacketParser::parse(context->data_link_type, packet, header->caplen);
    PacketFormatter::print(std::cout, *header, packet, details, context->show_hex);
}

void print_interface_address(const char* device) {
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw) != 0) {
        std::cerr << "Warning: could not list local interface addresses.\n";
        return;
    }
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(
        raw, &freeifaddrs);

    for (const ifaddrs* current = interfaces.get();
         current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr ||
            current->ifa_addr->sa_family != AF_INET ||
            std::strcmp(current->ifa_name, device) != 0) continue;

        const auto* ipv4 =
            reinterpret_cast<const sockaddr_in*>(current->ifa_addr);
        char address[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &ipv4->sin_addr, address,
                      sizeof(address)) != nullptr) {
            std::cout << "Your IPv4 address on " << device
                      << ": " << address << '\n';
        }
    }
}

} // namespace

int PacketCapture::run(const Options& options) {
    print_interface_address(options.device.c_str());

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    // Capture from the chosen interface without promiscuous mode.
    const std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_open_live(options.device.c_str(), SNAP_LENGTH, 0, 1000,
                       error_buffer),
        &pcap_close);

    if (!handle) {
        std::cerr << "Could not open interface '" << options.device
                  << "': " << error_buffer << '\n';
        return 1;
    }
    const int link_type = pcap_datalink(handle.get());
    if (!PacketParser::supports_link_type(link_type)) {
        std::cerr << "Unsupported link-layer type " << link_type
                  << ". Use an Ethernet, loopback, raw IP, or Linux cooked interface.\n";
        return 1;
    }

    if (!options.filter.empty()) {
        bpf_program compiled_filter{};
        if (pcap_compile(handle.get(), &compiled_filter, options.filter.c_str(),
                         1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
            std::cerr << "Invalid capture filter: "
                      << pcap_geterr(handle.get()) << '\n';
            return 1;
        }
        const int status = pcap_setfilter(handle.get(), &compiled_filter);
        pcap_freecode(&compiled_filter);
        if (status == PCAP_ERROR) {
            std::cerr << "Could not apply capture filter: "
                      << pcap_geterr(handle.get()) << '\n';
            return 1;
        }
    }

    const char* link_type_name = pcap_datalink_val_to_name(link_type);
    std::cout << "Capturing on " << options.device << " ("
              << (link_type_name ? link_type_name : "unknown")
              << "), promiscuous mode off.\n";
    if (!options.filter.empty())
        std::cout << "Filter: " << options.filter << '\n';
    if (options.count > 0)
        std::cout << "Packet limit: " << options.count << '\n';
    else
        std::cout << "Press Ctrl-C to stop.\n";
    std::cout << "Packet hex/ASCII dump: "
              << (options.show_hex ? "enabled" : "disabled (use --hex)") << '\n';

    CaptureContext context{link_type, options.show_hex};
    active_capture = handle.get();
    const auto previous_handler = std::signal(SIGINT, stop_capture);
    const int result = pcap_loop(handle.get(), options.count, packet_handler,
                                 reinterpret_cast<unsigned char*>(&context));
    active_capture = nullptr;
    std::signal(SIGINT, previous_handler);

    if (result == PCAP_ERROR)
        std::cerr << "Capture failed: " << pcap_geterr(handle.get()) << '\n';
    return result == PCAP_ERROR ? 1 : 0;
}

} // namespace packetsniffer
