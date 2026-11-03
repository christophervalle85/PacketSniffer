// Small regression checks for Phase 1 packet parsing safety.
// The real entry point is renamed so the callback can be tested with synthetic bytes.
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define main packetsniffer_application_main
#include "../packetSniffer.cpp"
#undef main

namespace {

std::vector<unsigned char> ipv4_tcp() {
    std::vector<unsigned char> bytes(40, 0);
    bytes[0] = 0x45;                // IPv4 with a 20-byte header
    bytes[3] = 40;                  // Declared IPv4 length
    bytes[9] = IPPROTO_TCP;
    bytes[12] = 127;
    bytes[15] = 1;                 // 127.0.0.1
    bytes[16] = 127;
    bytes[19] = 1;
    bytes[20] = 0x1f;
    bytes[21] = 0x90;               // TCP source port 8080
    bytes[22] = 0x00;
    bytes[23] = 0x50;               // TCP destination port 80
    bytes[32] = 0x50;               // TCP data offset: 20 bytes
    return bytes;
}

std::vector<unsigned char> ethernet(const std::vector<unsigned char>& ip) {
    std::vector<unsigned char> frame(14, 0);
    frame[12] = 0x08;               // EtherType IPv4
    frame[13] = 0x00;
    frame.insert(frame.end(), ip.begin(), ip.end());
    return frame;
}

std::string inspect(int data_link_type, const std::vector<unsigned char>& data,
                    std::uint32_t original_length = 0) {
    pcap_pkthdr header{};
    header.caplen = static_cast<bpf_u_int32>(data.size());
    header.len = original_length ? original_length : header.caplen;
    CaptureContext context{data_link_type};
    std::ostringstream output;
    std::streambuf* previous = std::cout.rdbuf(output.rdbuf());
    packet_handler(reinterpret_cast<unsigned char*>(&context), &header, data.data());
    std::cout.rdbuf(previous);
    return output.str();
}

void includes(const std::string& actual, const std::string& expected) {
    if (actual.find(expected) == std::string::npos) {
        std::cerr << "Expected: " << expected << "\nActual output:\n" << actual;
        std::abort();
    }
}

void excludes(const std::string& actual, const std::string& unexpected) {
    if (actual.find(unexpected) != std::string::npos) {
        std::cerr << "Unexpected: " << unexpected << "\nActual output:\n" << actual;
        std::abort();
    }
}

}  // namespace

int main() {
    const auto ip = ipv4_tcp();
    const auto frame = ethernet(ip);

    // A normal Ethernet/IPv4/TCP frame yields the expected addresses and ports.
    auto output = inspect(DLT_EN10MB, frame);
    includes(output, "Source IP: 127.0.0.1");
    includes(output, "Source Port: 8080");
    includes(output, "Destination Port: 80");

    // A 1500-byte packet captured with only 18 bytes cannot be parsed past caplen.
    output = inspect(DLT_EN10MB, std::vector<unsigned char>(frame.begin(), frame.begin() + 18), 1500);
    includes(output, "Truncated IPv4 header.");
    includes(output, "Captured length: 18 bytes");
    excludes(output, "Source IP:");

    // Truncated Ethernet/VLAN headers must not read past the buffer.
    output = inspect(DLT_EN10MB, std::vector<unsigned char>(3, 0), 100);
    includes(output, "Truncated Ethernet header.");
    auto vlan = std::vector<unsigned char>(14, 0);
    vlan[12] = 0x81;
    vlan[13] = 0x00;
    output = inspect(DLT_EN10MB, vlan);
    includes(output, "Truncated VLAN header.");

    // A tagged Ethernet frame should still find IPv4 at the right offset.
    vlan.push_back(0x00);
    vlan.push_back(0x01);
    vlan.push_back(0x08);
    vlan.push_back(0x00);
    vlan.insert(vlan.end(), ip.begin(), ip.end());
    output = inspect(DLT_EN10MB, vlan);
    includes(output, "Source Port: 8080");

    // Loopback with a native-endian AF_INET family and raw IPv4 both parse.
    std::vector<unsigned char> loopback(4);
    const std::uint32_t family = AF_INET;
    std::memcpy(loopback.data(), &family, sizeof(family));
    loopback.insert(loopback.end(), ip.begin(), ip.end());
    includes(inspect(DLT_NULL, loopback), "Source Port: 8080");
    includes(inspect(DLT_RAW, ip), "Source Port: 8080");

    // Reject an invalid IP header length and inconsistent IP total length.
    auto malformed = ip;
    malformed[0] = 0x44;
    includes(inspect(DLT_RAW, malformed), "Invalid or unsupported IPv4 header.");
    malformed = ip;
    malformed[3] = 10;
    includes(inspect(DLT_RAW, malformed), "Invalid IPv4 total length.");

    // TCP header access must honor both the captured and declared IP lengths.
    output = inspect(DLT_RAW, std::vector<unsigned char>(ip.begin(), ip.begin() + 20), 40);
    includes(output, "Truncated TCP header.");
    malformed = ip;
    malformed[32] = 0x40;
    includes(inspect(DLT_RAW, malformed), "Invalid TCP data offset.");

    // Fragmented IPv4 datagrams are not interpreted as complete TCP headers.
    malformed = ip;
    malformed[6] = 0x20;
    output = inspect(DLT_RAW, malformed);
    includes(output, "Fragmented IPv4 packet");
    excludes(output, "Source Port:");

    // Missing arguments should exit before attempting to open a device.
    char program[] = "packetSniffer";
    char* argv[] = {program, nullptr};
    assert(packetsniffer_application_main(1, argv) != 0);

    std::cout << "Phase 1 packet parser smoke tests passed.\n";
}
