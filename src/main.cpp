#include "CliOptions.hpp"
#include "PacketCapture.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
    packetsniffer::Options options;
    const auto result =
        packetsniffer::parse_arguments(argc, argv, options, std::cerr);
    if (result == packetsniffer::ParseResult::help) {
        packetsniffer::print_usage(argv[0], std::cout);
        return 0;
    }
    if (result == packetsniffer::ParseResult::error) {
        packetsniffer::print_usage(argv[0], std::cerr);
        return 1;
    }
    return packetsniffer::PacketCapture::run(options);
}
