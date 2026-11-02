// CLI parsing tests that never open an interface or require sudo.
#include "CliOptions.hpp"

#include <cassert>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using packetsniffer::Options;
using packetsniffer::ParseResult;

namespace {

ParseResult parse(std::initializer_list<std::string> args, Options& options) {
    std::vector<std::string> strings(args);
    std::vector<char*> argv;
    for (auto& arg : strings) argv.push_back(arg.data());
    std::ostringstream expected_errors;
    return packetsniffer::parse_arguments(
        static_cast<int>(argv.size()), argv.data(), options, expected_errors);
}

} // namespace

int main() {
    Options options;
    assert(parse({"packetSniffer", "lo0"}, options) == ParseResult::ok);
    assert(options.device == "lo0");
    assert(options.filter.empty());
    assert(options.count == 0);
    assert(!options.show_hex);

    options = {};
    assert(parse({"packetSniffer", "-i", "lo0", "--filter", "tcp port 8765",
                  "--count", "10", "--hex"}, options) == ParseResult::ok);
    assert(options.device == "lo0");
    assert(options.filter == "tcp port 8765");
    assert(options.count == 10);
    assert(options.show_hex);

    options = {};
    assert(parse({"packetSniffer", "--help"}, options) == ParseResult::help);
    options = {};
    assert(parse({"packetSniffer"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "--count", "0", "lo0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "--count", "-1", "lo0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "--count", "abc", "lo0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "--count", "2147483648", "lo0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "--filter", "lo0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "lo0", "en0"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "lo0", "--no-such-option"}, options) == ParseResult::error);
    options = {};
    assert(parse({"packetSniffer", "-i", "lo0", "en0"}, options) == ParseResult::error);
    std::cout << "CLI parsing smoke tests passed.\n";
}
