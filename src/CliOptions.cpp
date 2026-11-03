#include "CliOptions.hpp"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <ostream>
#include <string>

namespace packetsniffer {
namespace {

bool parse_positive_count(const char* value, int& count) {
    if (value == nullptr || *value == '\0') return false;
    errno = 0;
    char* end = nullptr;
    const long parsed = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed <= 0 || parsed > INT_MAX) return false;
    count = static_cast<int>(parsed);
    return true;
}

} // namespace

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

ParseResult parse_arguments(int argc, char* const argv[], Options& options,
                            std::ostream& errors) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") return ParseResult::help;
        if (arg == "-x" || arg == "--hex") {
            options.show_hex = true;
            continue;
        }
        if (arg == "-i" || arg == "--interface") {
            if (!options.device.empty() || i + 1 >= argc ||
                argv[i+1][0] == '\0' || argv[i+1][0] == '-') {
                errors << "Invalid or duplicate interface argument.\n";
                return ParseResult::error;
            }
            options.device = argv[++i];
            continue;
        }
        if (arg == "-f" || arg == "--filter") {
            if (!options.filter.empty() || i + 1 >= argc ||
                argv[i+1][0] == '\0') {
                errors << "Missing or duplicate packet filter.\n";
                return ParseResult::error;
            }
            options.filter = argv[++i];
            continue;
        }
        if (arg == "-c" || arg == "--count") {
            if (options.count != 0 || i + 1 >= argc ||
                !parse_positive_count(argv[i+1], options.count)) {
                errors << "Packet count must be a positive integer.\n";
                return ParseResult::error;
            }
            ++i;
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            errors << "Unknown option: " << arg << '\n';
            return ParseResult::error;
        }
        if (!options.device.empty()) {
            errors << "Only one interface can be specified.\n";
            return ParseResult::error;
        }
        options.device = arg;
    }
    if (options.device.empty()) {
        errors << "A network interface is required.\n";
        return ParseResult::error;
    }
    return ParseResult::ok;
}

} // namespace packetsniffer
