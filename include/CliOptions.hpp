#pragma once

#include <iosfwd>
#include <string>

namespace packetsniffer {

struct Options {
    std::string device;
    std::string filter;
    int count = 0; // Zero means keep capturing until interrupted.
    bool show_hex = false;
};

enum class ParseResult { ok, help, error };

void print_usage(const char* program, std::ostream& out);
ParseResult parse_arguments(int argc, char* const argv[], Options& options,
                            std::ostream& errors);

} // namespace packetsniffer
