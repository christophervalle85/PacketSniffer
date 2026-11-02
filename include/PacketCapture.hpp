#pragma once

#include "CliOptions.hpp"

namespace packetsniffer {
class PacketCapture {
public:
    // Runs a live capture. Returns 0 on success or Ctrl-C, nonzero on errors.
    static int run(const Options& options);
};
} // namespace packetsniffer
