#pragma once

#include <cstddef>
#include <cstdint>

// Minimal radiotap header (Channel + dBm Antenna Signal), shared by every
// WiFi capture tool that writes pcap files with DLT_IEEE802_11_RADIOTAP, so
// Wireshark shows channel/signal without each tool rebuilding the format.
// Field layout per https://www.radiotap.org/.
namespace radiotap {

constexpr uint32_t DLT_IEEE802_11_RADIOTAP = 127;  // http://www.tcpdump.org/linktypes.html
constexpr size_t HEADER_LEN = 13;                  // version/pad(2) + length(2) + present(4) + channel(4) + signal(1)

// Writes exactly HEADER_LEN bytes into out (caller-provided, >= HEADER_LEN).
void build(uint8_t* out, uint8_t channel, int8_t rssiDbm);

}  // namespace radiotap
