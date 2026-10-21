#include "Radiotap.h"

#include <cstring>

namespace radiotap {
namespace {
// Packed so sizeof() matches the on-wire layout exactly -- natural struct
// alignment would pad this to a 4-byte multiple and corrupt the format.
#pragma pack(push, 1)
struct RadiotapHeader {
  uint8_t version = 0;
  uint8_t pad = 0;
  uint16_t length = HEADER_LEN;
  uint32_t present = 0;
  uint16_t channelFreqMhz = 0;  // bit 3
  uint16_t channelFlags = 0;    // bit 3
  int8_t antennaSignalDbm = 0;  // bit 5
};
#pragma pack(pop)
static_assert(sizeof(RadiotapHeader) == HEADER_LEN, "radiotap header size drifted from HEADER_LEN");

constexpr uint32_t PRESENT_CHANNEL = 1u << 3;
constexpr uint32_t PRESENT_DBM_ANTSIGNAL = 1u << 5;
constexpr uint16_t CHANNEL_FLAG_2GHZ = 0x0080;

uint16_t channelToFreqMhz(const uint8_t channel) {
  // 2.4 GHz channel center frequencies, channels 1-13 (802.11).
  if (channel >= 1 && channel <= 13) return static_cast<uint16_t>(2407 + channel * 5);
  return 2412;  // fallback: channel 1
}
}  // namespace

void build(uint8_t* out, const uint8_t channel, const int8_t rssiDbm) {
  RadiotapHeader header{};
  header.present = PRESENT_CHANNEL | PRESENT_DBM_ANTSIGNAL;
  header.channelFreqMhz = channelToFreqMhz(channel);
  header.channelFlags = CHANNEL_FLAG_2GHZ;
  header.antennaSignalDbm = rssiDbm;
  memcpy(out, &header, HEADER_LEN);
}

}  // namespace radiotap
