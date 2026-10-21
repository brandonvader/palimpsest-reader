#include "PcapWriter.h"

#include <Logging.h>

#include <cstring>

namespace {
// Classic libpcap global header (24 bytes). See https://wiki.wireshark.org/Development/LibpcapFileFormat.
// LINKTYPE_IEEE802_11_RADIOTAP: http://www.tcpdump.org/linktypes.html
constexpr uint32_t PCAP_MAGIC = 0xa1b2c3d4;
constexpr uint32_t LINKTYPE_IEEE802_11_RADIOTAP = 127;

// Minimal radiotap header carrying just Channel (bit 3) and dBm Antenna
// Signal (bit 5). Field order follows increasing bit number and each field
// sits at the offset its own size requires from the header start, per the
// radiotap spec (https://www.radiotap.org/). Packed so sizeof() matches the
// on-wire layout exactly -- natural struct alignment would pad this to a
// 4-byte multiple and corrupt the format.
#pragma pack(push, 1)
struct RadiotapHeader {
  uint8_t version = 0;
  uint8_t pad = 0;
  uint16_t length = sizeof(RadiotapHeader);
  uint32_t present = 0;
  uint16_t channelFreqMhz = 0;  // bit 3
  uint16_t channelFlags = 0;    // bit 3
  int8_t antennaSignalDbm = 0;  // bit 5
};

struct PcapGlobalHeader {
  uint32_t magic;
  uint16_t versionMajor;
  uint16_t versionMinor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapRecordHeader {
  uint32_t tsSec;
  uint32_t tsUsec;
  uint32_t inclLen;  // bytes actually saved (radiotap header + possibly-truncated frame)
  uint32_t origLen;  // length on the wire (radiotap header + untruncated frame)
};
#pragma pack(pop)

constexpr uint32_t RADIOTAP_PRESENT_CHANNEL = 1u << 3;
constexpr uint32_t RADIOTAP_PRESENT_DBM_ANTSIGNAL = 1u << 5;
constexpr uint16_t RADIOTAP_CHANNEL_FLAG_2GHZ = 0x0080;

uint16_t channelToFreqMhz(const uint8_t channel) {
  // 2.4 GHz channel center frequencies, channels 1-13 (802.11).
  if (channel >= 1 && channel <= 13) return static_cast<uint16_t>(2407 + channel * 5);
  return 2412;  // fallback: channel 1
}
}  // namespace

bool PcapWriter::open(const std::string& path) {
  bytesWritten_ = 0;
  frameCount_ = 0;
  if (!Storage.openFileForWrite("PCAP", path, file)) {
    LOG_ERR("PCAP", "Failed to open %s", path.c_str());
    return false;
  }

  PcapGlobalHeader header{};
  header.magic = PCAP_MAGIC;
  header.versionMajor = 2;
  header.versionMinor = 4;
  header.thiszone = 0;
  header.sigfigs = 0;
  header.snaplen = static_cast<uint32_t>(sizeof(RadiotapHeader) + SNAPLEN);
  header.network = LINKTYPE_IEEE802_11_RADIOTAP;
  const size_t written = file.write(&header, sizeof(header));
  if (written != sizeof(header)) {
    LOG_ERR("PCAP", "Failed to write global header to %s", path.c_str());
    close();
    return false;
  }
  bytesWritten_ += written;
  return true;
}

bool PcapWriter::writeFrame(const uint8_t* data, const size_t length, const uint8_t channel, const int8_t rssiDbm,
                            const uint32_t tsSec, const uint32_t tsUsec) {
  if (!file.isOpen()) return false;
  const size_t capLen = length > SNAPLEN ? SNAPLEN : length;

  RadiotapHeader radiotap{};
  radiotap.present = RADIOTAP_PRESENT_CHANNEL | RADIOTAP_PRESENT_DBM_ANTSIGNAL;
  radiotap.channelFreqMhz = channelToFreqMhz(channel);
  radiotap.channelFlags = RADIOTAP_CHANNEL_FLAG_2GHZ;
  radiotap.antennaSignalDbm = rssiDbm;

  PcapRecordHeader record{};
  record.tsSec = tsSec;
  record.tsUsec = tsUsec;
  record.inclLen = static_cast<uint32_t>(sizeof(radiotap) + capLen);
  record.origLen = static_cast<uint32_t>(sizeof(radiotap) + length);

  size_t written = file.write(&record, sizeof(record));
  written += file.write(&radiotap, sizeof(radiotap));
  written += file.write(data, capLen);
  const size_t expected = sizeof(record) + sizeof(radiotap) + capLen;
  if (written != expected) {
    LOG_ERR("PCAP", "Short write (%zu of %zu bytes); stopping capture", written, expected);
    return false;
  }
  bytesWritten_ += written;
  frameCount_++;
  return true;
}

void PcapWriter::close() {
  if (file.isOpen()) {
    file.flush();
    file.close();
  }
}
