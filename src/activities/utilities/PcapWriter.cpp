#include "PcapWriter.h"

#include <Logging.h>

namespace {
// Classic libpcap global header (24 bytes). See https://wiki.wireshark.org/Development/LibpcapFileFormat.
#pragma pack(push, 1)
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
  uint32_t inclLen;  // bytes actually saved (may be less than origLen if truncated)
  uint32_t origLen;  // length on the wire
};
#pragma pack(pop)

constexpr uint32_t PCAP_MAGIC = 0xa1b2c3d4;
}  // namespace

bool PcapWriter::open(const std::string& path, const uint32_t linkType, const uint32_t snaplen) {
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
  header.snaplen = snaplen;
  header.network = linkType;
  const size_t written = file.write(&header, sizeof(header));
  if (written != sizeof(header)) {
    LOG_ERR("PCAP", "Failed to write global header to %s", path.c_str());
    close();
    return false;
  }
  bytesWritten_ += written;
  return true;
}

bool PcapWriter::writeRecord(const uint8_t* data, const size_t length, const size_t origLength, const uint32_t tsSec,
                             const uint32_t tsUsec) {
  if (!file.isOpen()) return false;

  PcapRecordHeader record{};
  record.tsSec = tsSec;
  record.tsUsec = tsUsec;
  record.inclLen = static_cast<uint32_t>(length);
  record.origLen = static_cast<uint32_t>(origLength);

  size_t written = file.write(&record, sizeof(record));
  written += file.write(data, length);
  const size_t expected = sizeof(record) + length;
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
