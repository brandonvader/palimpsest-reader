#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "HalStorage.h"

// Generic pcap file sink. Link-layer framing (radiotap+802.11, HCI H4, ...)
// is each caller's concern -- this just writes the pcap global header once
// and a correctly-sized record header per call, so every capture tool shares
// one file-I/O implementation regardless of what it captures.
class PcapWriter {
 public:
  // Opens path (its parent directory must already exist) and writes the pcap
  // global header for the given link-layer type (a DLT_* constant from
  // http://www.tcpdump.org/linktypes.html) and snaplen. False (file left
  // closed) on any failure.
  bool open(const std::string& path, uint32_t linkType, uint32_t snaplen);

  // Appends one record: data/length is the exact bytes to store (already
  // built in whatever link-layer format open() declared, and already
  // truncated to snaplen if needed). origLength is the untruncated length on
  // the wire, for the record's orig_len field (equal to length when nothing
  // was truncated). tsSec/tsUsec are a caller-provided timestamp pair
  // (monotonic is fine; Wireshark only needs per-file-consistent deltas).
  // Returns false if the write failed (e.g. SD full) -- the caller should
  // stop the capture.
  bool writeRecord(const uint8_t* data, size_t length, size_t origLength, uint32_t tsSec, uint32_t tsUsec);

  void close();
  bool isOpen() const { return file.isOpen(); }
  uint64_t bytesWritten() const { return bytesWritten_; }
  uint32_t frameCount() const { return frameCount_; }

 private:
  HalFile file;
  uint64_t bytesWritten_ = 0;
  uint32_t frameCount_ = 0;
};
