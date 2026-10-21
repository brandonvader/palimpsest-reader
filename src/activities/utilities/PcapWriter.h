#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "HalStorage.h"

// Writes 802.11 frames as a standard pcap file with a radiotap link-layer
// header (channel + RSSI per frame), so a capture opens directly in
// Wireshark. One writer instance = one capture session = one file, opened
// once and written to sequentially.
class PcapWriter {
 public:
  // Longest frame body kept per record; longer frames are truncated the same
  // way a tcpdump/airodump snaplen would (pcap's incl_len/orig_len record the
  // truncation, nothing is corrupted).
  static constexpr size_t SNAPLEN = 512;

  // Opens path (its parent directory must already exist) and writes the pcap
  // global header. False (and the file left closed) on any failure.
  bool open(const std::string& path);

  // Appends one frame: data/length is the raw 802.11 frame starting at the
  // frame-control field. channel is the 802.11 channel (1-13) it was heard
  // on; rssiDbm is the receive signal strength. tsSec/tsUsec are a
  // caller-provided timestamp pair (monotonic is fine; Wireshark only needs
  // per-file-consistent deltas). Returns false if the write failed (e.g. SD
  // full) -- the caller should stop the capture.
  bool writeFrame(const uint8_t* data, size_t length, uint8_t channel, int8_t rssiDbm, uint32_t tsSec, uint32_t tsUsec);

  void close();
  bool isOpen() const { return file.isOpen(); }
  uint64_t bytesWritten() const { return bytesWritten_; }
  uint32_t frameCount() const { return frameCount_; }

 private:
  HalFile file;
  uint64_t bytesWritten_ = 0;
  uint32_t frameCount_ = 0;
};
