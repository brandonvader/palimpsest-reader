#pragma once

#include <cstdint>
#include <string>

#include "PcapWriter.h"
#include "activities/UiListActivity.h"

// Captures BLE advertisements to a pcap file on the SD card for offline
// analysis (Wireshark), as the BLE counterpart to FrameCaptureActivity.
//
// NimBLE's host-level scan API has no raw promiscuous mode: it hands us
// already-decoded advertisement reports (address, RSSI, AD payload bytes),
// not raw radio frames or HCI bytes. Each record is a host-synthesized HCI
// "LE Advertising Report" event (Bluetooth Core Spec Vol 4 Part E 7.7.65.2)
// rebuilt from those decoded fields -- real address, RSSI, AD payload and
// event type, just reassembled into the wire format rather than tapped off
// the bus. Wireshark dissects it exactly as a real one.
class BleCaptureActivity final : public UiListActivity {
 public:
  explicit BleCaptureActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr const char* CAPTURE_DIR = "/Palimpsest/captures";
  static constexpr uint32_t STATUS_REFRESH_MS = 5000;
  // NimBLE's own scan-result cache reports each address only once (until
  // cleared); re-clearing it this often forces repeat advertisements to
  // reach our callback again, so this behaves like a continuous capture
  // instead of a one-shot device census.
  static constexpr uint32_t REARM_MS = 1000;
  // Safety caps: whichever is hit first ends the session automatically.
  static constexpr uint32_t MAX_FRAMES = 20000;
  static constexpr uint64_t MAX_BYTES = 8ull * 1024 * 1024;
  static constexpr uint32_t MAX_DURATION_MS = 10 * 60 * 1000;

  enum class State { IDLE, CAPTURING, STOPPED };
  enum class StopReason { USER, FRAME_LIMIT, SIZE_LIMIT, TIME_LIMIT, WRITE_ERROR, TEARDOWN };

  int listCount() const override { return 1; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startCapture();
  void stopCapture(StopReason reason);
  void failToStart();
  void drainRing();
  std::string buildCapturePath() const;
  // Caller holds the render lock.
  void rebuildRow();

  State state = State::IDLE;
  bool stackUp = false;
  uint32_t rearmMs = 0;
  uint32_t captureStartMs = 0;
  uint32_t lastStatusMs = 0;
  std::string capturePath;
  PcapWriter writer;
  char statusText[64] = {};
  freeink::ui::ListItem row{};
};
