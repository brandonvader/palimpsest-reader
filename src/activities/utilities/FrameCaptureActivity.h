#pragma once

#include <cstdint>
#include <string>

#include "PcapWriter.h"
#include "activities/UiListActivity.h"

// Captures 802.11 management frames (beacon, probe request/response, assoc,
// auth, ...) to a pcap file on the SD card for offline analysis (Wireshark).
// Hops channels 1-13 the same way ChannelSurveyActivity does. Deliberately
// scoped to management frames only -- the driver's own promiscuous filter
// excludes data and control frames, so no other device's actual traffic
// content is ever captured, only the same broadcast management traffic a
// passive survey already sees; this is a recon/survey tool, not a packet
// sniffer.
//
// A capture is a bounded session: it stops automatically at a frame-count,
// file-size or duration cap (whichever comes first), in addition to an
// explicit Stop, so a forgotten capture cannot silently fill the SD card.
// Captures are not auto-deleted; the operator manages retention (see README).
class FrameCaptureActivity final : public UiListActivity {
 public:
  explicit FrameCaptureActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr const char* CAPTURE_DIR = "/Palimpsest/captures";
  static constexpr uint8_t FIRST_CHANNEL = 1;
  static constexpr uint8_t LAST_CHANNEL = 13;
  static constexpr uint32_t DWELL_MS = 350;
  static constexpr uint32_t STATUS_REFRESH_MS = 5000;
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
  int priorWifiMode = 0;  // wifi_mode_t at entry, restored on exit
  bool promiscuousOn = false;
  uint8_t currentChannel = FIRST_CHANNEL;
  uint32_t channelStartMs = 0;
  uint32_t captureStartMs = 0;
  uint32_t lastStatusMs = 0;
  std::string capturePath;
  PcapWriter writer;
  char statusText[64] = {};
  freeink::ui::ListItem row{};
};
