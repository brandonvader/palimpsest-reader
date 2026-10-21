#pragma once

#include <cstdint>

#include "activities/UiListActivity.h"

// Passive 2.4 GHz channel survey: hops channels 1-13 and counts beacon frames
// heard on each during one sweep (dwell per channel, then stop). Only the
// 802.11 frame-control byte is inspected to recognise a beacon; no frame
// content (SSID, addresses) is stored or parsed, and no other frame type is
// counted. A traffic-density view, not a capture tool.
class ChannelSurveyActivity final : public UiListActivity {
 public:
  // Channel range and row count are used by the per-channel row buffers below
  // and by the promiscuous callback's tally array, so they are public (same
  // pattern as AboutActivity::ITEM_COUNT).
  static constexpr uint8_t FIRST_CHANNEL = 1;
  static constexpr uint8_t LAST_CHANNEL = 13;
  static constexpr int CHANNEL_COUNT = LAST_CHANNEL - FIRST_CHANNEL + 1;

  explicit ChannelSurveyActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr uint32_t DWELL_MS = 350;

  enum class State { SCANNING, DONE };

  int listCount() const override { return 1 + CHANNEL_COUNT; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startSweep();
  void finishSweep();
  // Caller holds the render lock.
  void rebuildRows();

  State state = State::SCANNING;
  int priorWifiMode = 0;  // wifi_mode_t at entry, restored on exit
  bool promiscuousOn = false;
  uint8_t currentChannel = FIRST_CHANNEL;
  uint32_t channelStartMs = 0;
  char summary[40] = {};
  char channelLabels[CHANNEL_COUNT][12] = {};  // "Channel 13" etc, built once
  char valueText[CHANNEL_COUNT][12] = {};      // beacon count per channel
  freeink::ui::ListItem rows[1 + CHANNEL_COUNT]{};
};
