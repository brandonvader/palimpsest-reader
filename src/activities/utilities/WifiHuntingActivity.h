#pragma once

#include <cstdint>
#include <string>

#include "activities/UiListActivity.h"

// Active single-target WiFi RSSI tracker ("fox hunting" on one specific
// device instead of surveying everything nearby): given a target address,
// either hops channels 1-13 until it hears that address transmit (same dwell
// pattern as ChannelSurveyActivity) then locks to the channel it found it on,
// or -- if launched with an already-known channel, e.g. from a WifiScanActivity
// row -- locks immediately and skips discovery. Once locked it polls the
// target's RSSI once a second and redraws the signal gauge; it resumes the
// discovery sweep if the target goes quiet for a while (it may have moved
// channel). Matches on the transmitter address (802.11 Addr2) of management
// frames only, the same scope Frame Capture and Airspace Monitor use -- a
// beacon's Addr2 is the AP's own BSSID, a probe request's is the sending
// client's, so this covers both an AP and a client target without touching
// data-frame content.
//
// startHunting() reads WiFi's CURRENT mode as the "prior" mode it restores on
// its own Stop. A "Hunt this" row action (WifiScanActivity, AirspaceMonitorActivity)
// deliberately leaves WiFi in STA mode rather than releasing it first, so this
// activity inherits STA and its own Stop just restores STA -> STA (a no-op).
// If the inherited/prior mode were OFF instead, Stop's WiFi.mode(WIFI_OFF)
// call would go through Arduino-ESP32's espWiFiStop(), an internal shutdown
// path with an unbounded wait best avoided -- the WiFi-side counterpart to
// the NimBLE deinit() risk documented on BleHuntingActivity.
class WifiHuntingActivity final : public UiListActivity {
 public:
  // Preset target (e.g. a "Hunt this" row action): `channel` is the already
  // known channel (1-13), or 0 if unknown and a discovery sweep is needed.
  // `label` is the row's display name (SSID, vendor, etc.); pass nullptr to
  // fall back to the formatted address.
  WifiHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, const uint8_t targetAddrIn[6],
                      uint8_t channel, const char* label);
  // No preset target: onEnter() immediately prompts for an address via the
  // on-screen keyboard.
  explicit WifiHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr uint8_t FIRST_CHANNEL = 1;
  static constexpr uint8_t LAST_CHANNEL = 13;
  static constexpr uint32_t DWELL_MS = 350;        // per-channel dwell while discovering, same as ChannelSurveyActivity
  // This device's short reception range (everything is within ~100 ft) makes
  // a snappy update meaningfully better for fox-hunting.
  static constexpr uint32_t UPDATE_MS = 1000;
  // Active tracking at this cadence hears far more often than a 13-channel passive sweep
  // would; this long with nothing is a fair sign the target left this channel
  // (or is simply gone), worth re-sweeping for rather than sitting frozen.
  static constexpr uint32_t STALE_THRESHOLD_MS = 6000;
  static constexpr int GAUGE_HEIGHT = 150;
  static constexpr int GAUGE_MARGIN = 12;
  static constexpr int ROW_COUNT = 3;  // control, target, channel

  enum class State { ENTER_ADDRESS, DISCOVERING, LOCKED, STOPPED };

  int listCount() const override { return rowCount; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  void drawChrome() override;
  const char* headerTitle() const override;

  void promptForAddress(const char* title, const std::string& initialText);
  void startHunting(uint8_t preset);
  // `forTeardown`: called from onExit(), which ActivityManager always invokes
  // while it already holds the render lock (see FrameCaptureActivity's
  // StopReason::TEARDOWN for the same pattern already established elsewhere)
  // -- skips the RenderLock/state/rebuildRows/requestUpdate tail, which would
  // otherwise deadlock the task trying to re-acquire a lock it already holds.
  void stopHunting(bool forTeardown = false);
  // Channel-hop dwell, target-sighting snapshot, and the discover/lock/
  // reacquire state transitions. Runs every loop() pass; cheap, no rendering.
  void pollRadio();
  // Caller holds the render lock.
  void rebuildRows();

  const bool hasTarget = false;
  uint8_t targetAddr[6] = {};
  const uint8_t presetChannel = 0;
  char targetLabel[40] = {};

  State state = State::ENTER_ADDRESS;
  int priorWifiMode = 0;  // wifi_mode_t at entry, restored on exit
  bool promiscuousOn = false;
  uint8_t lockedChannel = 0;  // 0 = not yet locked
  uint8_t currentChannel = FIRST_CHANNEL;
  uint32_t channelStartMs = 0;
  uint32_t lastUpdateMs = 0;

  bool everSeen = false;
  int8_t rssi = -128;
  uint32_t lastSeenMs = 0;

  int rowCount = 0;
  char controlValueText[40] = {};
  char addressRowValue[24] = {};
  char signalSubtitle[32] = {};
  char channelRowValue[16] = {};
  freeink::ui::ListItem rows[ROW_COUNT]{};
};
