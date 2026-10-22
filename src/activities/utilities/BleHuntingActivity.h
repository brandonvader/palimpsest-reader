#pragma once

#include <cstdint>
#include <string>

#include "activities/UiListActivity.h"

// Active single-target BLE RSSI tracker ("fox hunting" one specific
// advertiser), the BLE sibling of WifiHuntingActivity. BLE has no
// channel-hop/lock concept the way WiFi promiscuous mode does -- NimBLE's
// scanner already listens across all three primary advertising channels at
// once -- so there is no discovery phase: given a target address, it starts
// scanning immediately and polls the target's RSSI once a second.
//
// A preset target (hasTarget) always comes from a "Hunt this" row action on
// BleScanActivity/BleFinderActivity, which keeps the NimBLE stack
// initialized and simply hands this activity its already-running (or just-
// ended) scan to borrow; this activity never calls NimBLEDevice::init() or
// deinit() in that case. Only a standalone (manual-entry) launch owns the
// stack's init/deinit lifecycle. This matters because NimBLEDevice::deinit()
// has an unbounded internal wait with no app-level timeout (confirmed by
// reading NimBLE-Arduino's own source -- see stopHunting() for the exact
// call), which a naive "release before push, reacquire on pop" design around
// the row action would have exercised on every single hunt.
class BleHuntingActivity final : public UiListActivity {
 public:
  // Preset target (e.g. a "Hunt this" row action). `label` is the row's
  // display name (device name, "Flipper Zero", etc.); pass nullptr to fall
  // back to the formatted address.
  BleHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, const uint8_t targetAddrIn[6],
                     const char* label);
  // No preset target: onEnter() immediately prompts for an address via the
  // on-screen keyboard.
  explicit BleHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  // This device's short reception range (everything is within ~100 ft) makes
  // a snappy update meaningfully better for fox-hunting.
  static constexpr uint32_t UPDATE_MS = 1000;
  // BLE devices typically advertise far more often than this; this long with
  // nothing at this cadence is a fair sign the target is genuinely gone.
  static constexpr uint32_t STALE_THRESHOLD_MS = 6000;
  // Re-clearing NimBLE's own dedup cache this often forces repeat
  // advertisements to reach the callback again, same technique BleFinderActivity uses.
  static constexpr uint32_t REARM_MS = 1000;
  static constexpr int GAUGE_HEIGHT = 150;
  static constexpr int GAUGE_MARGIN = 12;
  static constexpr int ROW_COUNT = 2;  // control, target

  enum class State { ENTER_ADDRESS, SCANNING, STOPPED };

  int listCount() const override { return rowCount; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  void drawChrome() override;
  const char* headerTitle() const override;

  void promptForAddress(const char* title, const std::string& initialText);
  void startHunting();
  // `forTeardown`: called from onExit(), which ActivityManager always invokes
  // while it already holds the render lock (see FrameCaptureActivity's
  // StopReason::TEARDOWN for the same pattern already established elsewhere)
  // -- skips the RenderLock/state/rebuildRows/requestUpdate tail, which would
  // otherwise deadlock the task trying to re-acquire a lock it already holds.
  void stopHunting(bool forTeardown = false);
  // Caller holds the render lock.
  void rebuildRows();

  const bool hasTarget = false;
  uint8_t targetAddr[6] = {};
  char targetLabel[40] = {};

  State state = State::ENTER_ADDRESS;
  bool stackUp = false;  // true only for a standalone launch that owns init/deinit itself
  uint32_t rearmMs = 0;
  uint32_t lastUpdateMs = 0;

  bool everSeen = false;
  int8_t rssi = -128;
  uint32_t lastSeenMs = 0;

  int rowCount = 0;
  char controlValueText[40] = {};
  char addressRowValue[24] = {};
  char signalSubtitle[32] = {};
  freeink::ui::ListItem rows[ROW_COUNT]{};
};
