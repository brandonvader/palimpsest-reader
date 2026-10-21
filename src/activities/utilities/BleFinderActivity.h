#pragma once

#include <cstdint>

#include "activities/UiListActivity.h"

// Shared with the .cpp's file-scope tracking tables and the Activity's own
// snapshot members (kept off the stack for the same reason as
// AirspaceMonitorActivity's snapshot members -- see the note there).
struct BleFinderDevice {
  uint8_t addr[6] = {};
  int8_t rssi = 0;
  uint32_t lastSeenMs = 0;
};

struct BleFinderSpamSource {
  uint8_t addr[6] = {};
  uint32_t matchCount = 0;
  char lastType[24] = {};  // most recent matched pattern's label
  int8_t rssi = 0;
  uint32_t lastSeenMs = 0;
};

// Passive BLE "who's nearby" finder: continuous scan like BLE Capture
// (periodically clearing NimBLE's own dedup cache so repeat advertisements
// keep registering), surfacing three kinds of finding:
//   - Flipper Zero: MAC vendor prefix (80:e1:26, 80:e1:27, 0c:fa:22 --
//     registered to Flipper Devices Inc), default device name ("Flipper..."),
//     or its colorway GATT service UUID (0x3080-0x308F) -- the same three
//     signals the Wall-of-Flippers project uses (MIT licensed, reimplemented
//     independently here; https://github.com/K3YOMI/Wall-of-Flippers).
//   - AirTag / Find My: Apple manufacturer data (company 0x004C) with type
//     byte 0x12, the fixed marker for a Find My network advertisement
//     (Bluetooth-independent of AirPods/Continuity, which use other type
//     bytes). Labelled "Find My Tracker", not "AirTag": any Find My
//     accessory (Chipolo, etc.) or even a lost iPhone can broadcast this.
//   - BLE spam/attack: manufacturer-data and service-data byte patterns
//     matching known forged-popup payloads (Apple proximity-pairing/nearby-
//     action, Samsung Buds/Watch pairing, Windows Swift Pair, a BLE "toy"
//     proximity beacon) plus the standard HID and Fast Pair service UUIDs,
//     adapted from Wall-of-Flippers' own pattern list. A single match is not
//     an alert by itself -- ordinary earbuds legitimately send some of these
//     during normal pairing-mode chatter -- so, exactly as Wall-of-Flippers
//     does, only an address crossing a cumulative match threshold (25,
//     their own sourced default) is shown, and this is not Flipper-specific:
//     any BLE spam tool trips it.
class BleFinderActivity final : public UiListActivity {
 public:
  static constexpr int MAX_FLIPPERS = 8;
  static constexpr int MAX_TRACKERS = 8;
  static constexpr int MAX_SPAM_SOURCES = 8;
  static constexpr uint32_t SPAM_THRESHOLD = 25;  // Wall-of-Flippers' own sourced default

  explicit BleFinderActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr uint32_t STATUS_REFRESH_MS = 5000;
  static constexpr uint32_t MAX_DURATION_MS = 10 * 60 * 1000;
  // NimBLE's own scan-result cache reports each address only once (until
  // cleared); re-clearing it this often forces repeat advertisements to
  // reach our callback again, same technique BleCaptureActivity uses.
  static constexpr uint32_t REARM_MS = 1000;
  // BLE devices typically advertise far more often than this; missing for
  // this long is a fair sign a finding is genuinely gone, not just between
  // advertisements.
  static constexpr uint32_t STALE_THRESHOLD_MS = 10000;

  enum class State { IDLE, SCANNING, STOPPED };
  enum Severity : int { SEVERITY_CONFIRMED = 0, SEVERITY_NOTABLE = 1 };

  struct PendingAlert {
    int severity = SEVERITY_NOTABLE;
    char label[20] = {};
    char subtitle[18] = {};  // signal ("-52 dBm ||||") or "Out of range"
    char value[40] = {};
  };
  static constexpr int MAX_ALERTS = MAX_FLIPPERS + MAX_TRACKERS + MAX_SPAM_SOURCES;
  static constexpr int MAX_ROWS = 1 /*control*/ + MAX_ALERTS;

  int listCount() const override;
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startScanning();
  void stopScanning();
  // Caller holds the render lock.
  void rebuildRows();

  State state = State::IDLE;
  bool stackUp = false;
  uint32_t rearmMs = 0;
  uint32_t scanStartMs = 0;
  uint32_t lastStatusMs = 0;
  char summary[40] = {};
  int rowCount = 0;
  char controlValueText[40] = {};
  freeink::ui::ListItem rows[MAX_ROWS]{};

  // See AirspaceMonitorActivity's identical note: these total more than the
  // project's "<256 bytes of locals" stack guidance, so they live on this
  // heap-allocated Activity instance instead of as rebuildRows() stack locals.
  BleFinderDevice flipperSnapshot[MAX_FLIPPERS];
  BleFinderDevice trackerSnapshot[MAX_TRACKERS];
  BleFinderSpamSource spamSnapshot[MAX_SPAM_SOURCES];
  PendingAlert alerts[MAX_ALERTS];
};
