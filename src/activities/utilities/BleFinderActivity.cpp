#include "BleFinderActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <NimBLEDevice.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "SignalStrength.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
// Flipper Devices Inc OUIs. 0C:FA:22 is in Wireshark's own manuf database
// (cross-checked); 80:E1:26/80:E1:27 are not yet but are cited by
// Wall-of-Flippers via maclookup.app -- newly issued blocks can lag a bundled
// database's refresh cycle.
constexpr uint8_t FLIPPER_OUIS[][3] = {{0x80, 0xE1, 0x26}, {0x80, 0xE1, 0x27}, {0x0C, 0xFA, 0x22}};
// Flipper's colorway GATT service UUIDs (0x3081 Black, 0x3082 White, 0x3083
// Transparent, confirmed; 0x3080-0x308F is Wall-of-Flippers' own broader
// fallback range for colorways not yet in their table).
constexpr uint16_t FLIPPER_SERVICE_RANGE_BASE = 0x3080;
constexpr uint16_t FLIPPER_SERVICE_RANGE_MASK = 0xFFF0;

constexpr uint16_t SERVICE_UUID_HID = 0x1812;             // standard Bluetooth SIG Human Interface Device service
constexpr uint16_t SERVICE_DATA_UUID_FAST_PAIR = 0xFE2C;  // Google Fast Pair
constexpr uint8_t AD_TYPE_UUID16_INCOMPLETE = 0x02;
constexpr uint8_t AD_TYPE_UUID16_COMPLETE = 0x03;
constexpr uint8_t AD_TYPE_SERVICE_DATA_16 = 0x16;

constexpr uint8_t APPLE_COMPANY_ID[2] = {0x4C, 0x00};  // little-endian on the wire
constexpr uint8_t FIND_MY_TYPE = 0x12;                 // fixed marker byte for a Find My advertisement

// Known forged-advertisement byte patterns, adapted independently from
// Wall-of-Flippers' own list (MIT licensed; https://github.com/K3YOMI/Wall-of-Flippers,
// utils/wof_cache.py "forbidden_packets"). Matched against manufacturer-data
// bytes at hex-NIBBLE granularity (not byte granularity: several of their
// templates have wildcard runs starting mid-byte), reimplemented here as
// parsed nibble/mask arrays rather than hex strings with underscores.
// `_` cells in their source became mask=0 here; the match only requires
// min(pattern length, data length) nibbles to line up, same as their own
// Python zip()-based comparison (a manufacturer-data blob shorter than a
// pattern is compared only up to its own length, not rejected outright).
struct SpamPattern {
  uint8_t nibbles[31];
  uint8_t mask[31];
  const char* label;
};
constexpr SpamPattern SPAM_PATTERNS[] = {
    {{4, 12, 0, 0, 0, 7, 1, 9, 0, 1, 0, 0, 2, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     "Apple popup (close)"},
    {{4, 12, 0, 0, 0, 15, 0, 5, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     "Apple action modal"},
    {{4, 12, 0, 0, 0, 7, 1, 9, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     "Apple connect"},
    {{4, 12, 0, 0, 0, 4, 0, 4, 2, 10, 0, 0, 0, 0, 0, 0, 0, 15, 0, 5, 12, 1, 0, 0, 6, 0, 4, 12, 9, 5, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1},
     "Apple device setup"},
    {{7, 5, 0, 0, 4, 2, 0, 9, 8, 1, 0, 2, 1, 4, 1, 5, 0, 3, 2, 1, 0, 1, 0, 9, 0, 0, 0, 0, 0, 1, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0},
     "Samsung Buds popup"},
    {{7, 5, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 1, 15, 15, 0, 0, 0, 0, 4, 3, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0},
     "Samsung Watch pair"},
    {{0, 6, 0, 0, 0, 3, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     "Windows Swift Pair"},
    {{15, 15, 0, 0, 6, 13, 11, 6, 4, 3, 12, 14, 9, 7, 15, 14, 4, 2, 7, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
     "Love-toy proximity"},
};
constexpr int SPAM_PATTERN_COUNT = sizeof(SPAM_PATTERNS) / sizeof(SPAM_PATTERNS[0]);
// Wall-of-Flippers ignores packets shorter than this many bytes as noise.
constexpr size_t MIN_PATTERN_BYTES = 3;

portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;
BleFinderDevice g_flippers[BleFinderActivity::MAX_FLIPPERS];
int g_flipperCount = 0;
BleFinderDevice g_trackers[BleFinderActivity::MAX_TRACKERS];
int g_trackerCount = 0;
BleFinderSpamSource g_spamSources[BleFinderActivity::MAX_SPAM_SOURCES];
int g_spamCount = 0;

// Finds and updates an existing entry's rssi/lastSeenMs in place; returns
// whether one was found, so recordFlipper/recordTracker only need to
// insert a new entry when it returns false.
bool touchKnown(BleFinderDevice* table, const int count, const uint8_t* addr, const int8_t rssi) {
  for (int i = 0; i < count; i++) {
    if (memcmp(table[i].addr, addr, 6) == 0) {
      table[i].rssi = rssi;
      table[i].lastSeenMs = millis();
      return true;
    }
  }
  return false;
}

// Caller holds g_mux.
void recordFlipper(const uint8_t* addr, const int8_t rssi) {
  if (touchKnown(g_flippers, g_flipperCount, addr, rssi)) return;
  if (g_flipperCount >= BleFinderActivity::MAX_FLIPPERS) return;
  BleFinderDevice& entry = g_flippers[g_flipperCount++];
  memcpy(entry.addr, addr, 6);
  entry.rssi = rssi;
  entry.lastSeenMs = millis();
}

// Caller holds g_mux.
void recordTracker(const uint8_t* addr, const int8_t rssi) {
  if (touchKnown(g_trackers, g_trackerCount, addr, rssi)) return;
  if (g_trackerCount >= BleFinderActivity::MAX_TRACKERS) return;
  BleFinderDevice& entry = g_trackers[g_trackerCount++];
  memcpy(entry.addr, addr, 6);
  entry.rssi = rssi;
  entry.lastSeenMs = millis();
}

// Caller holds g_mux. Returns the address's cumulative match count after
// this one (0 if the table was full and this is a brand new, untracked
// address -- naturally below the threshold, so the caller skips it).
uint32_t recordSpamMatch(const uint8_t* addr, const char* type, const int8_t rssi) {
  const uint32_t now = millis();
  for (int i = 0; i < g_spamCount; i++) {
    if (memcmp(g_spamSources[i].addr, addr, 6) == 0) {
      strlcpy(g_spamSources[i].lastType, type, sizeof(g_spamSources[0].lastType));
      g_spamSources[i].rssi = rssi;
      g_spamSources[i].lastSeenMs = now;
      return ++g_spamSources[i].matchCount;
    }
  }
  if (g_spamCount < BleFinderActivity::MAX_SPAM_SOURCES) {
    BleFinderSpamSource& entry = g_spamSources[g_spamCount++];
    memcpy(entry.addr, addr, 6);
    strlcpy(entry.lastType, type, sizeof(entry.lastType));
    entry.matchCount = 1;
    entry.rssi = rssi;
    entry.lastSeenMs = now;
    return 1;
  }
  return 0;
}

bool isFlipperOui(const uint8_t* addr) {
  for (const auto& oui : FLIPPER_OUIS) {
    if (memcmp(addr, oui, 3) == 0) return true;
  }
  return false;
}

bool startsWithFlipper(const std::string& name) {
  if (name.size() < 7) return false;
  for (int i = 0; i < 7; i++) {
    if (tolower(static_cast<unsigned char>(name[i])) != "flipper"[i]) return false;
  }
  return true;
}

// Nibble-granular match: compares min(pattern length, data length) nibbles,
// same as Wall-of-Flippers' own Python zip()-based comparison. `data` is raw
// manufacturer-data bytes (company ID first, as NimBLE/the controller hands
// it to us -- already confirmed wire order by cross-checking a real capture
// in Wireshark during Frame/BLE Capture development).
bool matchesSpamPattern(const SpamPattern& pattern, const uint8_t* data, const size_t dataLen) {
  const size_t dataNibbles = dataLen * 2;
  const size_t patternNibbles = sizeof(pattern.nibbles);
  const size_t compareLen = std::min(dataNibbles, patternNibbles);
  for (size_t i = 0; i < compareLen; i++) {
    if (!pattern.mask[i]) continue;
    const uint8_t dataNibble = (i % 2 == 0) ? (data[i / 2] >> 4) : (data[i / 2] & 0x0F);
    if (dataNibble != pattern.nibbles[i]) return false;
  }
  return true;
}

// Walks BLE advertising-data structures (length-prefixed TLVs, same shape as
// the WiFi IE walk elsewhere in this codebase) looking for the HID service
// UUID (as a 16-bit Service UUID list entry) or the Fast Pair service UUID
// (as a Service Data - 16-bit UUID prefix). Bounds-checked at every step:
// this parses attacker-controlled advertising data.
void scanServiceSignatures(const uint8_t* payload, const size_t len, bool& hasHid, bool& hasFastPair,
                           bool& hasFlipperService) {
  size_t pos = 0;
  while (pos + 2 <= len) {
    const uint8_t adLen = payload[pos];
    if (adLen == 0 || pos + 1 + adLen > len) break;
    const uint8_t adType = payload[pos + 1];
    const uint8_t* value = &payload[pos + 2];
    const uint8_t valueLen = adLen - 1;
    if (adType == AD_TYPE_UUID16_INCOMPLETE || adType == AD_TYPE_UUID16_COMPLETE) {
      for (size_t i = 0; i + 2 <= valueLen; i += 2) {
        uint16_t uuid;
        memcpy(&uuid, &value[i], 2);
        if (uuid == SERVICE_UUID_HID) hasHid = true;
        if ((uuid & FLIPPER_SERVICE_RANGE_MASK) == FLIPPER_SERVICE_RANGE_BASE) hasFlipperService = true;
      }
    } else if (adType == AD_TYPE_SERVICE_DATA_16 && valueLen >= 2) {
      uint16_t uuid;
      memcpy(&uuid, value, 2);
      if (uuid == SERVICE_DATA_UUID_FAST_PAIR) hasFastPair = true;
    }
    pos += 1 + adLen;
  }
}

class FinderCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    if (!dev) return;
    uint8_t addr[6];
    memcpy(addr, dev->getAddress().getVal(), 6);
    const int8_t rssi = static_cast<int8_t>(dev->getRSSI());

    bool isFlipper = isFlipperOui(addr);
    if (!isFlipper && dev->haveName()) isFlipper = startsWithFlipper(dev->getName());
    bool hasHid = false, hasFastPair = false, hasFlipperService = false;
    const auto& payload = dev->getPayload();
    if (!payload.empty()) scanServiceSignatures(payload.data(), payload.size(), hasHid, hasFastPair, hasFlipperService);
    isFlipper = isFlipper || hasFlipperService;

    bool isTracker = false;
    for (uint8_t i = 0; i < dev->getManufacturerDataCount(); i++) {
      const std::string data = dev->getManufacturerData(i);
      if (data.size() >= 3 && memcmp(data.data(), APPLE_COMPANY_ID, 2) == 0 &&
          static_cast<uint8_t>(data[2]) == FIND_MY_TYPE) {
        isTracker = true;
      }
      if (data.size() < MIN_PATTERN_BYTES) continue;
      for (int p = 0; p < SPAM_PATTERN_COUNT; p++) {
        if (matchesSpamPattern(SPAM_PATTERNS[p], reinterpret_cast<const uint8_t*>(data.data()), data.size())) {
          portENTER_CRITICAL(&g_mux);
          recordSpamMatch(addr, SPAM_PATTERNS[p].label, rssi);
          portEXIT_CRITICAL(&g_mux);
          break;  // one match per manufacturer-data block is enough to count this advertisement
        }
      }
    }
    if (hasHid) {
      portENTER_CRITICAL(&g_mux);
      recordSpamMatch(addr, "HID service advertised", rssi);
      portEXIT_CRITICAL(&g_mux);
    }
    if (hasFastPair) {
      portENTER_CRITICAL(&g_mux);
      recordSpamMatch(addr, "Fast Pair service advertised", rssi);
      portEXIT_CRITICAL(&g_mux);
    }

    if (isFlipper || isTracker) {
      portENTER_CRITICAL(&g_mux);
      if (isFlipper) recordFlipper(addr, rssi);
      if (isTracker) recordTracker(addr, rssi);
      portEXIT_CRITICAL(&g_mux);
    }
  }
};

FinderCallbacks g_callbacks;
}  // namespace

BleFinderActivity::BleFinderActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("BleFinder", renderer, mappedInput) {}

const char* BleFinderActivity::headerTitle() const { return tr(STR_UTILITIES_BLE_FINDER); }

int BleFinderActivity::listCount() const { return rowCount; }

void BleFinderActivity::onEnter() {
  UiListActivity::onEnter();
  snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_IDLE));
  rebuildRows();
}

void BleFinderActivity::onExit() {
  if (state == State::SCANNING) stopScanning();
  UiListActivity::onExit();
}

void BleFinderActivity::loop() {
  if (state == State::SCANNING) {
    if (millis() - rearmMs >= REARM_MS) {
      NimBLEDevice::getScan()->clearResults();
      rearmMs = millis();
    }
    if (millis() - scanStartMs >= MAX_DURATION_MS) {
      stopScanning();
    } else if (millis() - lastStatusMs >= STATUS_REFRESH_MS) {
      lastStatusMs = millis();
      {
        RenderLock lock(*this);
        rebuildRows();
      }
      requestUpdate();
    }
  }
  UiListActivity::loop();
}

void BleFinderActivity::startScanning() {
  stackUp = NimBLEDevice::init("");
  if (!stackUp) {
    LOG_ERR("BFIND", "NimBLE init failed");
    RenderLock lock(*this);
    snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_UNAVAILABLE));
    rebuildRows();
    requestUpdate();
    return;
  }

  portENTER_CRITICAL(&g_mux);
  g_flipperCount = 0;
  g_trackerCount = 0;
  g_spamCount = 0;
  portEXIT_CRITICAL(&g_mux);

  auto* scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(&g_callbacks, true);  // wantDuplicates: scan responses pair with the right advertisement
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(100);
  if (!scan->start(0, false, true)) {  // 0 = scan until stopped
    LOG_ERR("BFIND", "Failed to start BLE scan");
    NimBLEDevice::deinit(true);
    stackUp = false;
    RenderLock lock(*this);
    snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_UNAVAILABLE));
    rebuildRows();
    requestUpdate();
    return;
  }

  scanStartMs = millis();
  lastStatusMs = millis();
  rearmMs = millis();

  {
    RenderLock lock(*this);
    state = State::SCANNING;
    snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_STARTING));
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();
}

void BleFinderActivity::stopScanning() {
  if (stackUp) {
    // Wait for onScanEnd before deinit: stop() only requests cancellation and
    // returns before the host task has processed it, and deinit() racing
    // that cancellation crashed inside NimBLE's own teardown during Frame
    // Capture's BLE sibling -- see palimpsest-ble-capture-crash (project
    // memory) for the full root cause.
    static volatile bool scanEnded = false;
    class OnceCallbacks : public NimBLEScanCallbacks {
      void onScanEnd(const NimBLEScanResults&, int) override { scanEnded = true; }
    };
    static OnceCallbacks onceCallbacks;
    scanEnded = false;
    auto* scan = NimBLEDevice::getScan();
    if (scan->isScanning()) {
      scan->setScanCallbacks(&onceCallbacks, true);
      scan->stop();
      const uint32_t waitStart = millis();
      while (!scanEnded && millis() - waitStart < 1000) {
        delay(5);
      }
    }
    scan->clearResults();
    scan->setScanCallbacks(nullptr);
    NimBLEDevice::deinit(true);
    stackUp = false;
  }

  RenderLock lock(*this);
  state = State::STOPPED;
  snprintf(summary, sizeof(summary), "%s", tr(STR_RESCAN));
  rebuildRows();
  requestUpdate();
}

void BleFinderActivity::rebuildRows() {
  int flipperCount, trackerCount, spamCount;
  portENTER_CRITICAL(&g_mux);
  flipperCount = g_flipperCount;
  memcpy(flipperSnapshot, g_flippers, sizeof(BleFinderDevice) * flipperCount);
  trackerCount = g_trackerCount;
  memcpy(trackerSnapshot, g_trackers, sizeof(BleFinderDevice) * trackerCount);
  spamCount = g_spamCount;
  memcpy(spamSnapshot, g_spamSources, sizeof(BleFinderSpamSource) * spamCount);
  portEXIT_CRITICAL(&g_mux);

  const uint32_t now = millis();
  int alertCount = 0;

  for (int i = 0; i < spamCount && alertCount < MAX_ALERTS; i++) {
    if (spamSnapshot[i].matchCount < SPAM_THRESHOLD) continue;  // see class comment: one match is not an alert
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_CONFIRMED;
    a.rssi = spamSnapshot[i].rssi;
    a.stale = (now - spamSnapshot[i].lastSeenMs) > STALE_THRESHOLD_MS;
    snprintf(a.label, sizeof(a.label), "%02X:%02X:%02X:%02X:%02X:%02X", spamSnapshot[i].addr[0],
             spamSnapshot[i].addr[1], spamSnapshot[i].addr[2], spamSnapshot[i].addr[3], spamSnapshot[i].addr[4],
             spamSnapshot[i].addr[5]);
    formatSignalSubtitle(a.subtitle, sizeof(a.subtitle), nullptr, spamSnapshot[i].rssi, spamSnapshot[i].lastSeenMs, now,
                         STALE_THRESHOLD_MS);
    snprintf(a.value, sizeof(a.value), tr(STR_BLE_SPAM_DETECTED), spamSnapshot[i].lastType);
    alertCount++;
  }

  for (int i = 0; i < flipperCount && alertCount < MAX_ALERTS; i++) {
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_NOTABLE;
    a.rssi = flipperSnapshot[i].rssi;
    a.stale = (now - flipperSnapshot[i].lastSeenMs) > STALE_THRESHOLD_MS;
    snprintf(a.label, sizeof(a.label), "%02X:%02X:%02X:%02X:%02X:%02X", flipperSnapshot[i].addr[0],
             flipperSnapshot[i].addr[1], flipperSnapshot[i].addr[2], flipperSnapshot[i].addr[3],
             flipperSnapshot[i].addr[4], flipperSnapshot[i].addr[5]);
    formatSignalSubtitle(a.subtitle, sizeof(a.subtitle), nullptr, flipperSnapshot[i].rssi,
                         flipperSnapshot[i].lastSeenMs, now, STALE_THRESHOLD_MS);
    snprintf(a.value, sizeof(a.value), "%s", tr(STR_FLIPPER_DETECTED));
    alertCount++;
  }

  for (int i = 0; i < trackerCount && alertCount < MAX_ALERTS; i++) {
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_NOTABLE;
    a.rssi = trackerSnapshot[i].rssi;
    a.stale = (now - trackerSnapshot[i].lastSeenMs) > STALE_THRESHOLD_MS;
    snprintf(a.label, sizeof(a.label), "%02X:%02X:%02X:%02X:%02X:%02X", trackerSnapshot[i].addr[0],
             trackerSnapshot[i].addr[1], trackerSnapshot[i].addr[2], trackerSnapshot[i].addr[3],
             trackerSnapshot[i].addr[4], trackerSnapshot[i].addr[5]);
    formatSignalSubtitle(a.subtitle, sizeof(a.subtitle), nullptr, trackerSnapshot[i].rssi,
                         trackerSnapshot[i].lastSeenMs, now, STALE_THRESHOLD_MS);
    snprintf(a.value, sizeof(a.value), "%s", tr(STR_TRACKER_DETECTED));
    alertCount++;
  }

  // Severity first, then fresh findings ahead of stale ones, then strongest
  // signal first -- useful for fox-hunting. See AirspaceMonitorActivity's
  // identical comparator for the full reasoning.
  std::stable_sort(alerts, alerts + alertCount, [](const PendingAlert& x, const PendingAlert& y) {
    if (x.severity != y.severity) return x.severity < y.severity;
    if (x.stale != y.stale) return !x.stale;
    return x.rssi > y.rssi;
  });

  rowCount = 0;
  fui::ListItem& control = rows[rowCount];
  control = fui::ListItem{};
  control.label = state == State::SCANNING ? tr(STR_CAPTURE_STOP) : tr(STR_CAPTURE_START);
  snprintf(controlValueText, sizeof(controlValueText), "%s", summary);
  control.value = controlValueText;
  control.actionValue = 0;
  rowCount++;

  for (int i = 0; i < alertCount; i++) {
    fui::ListItem& row = rows[rowCount];
    row = fui::ListItem{};
    row.label = alerts[i].label;
    if (alerts[i].subtitle[0] != '\0') row.subtitle = alerts[i].subtitle;
    row.value = alerts[i].value;
    row.actionValue = static_cast<int16_t>(rowCount);
    rowCount++;
  }
}

void BleFinderActivity::activateIndex(const int index) {
  if (index != 0) return;
  if (state == State::SCANNING) {
    stopScanning();
  } else {
    startScanning();
  }
}

void BleFinderActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  fui::ListProps props;
  props.items = rows;
  props.count = static_cast<uint16_t>(rowCount);
  props.action = ACTION_ROW;
  props.inputMask = fui::InputTouch;  // physical buttons stay in loop()
  props.valueInset = 8;
  props.labelText = screen.theme().smallText;
  props.labelText.maxLines = 1;
  syncListViewport(screen, props);
  screen.list(props);
}
