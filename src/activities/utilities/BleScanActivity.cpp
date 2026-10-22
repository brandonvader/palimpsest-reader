#include "BleScanActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <NimBLEDevice.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

#include "BleHuntingActivity.h"
#include "MappedInputManager.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
constexpr uint32_t SCAN_DURATION_MS = 6000;
// Continuous listening (window == interval) so scan responses and extended
// advertising data are not missed.
constexpr uint16_t SCAN_INTERVAL_MS = 100;

// BLE address types, not user prose: deliberately untranslated.
const char* addressTypeName(const uint8_t type) {
  switch (type) {
    case BLE_ADDR_PUBLIC:
      return "pub";
    case BLE_ADDR_RANDOM:
      return "rnd";
    default:
      return "rpa";
  }
}
}  // namespace

class ScanEndCallbacks : public NimBLEScanCallbacks {
 public:
  explicit ScanEndCallbacks(BleScanActivity& owner) : owner(owner) {}
  void onScanEnd(const NimBLEScanResults&, int) override { owner.markScanEnded(); }

 private:
  BleScanActivity& owner;
};

BleScanActivity::BleScanActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("BleScan", renderer, mappedInput) {}

BleScanActivity::~BleScanActivity() = default;

const char* BleScanActivity::headerTitle() const { return tr(STR_UTILITIES_BLE_SCAN); }

void BleScanActivity::onEnter() {
  UiListActivity::onEnter();
  LOG_DBG("BSCAN", "Free heap at enter: %d bytes", ESP.getFreeHeap());

  devices.reserve(MAX_DEVICES);

  if (!acquireBle()) {
    finishWithMessage(tr(STR_BLE_UNAVAILABLE));
    return;
  }
  startScan();
}

void BleScanActivity::onExit() {
  UiListActivity::onExit();
  releaseBle();
  LOG_DBG("BSCAN", "Free heap at exit: %d bytes", ESP.getFreeHeap());
}

bool BleScanActivity::acquireBle() {
  stackUp = NimBLEDevice::init("");
  if (!stackUp) {
    LOG_ERR("BSCAN", "NimBLE init failed");
    return false;
  }

  auto* scan = NimBLEDevice::getScan();
  callbacks = makeUniqueNoThrow<ScanEndCallbacks>(*this);
  if (!callbacks) {
    LOG_ERR("BSCAN", "OOM: scan callbacks");
    NimBLEDevice::deinit(true);
    stackUp = false;
    return false;
  }
  // wantDuplicates: scan responses (names) arrive as a second PDU from the same address.
  scan->setScanCallbacks(callbacks.get(), true);
  scan->setActiveScan(true);
  scan->setInterval(SCAN_INTERVAL_MS);
  scan->setWindow(SCAN_INTERVAL_MS);
  scan->setMaxResults(MAX_DEVICES);
#if CONFIG_BT_NIMBLE_EXT_ADV
  scan->setPhy(NimBLEScan::SCAN_ALL);
#endif
  return true;
}

void BleScanActivity::releaseBle() {
  // Stop any scan in flight, drop results, deinit.
  if (!stackUp) return;
  auto* scan = NimBLEDevice::getScan();
  if (scan->isScanning()) scan->stop();
  scan->clearResults();
  scan->setScanCallbacks(nullptr);
  NimBLEDevice::deinit(true);
  stackUp = false;
  callbacks.reset();
}

void BleScanActivity::loop() {
  if (state == State::SCANNING && stackUp && scanEnded.load()) collectResults();
  UiListActivity::loop();
}

void BleScanActivity::startScan() {
  {
    RenderLock lock(*this);
    state = State::SCANNING;
    devices.clear();
    snprintf(summary, sizeof(summary), "%s", tr(STR_SCANNING));
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();

  scanEnded.store(false);
  auto* scan = NimBLEDevice::getScan();
  scan->clearResults();
  if (!scan->start(SCAN_DURATION_MS, false, true)) {
    LOG_ERR("BSCAN", "Failed to start scan");
    scanEnded.store(true);  // surfaces as an empty result next loop pass
  }
}

void BleScanActivity::collectResults() {
  scanEnded.store(false);
  const NimBLEScanResults results = NimBLEDevice::getScan()->getResults();
  {
    RenderLock lock(*this);
    devices.clear();
    const int count = std::min(results.getCount(), static_cast<int>(MAX_DEVICES));
    for (int i = 0; i < count; i++) {
      const NimBLEAdvertisedDevice* dev = results.getDevice(i);
      if (!dev) continue;
      Device d{};
      if (dev->haveName()) strlcpy(d.name, dev->getName().c_str(), sizeof(d.name));
      snprintf(d.detail, sizeof(d.detail), "%s  %s%s", dev->getAddress().toString().c_str(),
               addressTypeName(dev->getAddressType()), dev->isConnectable() ? "  conn" : "");
      memcpy(d.addr, dev->getAddress().getVal(), 6);
      d.rssi = dev->getRSSI();
      snprintf(d.signal, sizeof(d.signal), "%d dBm", static_cast<int>(d.rssi));
      devices.push_back(d);
    }
    std::sort(devices.begin(), devices.end(), [](const Device& a, const Device& b) { return a.rssi > b.rssi; });

    state = State::DONE;
    if (devices.empty()) {
      snprintf(summary, sizeof(summary), "%s", tr(STR_BLE_NO_DEVICES));
    } else {
      snprintf(summary, sizeof(summary), tr(STR_BLE_DEVICES_FOUND), devices.size());
    }
    rebuildRows();
  }
  NimBLEDevice::getScan()->clearResults();
  requestUpdate();
}

void BleScanActivity::finishWithMessage(const char* message) {
  {
    RenderLock lock(*this);
    state = State::DONE;
    devices.clear();
    snprintf(summary, sizeof(summary), "%s", message);
    rebuildRows();
  }
  requestUpdate();
}

void BleScanActivity::rebuildRows() {
  rows.clear();
  rows.reserve(1 + devices.size());

  fui::ListItem rescan;
  rescan.label = tr(STR_RESCAN);
  rescan.value = summary;
  rescan.actionValue = 0;
  rows.push_back(rescan);

  for (size_t i = 0; i < devices.size(); i++) {
    fui::ListItem row;
    row.label = devices[i].name[0] ? devices[i].name : tr(STR_BLE_UNNAMED);
    row.subtitle = devices[i].detail;
    row.value = devices[i].signal;
    row.actionValue = static_cast<int16_t>(i + 1);
    rows.push_back(row);
  }
}

void BleScanActivity::activateIndex(const int index) {
  if (index == 0) {
    if (state == State::DONE && stackUp) startScan();
    return;
  }
  if (state != State::DONE) return;
  const size_t devIndex = static_cast<size_t>(index - 1);
  if (devIndex >= devices.size()) return;
  // Tap a row to hunt that device: launch straight into BleHuntingActivity
  // with its address preset.
  const Device& dev = devices[devIndex];
  app.clearTapFlash();
  // Hand the BLE stack to BleHuntingActivity WITHOUT deiniting it first:
  // NimBLEDevice::deinit() has an unbounded internal wait (see
  // BleHuntingActivity's class comment) that a deinit-then-reinit churn
  // around this push would needlessly risk. BleHuntingActivity borrows the
  // (already-ended) scan's callback slot instead and never touches init/
  // deinit for a preset target. Re-register our own callback and scan params
  // on return (acquireBle() no-ops the init() call since the stack was never
  // released) without touching the already-shown results list.
  startActivityForResult(
      std::make_unique<BleHuntingActivity>(renderer, mappedInput, dev.addr, dev.name[0] ? dev.name : nullptr),
      [this](const ActivityResult&) { acquireBle(); });
}

void BleScanActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  fui::ListProps props;
  props.items = rows.data();
  props.count = static_cast<uint16_t>(rows.size());
  props.action = ACTION_ROW;
  props.inputMask = fui::InputTouch;  // physical buttons stay in loop()
  props.valueInset = 8;
  props.labelText = screen.theme().smallText;
  props.labelText.maxLines = 1;
  syncListViewport(screen, props);
  screen.list(props);
}
