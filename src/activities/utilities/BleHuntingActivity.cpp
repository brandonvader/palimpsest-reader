#include "BleHuntingActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <NimBLEDevice.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "MacAddress.h"
#include "MappedInputManager.h"
#include "SignalGauge.h"
#include "SignalStrength.h"
#include "activities/RenderLock.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;
uint8_t g_targetAddr[6] = {};
bool g_hasSighting = false;
int8_t g_rssi = -128;
uint32_t g_lastSeenMs = 0;

class HuntCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    if (!dev) return;
    uint8_t addr[6];
    memcpy(addr, dev->getAddress().getVal(), 6);
    portENTER_CRITICAL(&g_mux);
    if (memcmp(addr, g_targetAddr, 6) == 0) {
      g_hasSighting = true;
      g_rssi = static_cast<int8_t>(dev->getRSSI());
      g_lastSeenMs = millis();
    }
    portEXIT_CRITICAL(&g_mux);
  }
};

HuntCallbacks g_callbacks;
}  // namespace

BleHuntingActivity::BleHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput,
                                       const uint8_t targetAddrIn[6], const char* label)
    : UiListActivity("BleHunting", renderer, mappedInput), hasTarget(true) {
  memcpy(targetAddr, targetAddrIn, 6);
  if (label) strlcpy(targetLabel, label, sizeof(targetLabel));
}

BleHuntingActivity::BleHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("BleHunting", renderer, mappedInput) {}

const char* BleHuntingActivity::headerTitle() const { return tr(STR_UTILITIES_BLE_HUNTING); }

void BleHuntingActivity::onEnter() {
  UiListActivity::onEnter();
  if (hasTarget) {
    startHunting();
  } else {
    state = State::ENTER_ADDRESS;
    rebuildRows();
    promptForAddress(tr(STR_HUNT_ENTER_ADDRESS), "");
  }
}

void BleHuntingActivity::onExit() {
  if (state == State::SCANNING) stopHunting(/*forTeardown=*/true);
  UiListActivity::onExit();
}

void BleHuntingActivity::promptForAddress(const char* title, const std::string& initialText) {
  startActivityForResult(
      std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, title, initialText,
                                              17,  // "AA:BB:CC:DD:EE:FF"
                                              InputType::Text),
      [this](const ActivityResult& result) {
        if (result.isCancelled) {
          finish();
          return;
        }
        const std::string text = std::get<KeyboardResult>(result.data).text;
        uint8_t addr[6];
        if (!parseMacAddress(text, addr)) {
          promptForAddress(tr(STR_HUNT_INVALID_ADDRESS), text);
          return;
        }
        memcpy(targetAddr, addr, 6);
        targetLabel[0] = '\0';
        startHunting();
      });
}

void BleHuntingActivity::startHunting() {
  // A preset target (hasTarget) always comes from a "Hunt this" row action on
  // BleScanActivity/BleFinderActivity, which keeps the NimBLE stack
  // initialized for the duration of the push rather than deiniting it -- see
  // the class comment on why. Only the standalone (manual-entry) launch owns
  // the stack's init/deinit lifecycle itself.
  if (!hasTarget) {
    stackUp = NimBLEDevice::init("");
    if (!stackUp) {
      LOG_ERR("BHUNT", "NimBLE init failed");
      RenderLock lock(*this);
      state = State::STOPPED;
      rebuildRows();
      requestUpdate();
      return;
    }
  }

  portENTER_CRITICAL(&g_mux);
  memcpy(g_targetAddr, targetAddr, 6);
  g_hasSighting = false;
  g_rssi = -128;
  g_lastSeenMs = 0;
  portEXIT_CRITICAL(&g_mux);
  everSeen = false;
  rssi = -128;
  lastSeenMs = 0;

  // Borrow the scan already running (BleFinderActivity) or just park it
  // (BleScanActivity, whose own time-boxed scan has already ended by the time
  // its results are tappable) by swapping in our own callback; only actually
  // start a new scan if nothing is running yet.
  auto* scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(&g_callbacks, true);
  if (!scan->isScanning()) {
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(100);
    if (!scan->start(0, false, true)) {  // 0 = scan until stopped
      LOG_ERR("BHUNT", "Failed to start BLE scan");
      if (!hasTarget) {
        NimBLEDevice::deinit(true);
        stackUp = false;
      }
      RenderLock lock(*this);
      state = State::STOPPED;
      rebuildRows();
      requestUpdate();
      return;
    }
  }

  rearmMs = millis();
  lastUpdateMs = millis();

  {
    RenderLock lock(*this);
    state = State::SCANNING;
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();
}

void BleHuntingActivity::stopHunting(const bool forTeardown) {
  auto* scan = NimBLEDevice::getScan();
  if (!hasTarget) {
    // Standalone launch: own the stack, so fully stop and release it.
    // Wait for onScanEnd before deinit: stop() only requests cancellation and
    // returns before the host task has processed it, and deinit() racing that
    // cancellation crashed inside NimBLE's own teardown during BLE Capture --
    // see palimpsest-ble-capture-crash (project memory) for the full root
    // cause. Reused verbatim from BleFinderActivity::stopScanning().
    if (stackUp) {
      static volatile bool scanEnded = false;
      class OnceCallbacks : public NimBLEScanCallbacks {
        void onScanEnd(const NimBLEScanResults&, int) override { scanEnded = true; }
      };
      static OnceCallbacks onceCallbacks;
      scanEnded = false;
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
      // NimBLEDevice::deinit() calls nimble_port_stop(), which does an
      // UNBOUNDED internal wait (ble_npl_sem_pend(..., BLE_NPL_TIME_FOREVER))
      // for the NimBLE host's own stop procedure to complete -- our code has
      // no way to time that out if it never does (confirmed by reading
      // NimBLE-Arduino's own source, not by reproducing a hang from this
      // specific call -- the hangs actually reproduced during development
      // turned out to be the render-lock double-acquisition fixed by the
      // `forTeardown` parameter below). Calling it as rarely as possible is
      // still the only mitigation available at this layer for the risk that
      // IS confirmed to exist; a shared-stack hunt (hasTarget) avoids it
      // entirely by never touching init/deinit in the first place.
      NimBLEDevice::deinit(true);
      stackUp = false;
    }
  } else {
    // Shared stack (borrowed from BleScanActivity/BleFinderActivity): just
    // drop our callback and leave the scan itself running for whichever
    // screen handed it to us to reclaim.
    scan->setScanCallbacks(nullptr);
  }

  // onExit() (forTeardown) runs while ActivityManager already holds the
  // render lock -- see WifiHuntingActivity::stopHunting()'s identical
  // comment for the full explanation. The activity is also about to be
  // destroyed, so there is nothing left to render anyway.
  if (forTeardown) return;

  RenderLock lock(*this);
  state = State::STOPPED;
  rebuildRows();
  requestUpdate();
}

void BleHuntingActivity::loop() {
  if (state == State::SCANNING) {
    if (millis() - rearmMs >= REARM_MS) {
      NimBLEDevice::getScan()->clearResults();
      rearmMs = millis();
    }
    if (millis() - lastUpdateMs >= UPDATE_MS) {
      lastUpdateMs = millis();
      bool saw;
      int8_t sawRssi;
      uint32_t sawLastSeenMs;
      portENTER_CRITICAL(&g_mux);
      saw = g_hasSighting;
      sawRssi = g_rssi;
      sawLastSeenMs = g_lastSeenMs;
      portEXIT_CRITICAL(&g_mux);
      if (saw) {
        everSeen = true;
        rssi = sawRssi;
        lastSeenMs = sawLastSeenMs;
      }
      {
        RenderLock lock(*this);
        rebuildRows();
      }
      requestUpdate();
    }
  }
  UiListActivity::loop();
}

void BleHuntingActivity::rebuildRows() {
  rowCount = 0;
  fui::ListItem& control = rows[rowCount++];
  control = fui::ListItem{};
  switch (state) {
    case State::ENTER_ADDRESS:
      control.label = tr(STR_HUNT_ENTER_ADDRESS);
      controlValueText[0] = '\0';
      break;
    case State::SCANNING:
      control.label = tr(STR_HUNT_STOP);
      snprintf(controlValueText, sizeof(controlValueText), "%s", tr(STR_HUNT_TRACKING));
      break;
    case State::STOPPED:
      control.label = tr(STR_HUNT_START);
      snprintf(controlValueText, sizeof(controlValueText), "%s", tr(STR_RESCAN));
      break;
  }
  control.value = controlValueText;
  control.actionValue = 0;

  if (state == State::ENTER_ADDRESS) return;  // nothing else to show until an address is set

  fui::ListItem& target = rows[rowCount++];
  target = fui::ListItem{};
  target.label = targetLabel[0] ? targetLabel : tr(STR_HUNT_UNKNOWN_DEVICE);
  snprintf(addressRowValue, sizeof(addressRowValue), "%02X:%02X:%02X:%02X:%02X:%02X", targetAddr[0], targetAddr[1],
           targetAddr[2], targetAddr[3], targetAddr[4], targetAddr[5]);
  target.value = addressRowValue;
  formatSignalSubtitle(signalSubtitle, sizeof(signalSubtitle), nullptr, rssi, lastSeenMs, millis(), STALE_THRESHOLD_MS);
  target.subtitle = signalSubtitle;
  target.actionValue = 1;
}

void BleHuntingActivity::activateIndex(const int index) {
  if (index != 0) return;
  switch (state) {
    case State::ENTER_ADDRESS:
      break;  // control row isn't interactive until the keyboard flow resolves
    case State::SCANNING:
      stopHunting();
      break;
    case State::STOPPED:
      startHunting();
      break;
  }
}

void BleHuntingActivity::drawChrome() {
  UiListActivity::drawChrome();
  if (state == State::ENTER_ADDRESS) return;
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int bandTop = metrics.topPadding + metrics.headerHeight;
  const int cx = renderer.getScreenWidth() / 2;
  const int cy = bandTop + GAUGE_HEIGHT / 2;
  const int outerRadius = std::min(GAUGE_HEIGHT, static_cast<int>(renderer.getScreenWidth())) / 2 - GAUGE_MARGIN;
  signalgauge::draw(renderer, cx, cy, outerRadius, rssi, everSeen, (millis() - lastSeenMs) > STALE_THRESHOLD_MS);
}

void BleHuntingActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int topMargin =
      metrics.topPadding + metrics.headerHeight + (state == State::ENTER_ADDRESS ? 0 : GAUGE_HEIGHT);
  screen.setContentMarginFromScreen(
      fui::Insets{static_cast<int16_t>(topMargin), 0, static_cast<int16_t>(metrics.buttonHintsHeight), 0});
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
