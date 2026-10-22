#include "WifiScanActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

#include "MappedInputManager.h"
#include "WifiHuntingActivity.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
constexpr uint32_t SCAN_MS_PER_CHANNEL = 300;

// Protocol names, not user prose: deliberately untranslated, like the chip
// names in AboutActivity.
const char* authName(const wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:
      return "Open";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK:
      return "WAPI";
    case WIFI_AUTH_OWE:
      return "OWE";
    default:
      return "Other";
  }
}
}  // namespace

WifiScanActivity::WifiScanActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("WifiScan", renderer, mappedInput) {}

const char* WifiScanActivity::headerTitle() const { return tr(STR_UTILITIES_WIFI_SCAN); }

void WifiScanActivity::onEnter() {
  UiListActivity::onEnter();
  LOG_DBG("WSCAN", "Free heap at enter: %d bytes", ESP.getFreeHeap());

  aps.reserve(MAX_APS);
  acquireRadio();
  startScan();
}

void WifiScanActivity::onExit() {
  UiListActivity::onExit();
  releaseRadio();
  LOG_DBG("WSCAN", "Free heap at exit: %d bytes", ESP.getFreeHeap());
}

void WifiScanActivity::acquireRadio() {
  // A scan needs STA. Saved-network auto-connect must not run.
  priorWifiMode = static_cast<int>(WiFi.getMode());
  if ((priorWifiMode & WIFI_MODE_STA) == 0) {
    WiFi.mode(static_cast<wifi_mode_t>(priorWifiMode | WIFI_MODE_STA));
    WiFi.disconnect();
    delay(100);
  }
}

void WifiScanActivity::releaseRadio() {
  // Stop any scan in flight and restore the prior mode.
  if (WiFi.scanComplete() == WIFI_SCAN_RUNNING) esp_wifi_scan_stop();
  WiFi.scanDelete();
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));
}

void WifiScanActivity::loop() {
  if (state == State::SCANNING) {
    const int16_t result = WiFi.scanComplete();
    if (result != WIFI_SCAN_RUNNING) collectResults(result);
  }
  UiListActivity::loop();
}

void WifiScanActivity::startScan() {
  {
    RenderLock lock(*this);
    state = State::SCANNING;
    aps.clear();
    snprintf(summary, sizeof(summary), "%s", tr(STR_SCANNING));
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();

  WiFi.scanDelete();
  if (WiFi.scanNetworks(true, true, false, SCAN_MS_PER_CHANNEL) == WIFI_SCAN_FAILED) {
    LOG_ERR("WSCAN", "Failed to start scan");
    collectResults(WIFI_SCAN_FAILED);
  }
}

void WifiScanActivity::collectResults(const int scanResult) {
  {
    RenderLock lock(*this);
    aps.clear();
    const int count = scanResult > 0 ? std::min(scanResult, static_cast<int>(MAX_APS)) : 0;
    for (int i = 0; i < count; i++) {
      AccessPoint ap{};
      strlcpy(ap.ssid, WiFi.SSID(i).c_str(), sizeof(ap.ssid));
      const uint8_t* bssid = WiFi.BSSID(i);
      ap.channel = static_cast<uint8_t>(WiFi.channel(i));
      if (bssid) {
        memcpy(ap.bssid, bssid, 6);
        snprintf(ap.detail, sizeof(ap.detail), "%02X:%02X:%02X:%02X:%02X:%02X  ch %d", bssid[0], bssid[1], bssid[2],
                 bssid[3], bssid[4], bssid[5], static_cast<int>(ap.channel));
      }
      ap.rssi = static_cast<int8_t>(WiFi.RSSI(i));
      snprintf(ap.signal, sizeof(ap.signal), "%d dBm  %s", static_cast<int>(ap.rssi), authName(WiFi.encryptionType(i)));
      aps.push_back(ap);
    }
    std::sort(aps.begin(), aps.end(), [](const AccessPoint& a, const AccessPoint& b) { return a.rssi > b.rssi; });

    state = State::DONE;
    if (aps.empty()) {
      snprintf(summary, sizeof(summary), "%s", tr(STR_NO_NETWORKS));
    } else {
      snprintf(summary, sizeof(summary), tr(STR_NETWORKS_FOUND), aps.size());
    }
    rebuildRows();
  }
  WiFi.scanDelete();
  requestUpdate();
}

void WifiScanActivity::rebuildRows() {
  rows.clear();
  rows.reserve(1 + aps.size());

  fui::ListItem rescan;
  rescan.label = tr(STR_RESCAN);
  rescan.value = summary;
  rescan.actionValue = 0;
  rows.push_back(rescan);

  for (size_t i = 0; i < aps.size(); i++) {
    fui::ListItem row;
    row.label = aps[i].ssid[0] ? aps[i].ssid : tr(STR_WIFI_HIDDEN);
    row.subtitle = aps[i].detail;
    row.value = aps[i].signal;
    row.actionValue = static_cast<int16_t>(i + 1);
    rows.push_back(row);
  }
}

void WifiScanActivity::activateIndex(const int index) {
  if (index == 0) {
    if (state == State::DONE) startScan();
    return;
  }
  const size_t apIndex = static_cast<size_t>(index - 1);
  if (apIndex >= aps.size()) return;
  // Tap a row to hunt that access point: launch straight into WifiHuntingActivity
  // with its BSSID and already-known channel preset, skipping discovery.
  const AccessPoint& ap = aps[apIndex];
  app.clearTapFlash();
  // Hand off to WifiHuntingActivity WITHOUT releasing the radio first: this
  // screen's scan has already finished by the time a row is tappable (state
  // == DONE), so WiFi is just sitting in STA mode with nothing in flight --
  // there's nothing to protect by releasing it. Releasing it here would leave
  // WiFi mode at OFF/NULL, which WifiHuntingActivity would then read as its
  // own "prior" mode and try to restore on its own Stop -- a transition
  // through Arduino-ESP32's espWiFiStop(), an internal shutdown path with an
  // unbounded wait best avoided. Leaving WiFi in STA here means Hunting's own
  // Stop just restores STA -> STA, a no-op that never reaches espWiFiStop().
  // acquireRadio() on return is a defensive no-op (mode never changed) that
  // also re-affirms STA if anything did.
  startActivityForResult(std::make_unique<WifiHuntingActivity>(renderer, mappedInput, ap.bssid, ap.channel,
                                                               ap.ssid[0] ? ap.ssid : nullptr),
                         [this](const ActivityResult&) { acquireRadio(); });
}

void WifiScanActivity::buildScreen(UiScreen& screen) {
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
