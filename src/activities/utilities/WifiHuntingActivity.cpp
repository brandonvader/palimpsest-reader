#include "WifiHuntingActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_wifi.h>

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
// Non-QoS management frame header: FrameControl(2) Duration(2) Addr1(6)
// Addr2(6) Addr3(6) SeqCtrl(2) -- same layout AirspaceMonitorActivity parses.
// Addr2 is the transmitter: a beacon's is the AP's own BSSID, a probe
// request's is the sending client's, so matching it covers hunting either an
// AP or a client by address.
constexpr size_t ADDR2_OFFSET = 10;
constexpr size_t MGMT_HEADER_LEN = 24;

portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;
uint8_t g_targetAddr[6] = {};
volatile bool g_hunting = false;
bool g_hasSighting = false;
int8_t g_rssi = -128;
uint32_t g_lastSeenMs = 0;
uint8_t g_sightingChannel = 0;

// Runs on the WiFi driver's internal task, not a hardware ISR (same
// assumption as AirspaceMonitorActivity/ChannelSurveyActivity), so plain
// portENTER_CRITICAL is correct here.
void onPromiscuousPacket(void* buf, const wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !buf || !g_hunting) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  if (pkt->rx_ctrl.sig_len < MGMT_HEADER_LEN) return;
  const uint8_t* transmitter = &pkt->payload[ADDR2_OFFSET];
  portENTER_CRITICAL(&g_mux);
  if (memcmp(transmitter, g_targetAddr, 6) == 0) {
    g_hasSighting = true;
    g_rssi = pkt->rx_ctrl.rssi;
    g_lastSeenMs = millis();
    g_sightingChannel = pkt->rx_ctrl.channel;
  }
  portEXIT_CRITICAL(&g_mux);
}
}  // namespace

WifiHuntingActivity::WifiHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput,
                                         const uint8_t targetAddrIn[6], const uint8_t channel, const char* label)
    : UiListActivity("WifiHunting", renderer, mappedInput), hasTarget(true), presetChannel(channel) {
  memcpy(targetAddr, targetAddrIn, 6);
  if (label) strlcpy(targetLabel, label, sizeof(targetLabel));
}

WifiHuntingActivity::WifiHuntingActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("WifiHunting", renderer, mappedInput) {}

const char* WifiHuntingActivity::headerTitle() const { return tr(STR_UTILITIES_WIFI_HUNTING); }

void WifiHuntingActivity::onEnter() {
  UiListActivity::onEnter();
  if (hasTarget) {
    startHunting(presetChannel);
  } else {
    state = State::ENTER_ADDRESS;
    rebuildRows();
    promptForAddress(tr(STR_HUNT_ENTER_ADDRESS), "");
  }
}

void WifiHuntingActivity::onExit() {
  if (state == State::DISCOVERING || state == State::LOCKED) stopHunting(/*forTeardown=*/true);
  UiListActivity::onExit();
}

void WifiHuntingActivity::promptForAddress(const char* title, const std::string& initialText) {
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
        startHunting(0);
      });
}

void WifiHuntingActivity::startHunting(const uint8_t preset) {
  priorWifiMode = static_cast<int>(WiFi.getMode());
  if ((priorWifiMode & WIFI_MODE_STA) == 0) {
    WiFi.mode(static_cast<wifi_mode_t>(priorWifiMode | WIFI_MODE_STA));
  }
  WiFi.disconnect();
  delay(100);

  portENTER_CRITICAL(&g_mux);
  memcpy(g_targetAddr, targetAddr, 6);
  g_hasSighting = false;
  g_rssi = -128;
  g_lastSeenMs = 0;
  g_sightingChannel = 0;
  portEXIT_CRITICAL(&g_mux);
  everSeen = false;
  rssi = -128;
  lastSeenMs = 0;

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    LOG_ERR("WHUNT", "Failed to enable promiscuous mode");
    WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));
    RenderLock lock(*this);
    state = State::STOPPED;
    rebuildRows();
    requestUpdate();
    return;
  }
  promiscuousOn = true;
  g_hunting = true;

  if (preset >= FIRST_CHANNEL && preset <= LAST_CHANNEL) {
    lockedChannel = preset;
    currentChannel = preset;
    esp_wifi_set_channel(lockedChannel, WIFI_SECOND_CHAN_NONE);
    state = State::LOCKED;
  } else {
    lockedChannel = 0;
    currentChannel = FIRST_CHANNEL;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    state = State::DISCOVERING;
  }
  channelStartMs = millis();
  lastUpdateMs = millis();

  {
    RenderLock lock(*this);
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();
}

void WifiHuntingActivity::stopHunting(const bool forTeardown) {
  g_hunting = false;
  if (promiscuousOn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuousOn = false;
  }
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));

  // onExit() (forTeardown) runs while ActivityManager already holds the
  // render lock. RenderLock's mutex is not recursive, so acquiring a second
  // one on the same task below would deadlock it forever; the activity is
  // also about to be destroyed, so there is nothing left to render anyway.
  // Same pattern as FrameCaptureActivity/BleCaptureActivity's
  // StopReason::TEARDOWN early return.
  if (forTeardown) return;

  RenderLock lock(*this);
  state = State::STOPPED;
  rebuildRows();
  requestUpdate();
}

void WifiHuntingActivity::pollRadio() {
  if (state == State::DISCOVERING && millis() - channelStartMs >= DWELL_MS) {
    currentChannel = currentChannel >= LAST_CHANNEL ? FIRST_CHANNEL : currentChannel + 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    channelStartMs = millis();
  }

  bool saw;
  int8_t sawRssi;
  uint32_t sawLastSeenMs;
  uint8_t sawChannel;
  portENTER_CRITICAL(&g_mux);
  saw = g_hasSighting;
  sawRssi = g_rssi;
  sawLastSeenMs = g_lastSeenMs;
  sawChannel = g_sightingChannel;
  portEXIT_CRITICAL(&g_mux);

  if (saw) {
    everSeen = true;
    rssi = sawRssi;
    lastSeenMs = sawLastSeenMs;
    if (state == State::DISCOVERING) {
      lockedChannel = sawChannel;
      esp_wifi_set_channel(lockedChannel, WIFI_SECOND_CHAN_NONE);
      state = State::LOCKED;
    }
  }

  if (state == State::LOCKED && millis() - lastSeenMs > STALE_THRESHOLD_MS) {
    // Quiet on this channel for a while -- it may have moved; resume the sweep.
    state = State::DISCOVERING;
    lockedChannel = 0;
    currentChannel = FIRST_CHANNEL;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    channelStartMs = millis();
  }
}

void WifiHuntingActivity::loop() {
  if (state == State::DISCOVERING || state == State::LOCKED) {
    pollRadio();
    if (millis() - lastUpdateMs >= UPDATE_MS) {
      lastUpdateMs = millis();
      {
        RenderLock lock(*this);
        rebuildRows();
      }
      requestUpdate();
    }
  }
  UiListActivity::loop();
}

void WifiHuntingActivity::rebuildRows() {
  rowCount = 0;
  fui::ListItem& control = rows[rowCount++];
  control = fui::ListItem{};
  switch (state) {
    case State::ENTER_ADDRESS:
      control.label = tr(STR_HUNT_ENTER_ADDRESS);
      controlValueText[0] = '\0';
      break;
    case State::DISCOVERING:
    case State::LOCKED:
      control.label = tr(STR_HUNT_STOP);
      snprintf(controlValueText, sizeof(controlValueText), "%s",
               state == State::LOCKED ? tr(STR_HUNT_LOCKED) : tr(STR_SCANNING));
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

  fui::ListItem& channel = rows[rowCount++];
  channel = fui::ListItem{};
  channel.label = tr(STR_CHANNEL_LABEL);
  if (lockedChannel > 0) {
    snprintf(channelRowValue, sizeof(channelRowValue), "%u", static_cast<unsigned>(lockedChannel));
  } else {
    snprintf(channelRowValue, sizeof(channelRowValue), "%s", tr(STR_SCANNING));
  }
  channel.value = channelRowValue;
  channel.actionValue = 2;
}

void WifiHuntingActivity::activateIndex(const int index) {
  if (index != 0) return;
  switch (state) {
    case State::ENTER_ADDRESS:
      break;  // control row isn't interactive until the keyboard flow resolves
    case State::DISCOVERING:
    case State::LOCKED:
      stopHunting();
      break;
    case State::STOPPED:
      startHunting(lockedChannel);  // retry on the last known channel, if any
      break;
  }
}

void WifiHuntingActivity::drawChrome() {
  UiListActivity::drawChrome();
  if (state == State::ENTER_ADDRESS) return;
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int bandTop = metrics.topPadding + metrics.headerHeight;
  const int cx = renderer.getScreenWidth() / 2;
  const int cy = bandTop + GAUGE_HEIGHT / 2;
  const int outerRadius = std::min(GAUGE_HEIGHT, static_cast<int>(renderer.getScreenWidth())) / 2 - GAUGE_MARGIN;
  signalgauge::draw(renderer, cx, cy, outerRadius, rssi, everSeen, (millis() - lastSeenMs) > STALE_THRESHOLD_MS);
}

void WifiHuntingActivity::buildScreen(UiScreen& screen) {
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
