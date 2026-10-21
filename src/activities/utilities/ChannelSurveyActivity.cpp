#include "ChannelSurveyActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <atomic>
#include <cstdio>

#include "MappedInputManager.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
// Per-channel beacon tallies for the sweep in progress. A plain array (not a
// class member): esp_wifi_set_promiscuous_rx_cb takes a function pointer with
// no user-data argument, and only one Activity runs at a time, so one global
// table is enough. Index 0 is unused (channels are 1-based). Mutable static
// data lands in DRAM by default, which is what code reachable from the WiFi
// driver's RX path needs.
std::atomic<uint32_t> g_beaconCounts[ChannelSurveyActivity::LAST_CHANNEL + 1];

// Runs on the WiFi driver's internal task, not a hardware ISR (same
// assumption the SDK's NimBLE scan callback relies on for its host task), so
// this does not need IRAM_ATTR. Keep it cheap regardless: no heap, no logging
// on the hot path.
void onPromiscuousPacket(void* buf, const wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !buf) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  if (pkt->rx_ctrl.sig_len < 1) return;
  // 802.11 frame control, first byte: subtype(4) | type(2) | version(2).
  // Beacon = management (type 00) subtype 1000 -> 0x80. Every other frame
  // (probe, data, control, ...) is ignored; nothing past this byte is read.
  if (pkt->payload[0] != 0x80) return;
  const uint8_t ch = pkt->rx_ctrl.channel;
  if (ch >= ChannelSurveyActivity::FIRST_CHANNEL && ch <= ChannelSurveyActivity::LAST_CHANNEL) {
    g_beaconCounts[ch].fetch_add(1, std::memory_order_relaxed);
  }
}
}  // namespace

ChannelSurveyActivity::ChannelSurveyActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("ChannelSurvey", renderer, mappedInput) {
  for (uint8_t ch = FIRST_CHANNEL; ch <= LAST_CHANNEL; ch++) {
    snprintf(channelLabels[ch - FIRST_CHANNEL], sizeof(channelLabels[0]), "%s %u", tr(STR_CHANNEL_LABEL), ch);
  }
}

const char* ChannelSurveyActivity::headerTitle() const { return tr(STR_UTILITIES_CHANNEL_SURVEY); }

void ChannelSurveyActivity::onEnter() {
  UiListActivity::onEnter();
  LOG_DBG("CSURV", "Free heap at enter: %d bytes", ESP.getFreeHeap());

  // Acquire the radio: promiscuous mode needs the WiFi driver started but not
  // connected or scanning under us.
  priorWifiMode = static_cast<int>(WiFi.getMode());
  if ((priorWifiMode & WIFI_MODE_STA) == 0) {
    WiFi.mode(static_cast<wifi_mode_t>(priorWifiMode | WIFI_MODE_STA));
  }
  WiFi.disconnect();
  delay(100);

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    LOG_ERR("CSURV", "Failed to enable promiscuous mode");
    finishSweep();
    return;
  }
  promiscuousOn = true;

  startSweep();
}

void ChannelSurveyActivity::onExit() {
  UiListActivity::onExit();

  // Release the radio: leave promiscuous mode and restore the prior WiFi mode.
  if (promiscuousOn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuousOn = false;
  }
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));
  LOG_DBG("CSURV", "Free heap at exit: %d bytes", ESP.getFreeHeap());
}

void ChannelSurveyActivity::loop() {
  if (state == State::SCANNING && promiscuousOn) {
    if (millis() - channelStartMs >= DWELL_MS) {
      currentChannel++;
      if (currentChannel > LAST_CHANNEL) {
        finishSweep();
      } else {
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        channelStartMs = millis();
      }
    }
  }
  UiListActivity::loop();
}

void ChannelSurveyActivity::startSweep() {
  for (uint8_t ch = FIRST_CHANNEL; ch <= LAST_CHANNEL; ch++) {
    g_beaconCounts[ch].store(0, std::memory_order_relaxed);
  }
  currentChannel = FIRST_CHANNEL;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  channelStartMs = millis();

  {
    RenderLock lock(*this);
    state = State::SCANNING;
    snprintf(summary, sizeof(summary), "%s", tr(STR_SCANNING));
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();
}

void ChannelSurveyActivity::finishSweep() {
  uint32_t total = 0;
  {
    RenderLock lock(*this);
    state = State::DONE;
    for (uint8_t ch = FIRST_CHANNEL; ch <= LAST_CHANNEL; ch++) {
      const uint32_t count = g_beaconCounts[ch].load(std::memory_order_relaxed);
      total += count;
      snprintf(valueText[ch - FIRST_CHANNEL], sizeof(valueText[0]), "%u", static_cast<unsigned>(count));
    }
    if (total == 0) {
      snprintf(summary, sizeof(summary), "%s", tr(STR_NO_BEACONS));
    } else {
      snprintf(summary, sizeof(summary), tr(STR_BEACONS_HEARD), static_cast<unsigned>(total));
    }
    rebuildRows();
  }
  requestUpdate();
}

void ChannelSurveyActivity::rebuildRows() {
  rows[0] = fui::ListItem{};
  rows[0].label = tr(STR_RESCAN);
  rows[0].value = summary;
  rows[0].actionValue = 0;

  for (int i = 0; i < CHANNEL_COUNT; i++) {
    rows[i + 1] = fui::ListItem{};
    rows[i + 1].label = channelLabels[i];
    rows[i + 1].value = state == State::DONE ? valueText[i] : "";
    rows[i + 1].actionValue = static_cast<int16_t>(i + 1);
  }
}

void ChannelSurveyActivity::activateIndex(const int index) {
  if (index == 0 && state == State::DONE && promiscuousOn) startSweep();
}

void ChannelSurveyActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  fui::ListProps props;
  props.items = rows;
  props.count = listCount();
  props.action = ACTION_ROW;
  props.inputMask = fui::InputTouch;  // physical buttons stay in loop()
  props.valueInset = 8;
  props.labelText = screen.theme().smallText;
  props.labelText.maxLines = 1;
  syncListViewport(screen, props);
  screen.list(props);
}
