#include "FrameCaptureActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalMemory.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>

#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
constexpr size_t RING_SLOTS = 64;
constexpr size_t SNAPLEN = 512;  // longest frame body kept per record; longer frames are truncated

constexpr uint32_t DLT_IEEE802_11_RADIOTAP = 127;  // http://www.tcpdump.org/linktypes.html

// Minimal radiotap header carrying just Channel (bit 3) and dBm Antenna
// Signal (bit 5). Field order follows increasing bit number and each field
// sits at the offset its own size requires from the header start, per the
// radiotap spec (https://www.radiotap.org/). Packed so sizeof() matches the
// on-wire layout exactly -- natural struct alignment would pad this to a
// 4-byte multiple and corrupt the format.
#pragma pack(push, 1)
struct RadiotapHeader {
  uint8_t version = 0;
  uint8_t pad = 0;
  uint16_t length = sizeof(RadiotapHeader);
  uint32_t present = 0;
  uint16_t channelFreqMhz = 0;  // bit 3
  uint16_t channelFlags = 0;    // bit 3
  int8_t antennaSignalDbm = 0;  // bit 5
};
#pragma pack(pop)

constexpr uint32_t RADIOTAP_PRESENT_CHANNEL = 1u << 3;
constexpr uint32_t RADIOTAP_PRESENT_DBM_ANTSIGNAL = 1u << 5;
constexpr uint16_t RADIOTAP_CHANNEL_FLAG_2GHZ = 0x0080;

uint16_t channelToFreqMhz(const uint8_t channel) {
  // 2.4 GHz channel center frequencies, channels 1-13 (802.11).
  if (channel >= 1 && channel <= 13) return static_cast<uint16_t>(2407 + channel * 5);
  return 2412;  // fallback: channel 1
}

struct CapturedFrame {
  uint32_t tsSec = 0;
  uint32_t tsUsec = 0;
  uint8_t channel = 0;
  int8_t rssi = 0;
  uint16_t len = 0;      // bytes actually stored in data[] (<= SNAPLEN)
  uint16_t origLen = 0;  // true length on the wire, pre-truncation
  uint8_t data[SNAPLEN];
};

// Fixed-capacity SPSC ring in PSRAM: the promiscuous RX callback (producer,
// runs on the WiFi driver's task) enqueues; loop() (consumer, the activity's
// own task) drains it into the pcap file. Spinlock-guarded, same pattern as
// the SDK's BleKeyboardHost key-event ring
// (freeink-sdk/libs/network/BleKeyboardHost) -- not a class member, since
// esp_wifi_set_promiscuous_rx_cb takes a plain function pointer with no
// user-data argument, and only one Activity runs at a time.
portMUX_TYPE g_ringMux = portMUX_INITIALIZER_UNLOCKED;
HalMemory::PsramBuffer g_ringStorage;
CapturedFrame* g_ring = nullptr;
volatile size_t g_ringHead = 0;
volatile size_t g_ringTail = 0;
volatile uint32_t g_ringDropped = 0;
volatile bool g_capturing = false;

bool ringAllocate() {
  g_ringStorage = HalMemory::allocatePsram(sizeof(CapturedFrame) * RING_SLOTS);
  g_ring = reinterpret_cast<CapturedFrame*>(g_ringStorage.get());
  g_ringHead = 0;
  g_ringTail = 0;
  g_ringDropped = 0;
  return g_ring != nullptr;
}

void ringFree() {
  g_ring = nullptr;
  g_ringStorage.reset();
}

// Runs on the WiFi driver's internal task, not a hardware ISR (same
// assumption ChannelSurveyActivity's callback relies on), so plain
// portENTER_CRITICAL (not the _ISR variant) is correct here, matching
// BleKeyboardHost's ring. Keep this cheap: no heap, no SD I/O, no logging.
void onPromiscuousPacket(void* buf, const wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !buf || !g_capturing || !g_ring) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint16_t sigLen = pkt->rx_ctrl.sig_len;
  if (sigLen < 1) return;
  // The driver filter already restricts delivery to WIFI_PKT_MGMT (beacon,
  // probe request/response, assoc, auth, ...); no per-subtype filtering here,
  // unlike ChannelSurveyActivity, which only wants beacons.

  portENTER_CRITICAL(&g_ringMux);
  const size_t next = (g_ringHead + 1) % RING_SLOTS;
  if (next == g_ringTail) {
    g_ringDropped = g_ringDropped + 1;  // ring full: drop the newest frame, keep draining the rest
    portEXIT_CRITICAL(&g_ringMux);
    return;
  }
  CapturedFrame& slot = g_ring[g_ringHead];
  slot.tsSec = static_cast<uint32_t>(micros() / 1000000);
  slot.tsUsec = static_cast<uint32_t>(micros() % 1000000);
  slot.channel = pkt->rx_ctrl.channel;
  slot.rssi = pkt->rx_ctrl.rssi;
  slot.origLen = sigLen;
  slot.len = sigLen > SNAPLEN ? SNAPLEN : sigLen;
  memcpy(slot.data, pkt->payload, slot.len);
  g_ringHead = next;
  portEXIT_CRITICAL(&g_ringMux);
}
}  // namespace

FrameCaptureActivity::FrameCaptureActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("FrameCapture", renderer, mappedInput) {}

const char* FrameCaptureActivity::headerTitle() const { return tr(STR_UTILITIES_FRAME_CAPTURE); }

void FrameCaptureActivity::onEnter() {
  UiListActivity::onEnter();
  snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_IDLE));
  rebuildRow();
}

void FrameCaptureActivity::onExit() {
  if (state == State::CAPTURING) stopCapture(StopReason::TEARDOWN);
  UiListActivity::onExit();
}

void FrameCaptureActivity::loop() {
  if (state == State::CAPTURING) {
    drainRing();

    if (millis() - channelStartMs >= DWELL_MS) {
      currentChannel = currentChannel >= LAST_CHANNEL ? FIRST_CHANNEL : currentChannel + 1;
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      channelStartMs = millis();
    }

    if (writer.frameCount() >= MAX_FRAMES) {
      stopCapture(StopReason::FRAME_LIMIT);
    } else if (writer.bytesWritten() >= MAX_BYTES) {
      stopCapture(StopReason::SIZE_LIMIT);
    } else if (millis() - captureStartMs >= MAX_DURATION_MS) {
      stopCapture(StopReason::TIME_LIMIT);
    } else if (millis() - lastStatusMs >= STATUS_REFRESH_MS) {
      // Periodic status refresh during an open-ended capture, same pattern as
      // SdFirmwareUpdateActivity's progress bar: an occasional aggregate
      // counter, not a live stream of individual results.
      lastStatusMs = millis();
      {
        RenderLock lock(*this);
        snprintf(statusText, sizeof(statusText), tr(STR_CAPTURE_PROGRESS), static_cast<unsigned>(writer.frameCount()),
                 static_cast<unsigned>(writer.bytesWritten() / 1024));
        rebuildRow();
      }
      requestUpdate();
    }
  }
  UiListActivity::loop();
}

void FrameCaptureActivity::drainRing() {
  for (;;) {
    static CapturedFrame frame;  // reused scratch; drainRing always runs on this activity's own task
    bool got = false;
    portENTER_CRITICAL(&g_ringMux);
    if (g_ringTail != g_ringHead) {
      frame = g_ring[g_ringTail];
      g_ringTail = (g_ringTail + 1) % RING_SLOTS;
      got = true;
    }
    portEXIT_CRITICAL(&g_ringMux);
    if (!got) break;

    // Prefix a radiotap header (channel + RSSI) onto the frame so Wireshark
    // shows those columns; reused scratch, same reasoning as `frame` above.
    static uint8_t record[sizeof(RadiotapHeader) + SNAPLEN];
    RadiotapHeader radiotap{};
    radiotap.present = RADIOTAP_PRESENT_CHANNEL | RADIOTAP_PRESENT_DBM_ANTSIGNAL;
    radiotap.channelFreqMhz = channelToFreqMhz(frame.channel);
    radiotap.channelFlags = RADIOTAP_CHANNEL_FLAG_2GHZ;
    radiotap.antennaSignalDbm = frame.rssi;
    memcpy(record, &radiotap, sizeof(radiotap));
    memcpy(record + sizeof(radiotap), frame.data, frame.len);

    if (!writer.writeRecord(record, sizeof(radiotap) + frame.len, sizeof(radiotap) + frame.origLen, frame.tsSec,
                            frame.tsUsec)) {
      stopCapture(StopReason::WRITE_ERROR);
      return;
    }
  }
}

std::string FrameCaptureActivity::buildCapturePath() const {
  char stamp[24] = {};
  struct tm timeinfo{};
  if (halClock.isAvailable() && halClock.localTime(timeinfo)) {
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &timeinfo);
  } else {
    // No RTC (or not synced): fall back to a boot-relative stamp. Still
    // unique within a boot session, which is all collision-avoidance needs.
    snprintf(stamp, sizeof(stamp), "boot-%lu", static_cast<unsigned long>(millis()));
  }
  char path[96];
  snprintf(path, sizeof(path), "%s/wifi-capture-%s.pcap", CAPTURE_DIR, stamp);
  return std::string(path);
}

void FrameCaptureActivity::failToStart() {
  if (promiscuousOn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuousOn = false;
  }
  writer.close();
  ringFree();
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));

  RenderLock lock(*this);
  snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_UNAVAILABLE));
  rebuildRow();
  requestUpdate();
}

void FrameCaptureActivity::startCapture() {
  if (!ringAllocate()) {
    LOG_ERR("CAP", "OOM: capture ring (PSRAM)");
    failToStart();
    return;
  }

  // Acquire the radio: promiscuous mode needs the WiFi driver started but not
  // connected or scanning under us (same acquire as ChannelSurveyActivity).
  priorWifiMode = static_cast<int>(WiFi.getMode());
  if ((priorWifiMode & WIFI_MODE_STA) == 0) {
    WiFi.mode(static_cast<wifi_mode_t>(priorWifiMode | WIFI_MODE_STA));
  }
  WiFi.disconnect();
  delay(100);

  if (!Storage.ensureDirectoryExists(CAPTURE_DIR)) {
    LOG_ERR("CAP", "Failed to create %s", CAPTURE_DIR);
    failToStart();
    return;
  }

  capturePath = buildCapturePath();
  if (!writer.open(capturePath, DLT_IEEE802_11_RADIOTAP, sizeof(RadiotapHeader) + SNAPLEN)) {
    failToStart();
    return;
  }

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    LOG_ERR("CAP", "Failed to enable promiscuous mode");
    failToStart();
    return;
  }
  promiscuousOn = true;
  g_capturing = true;
  LOG_DBG("CAP", "Capture started: %s, free heap %d bytes", capturePath.c_str(), ESP.getFreeHeap());

  currentChannel = FIRST_CHANNEL;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  channelStartMs = millis();
  captureStartMs = millis();
  lastStatusMs = millis();

  {
    RenderLock lock(*this);
    state = State::CAPTURING;
    snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_STARTING));
    rebuildRow();
    activeNav().reset();
  }
  requestUpdate();
}

void FrameCaptureActivity::stopCapture(const StopReason reason) {
  g_capturing = false;
  if (promiscuousOn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuousOn = false;
  }
  drainRing();  // flush whatever is left in the ring before closing the file
  const uint32_t frames = writer.frameCount();
  const uint64_t bytes = writer.bytesWritten();
  writer.close();
  ringFree();
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));
  LOG_DBG("CAP", "Capture stopped (reason=%d): %u frames, %llu bytes, free heap %d bytes", static_cast<int>(reason),
          static_cast<unsigned>(frames), static_cast<unsigned long long>(bytes), ESP.getFreeHeap());

  if (reason == StopReason::TEARDOWN) return;  // activity is exiting; no UI update needed

  RenderLock lock(*this);
  state = State::STOPPED;
  switch (reason) {
    case StopReason::FRAME_LIMIT:
    case StopReason::SIZE_LIMIT:
    case StopReason::TIME_LIMIT:
      snprintf(statusText, sizeof(statusText), tr(STR_CAPTURE_STOPPED_LIMIT), static_cast<unsigned>(frames),
               static_cast<unsigned>(bytes / 1024));
      break;
    case StopReason::WRITE_ERROR:
      snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_WRITE_ERROR));
      break;
    default:
      snprintf(statusText, sizeof(statusText), tr(STR_CAPTURE_DONE), static_cast<unsigned>(frames),
               static_cast<unsigned>(bytes / 1024));
      break;
  }
  rebuildRow();
  requestUpdate();
}

void FrameCaptureActivity::activateIndex(const int index) {
  if (index != 0) return;
  if (state == State::CAPTURING) {
    stopCapture(StopReason::USER);
  } else {
    startCapture();
  }
}

void FrameCaptureActivity::rebuildRow() {
  row = fui::ListItem{};
  row.label = state == State::CAPTURING ? tr(STR_CAPTURE_STOP) : tr(STR_CAPTURE_START);
  row.value = statusText;
  row.actionValue = 0;
}

void FrameCaptureActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  fui::ListProps props;
  props.items = &row;
  props.count = 1;
  props.action = ACTION_ROW;
  props.inputMask = fui::InputTouch;  // physical buttons stay in loop()
  props.valueInset = 8;
  props.labelText = screen.theme().smallText;
  props.labelText.maxLines = 1;
  syncListViewport(screen, props);
  screen.list(props);
}
