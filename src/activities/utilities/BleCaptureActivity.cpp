#include "BleCaptureActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalMemory.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <NimBLEDevice.h>

#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
constexpr size_t RING_SLOTS = 64;
// Legacy AD payload is 31 bytes max; extended advertising can run larger.
// Capped well under the HCI event's 1-byte parameter-length field (255), with
// margin for the fixed report fields ahead of it.
constexpr size_t PAYLOAD_MAX = 200;

constexpr uint32_t DLT_BLUETOOTH_HCI_H4 = 187;  // http://www.tcpdump.org/linktypes.html

struct CapturedAdv {
  uint32_t tsSec = 0;
  uint32_t tsUsec = 0;
  uint8_t addr[6] = {};
  uint8_t addrType = 0;
  uint8_t eventType = 0;  // real HCI advertising-report event type (ADV_IND, SCAN_RSP, ...)
  int8_t rssi = 0;
  uint16_t payloadLen = 0;      // AD bytes actually stored (<= PAYLOAD_MAX)
  uint16_t origPayloadLen = 0;  // true AD length, pre-truncation
  uint8_t payload[PAYLOAD_MAX];
};

// Fixed-capacity SPSC ring in PSRAM, same pattern as FrameCaptureActivity's
// (and the SDK's BleKeyboardHost key-event ring): the NimBLE scan callback
// (producer, runs on the NimBLE host task -- not a hardware ISR, so plain
// portENTER_CRITICAL is correct here) enqueues; loop() (consumer) drains it
// into the pcap file.
portMUX_TYPE g_ringMux = portMUX_INITIALIZER_UNLOCKED;
HalMemory::PsramBuffer g_ringStorage;
CapturedAdv* g_ring = nullptr;
volatile size_t g_ringHead = 0;
volatile size_t g_ringTail = 0;
volatile uint32_t g_ringDropped = 0;
volatile bool g_capturing = false;
volatile bool g_scanEnded = false;

bool ringAllocate() {
  g_ringStorage = HalMemory::allocatePsram(sizeof(CapturedAdv) * RING_SLOTS);
  g_ring = reinterpret_cast<CapturedAdv*>(g_ringStorage.get());
  g_ringHead = 0;
  g_ringTail = 0;
  g_ringDropped = 0;
  return g_ring != nullptr;
}

void ringFree() {
  g_ring = nullptr;
  g_ringStorage.reset();
}

class CaptureCallbacks : public NimBLEScanCallbacks {
  // NimBLE's own signal that a stop()/cancel has actually been processed by
  // the host task -- the precondition deinit() needs. stop() itself only
  // requests ble_gap_disc_cancel() and returns before that settles; calling
  // deinit() too early raced NimBLE's internal stop sequence and crashed
  // inside it (confirmed from a coredump: a null function-pointer jump deep
  // in ble_gap_preempt_done()/ble_gap_adv_enable_tx(), reached while deinit()
  // unwound a cancellation we had not actually waited to finish).
  void onScanEnd(const NimBLEScanResults&, int) override { g_scanEnded = true; }

  // onResult (not onDiscovered) carries the scan-response-merged payload for
  // scannable legacy devices, same choice BleScanActivity makes and for the
  // same reason: a device's name often only arrives in the scan response.
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    if (!dev || !g_capturing || !g_ring) return;

    portENTER_CRITICAL(&g_ringMux);
    const size_t next = (g_ringHead + 1) % RING_SLOTS;
    if (next == g_ringTail) {
      g_ringDropped = g_ringDropped + 1;  // ring full: drop the newest record, keep draining the rest
      portEXIT_CRITICAL(&g_ringMux);
      return;
    }
    CapturedAdv& slot = g_ring[g_ringHead];
    slot.tsSec = static_cast<uint32_t>(micros() / 1000000);
    slot.tsUsec = static_cast<uint32_t>(micros() % 1000000);
    memcpy(slot.addr, dev->getAddress().getVal(), 6);  // already in HCI wire order
    slot.addrType = dev->getAddressType();
    slot.eventType = dev->getAdvType();
    slot.rssi = static_cast<int8_t>(dev->getRSSI());
    const auto& payload = dev->getPayload();
    slot.origPayloadLen = static_cast<uint16_t>(payload.size());
    slot.payloadLen = static_cast<uint16_t>(payload.size() > PAYLOAD_MAX ? PAYLOAD_MAX : payload.size());
    memcpy(slot.payload, payload.data(), slot.payloadLen);
    g_ringHead = next;
    portEXIT_CRITICAL(&g_ringMux);
  }
};

CaptureCallbacks g_callbacks;

// Stops scanning and tears the BLE stack down safely. stop() only requests
// ble_gap_disc_cancel() and returns before the host task has processed it;
// calling deinit() immediately after raced that cancellation and crashed
// inside NimBLE's own stop sequence (see the comment on onScanEnd above).
// Waiting for onScanEnd is the library's own signal that it is safe to
// proceed; the timeout is a last-resort safety net, not the expected path.
void releaseBleStack() {
  auto* scan = NimBLEDevice::getScan();
  if (scan->isScanning()) {
    g_scanEnded = false;
    scan->stop();
    const uint32_t waitStart = millis();
    while (!g_scanEnded && millis() - waitStart < 1000) {
      delay(5);
    }
    if (!g_scanEnded) {
      LOG_ERR("BCAP", "Timed out waiting for onScanEnd; deinit anyway");
    }
  }
  scan->clearResults();
  scan->setScanCallbacks(nullptr);
  NimBLEDevice::deinit(true);
}
}  // namespace

BleCaptureActivity::BleCaptureActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("BleCapture", renderer, mappedInput) {}

const char* BleCaptureActivity::headerTitle() const { return tr(STR_UTILITIES_BLE_CAPTURE); }

void BleCaptureActivity::onEnter() {
  UiListActivity::onEnter();
  snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_IDLE));
  rebuildRow();
}

void BleCaptureActivity::onExit() {
  if (state == State::CAPTURING) stopCapture(StopReason::TEARDOWN);
  UiListActivity::onExit();
}

void BleCaptureActivity::loop() {
  if (state == State::CAPTURING) {
    drainRing();

    if (millis() - rearmMs >= REARM_MS) {
      // Force NimBLE to treat every device as newly discovered again, or a
      // long capture would see each address only once and go silent.
      NimBLEDevice::getScan()->clearResults();
      rearmMs = millis();
    }

    if (writer.frameCount() >= MAX_FRAMES) {
      stopCapture(StopReason::FRAME_LIMIT);
    } else if (writer.bytesWritten() >= MAX_BYTES) {
      stopCapture(StopReason::SIZE_LIMIT);
    } else if (millis() - captureStartMs >= MAX_DURATION_MS) {
      stopCapture(StopReason::TIME_LIMIT);
    } else if (millis() - lastStatusMs >= STATUS_REFRESH_MS) {
      // Periodic status refresh during an open-ended capture, same pattern as
      // FrameCaptureActivity / SdFirmwareUpdateActivity's progress bar: an
      // occasional aggregate counter, not a live stream of individual results.
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

void BleCaptureActivity::drainRing() {
  for (;;) {
    static CapturedAdv adv;  // reused scratch; drainRing always runs on this activity's own task
    bool got = false;
    portENTER_CRITICAL(&g_ringMux);
    if (g_ringTail != g_ringHead) {
      adv = g_ring[g_ringTail];
      g_ringTail = (g_ringTail + 1) % RING_SLOTS;
      got = true;
    }
    portEXIT_CRITICAL(&g_ringMux);
    if (!got) break;

    // Host-synthesized HCI "LE Advertising Report" event (Bluetooth Core Spec
    // Vol 4 Part E 7.7.65.2): H4 packet indicator, LE Meta Event, one report.
    // Reused scratch, same reasoning as `adv` above.
    static uint8_t record[15 + PAYLOAD_MAX];
    record[0] = 0x04;                                       // H4: HCI Event packet
    record[1] = 0x3E;                                       // LE Meta Event
    record[2] = static_cast<uint8_t>(10 + adv.payloadLen);  // parameter total length
    record[3] = 0x02;                                       // LE Advertising Report subevent
    record[4] = 0x01;                                       // Num_Reports
    record[5] = adv.eventType;
    record[6] = adv.addrType;
    memcpy(&record[7], adv.addr, 6);
    record[13] = static_cast<uint8_t>(adv.payloadLen);
    memcpy(&record[14], adv.payload, adv.payloadLen);
    record[14 + adv.payloadLen] = static_cast<uint8_t>(adv.rssi);
    const size_t recordLen = 15 + adv.payloadLen;
    const size_t origLen = 15 + adv.origPayloadLen;

    if (!writer.writeRecord(record, recordLen, origLen, adv.tsSec, adv.tsUsec)) {
      stopCapture(StopReason::WRITE_ERROR);
      return;
    }
  }
}

std::string BleCaptureActivity::buildCapturePath() const {
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
  snprintf(path, sizeof(path), "%s/ble-capture-%s.pcap", CAPTURE_DIR, stamp);
  return std::string(path);
}

void BleCaptureActivity::failToStart() {
  if (stackUp) {
    releaseBleStack();
    stackUp = false;
  }
  writer.close();
  ringFree();

  RenderLock lock(*this);
  snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_UNAVAILABLE));
  rebuildRow();
  requestUpdate();
}

void BleCaptureActivity::startCapture() {
  if (!ringAllocate()) {
    LOG_ERR("BCAP", "OOM: capture ring (PSRAM)");
    failToStart();
    return;
  }

  stackUp = NimBLEDevice::init("");
  if (!stackUp) {
    LOG_ERR("BCAP", "NimBLE init failed");
    failToStart();
    return;
  }

  if (!Storage.ensureDirectoryExists(CAPTURE_DIR)) {
    LOG_ERR("BCAP", "Failed to create %s", CAPTURE_DIR);
    failToStart();
    return;
  }

  capturePath = buildCapturePath();
  if (!writer.open(capturePath, DLT_BLUETOOTH_HCI_H4, 15 + PAYLOAD_MAX)) {
    failToStart();
    return;
  }

  auto* scan = NimBLEDevice::getScan();
  // wantDuplicates: scan responses (names) arrive as a second PDU from the
  // same address; without this the controller drops that follow-up.
  scan->setScanCallbacks(&g_callbacks, true);
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(100);                // continuous listening (window == interval)
  if (!scan->start(0, false, true)) {  // 0 = scan until stopped
    LOG_ERR("BCAP", "Failed to start BLE scan");
    failToStart();
    return;
  }
  g_capturing = true;
  LOG_DBG("BCAP", "Capture started: %s, free heap %d bytes", capturePath.c_str(), ESP.getFreeHeap());

  captureStartMs = millis();
  lastStatusMs = millis();
  rearmMs = millis();

  {
    RenderLock lock(*this);
    state = State::CAPTURING;
    snprintf(statusText, sizeof(statusText), "%s", tr(STR_CAPTURE_STARTING));
    rebuildRow();
    activeNav().reset();
  }
  requestUpdate();
}

void BleCaptureActivity::stopCapture(const StopReason reason) {
  g_capturing = false;
  if (stackUp) {
    releaseBleStack();
    stackUp = false;
  }
  drainRing();  // flush whatever is left in the ring before closing the file
  const uint32_t frames = writer.frameCount();
  const uint64_t bytes = writer.bytesWritten();
  writer.close();
  ringFree();
  LOG_DBG("BCAP", "Capture stopped (reason=%d): %u frames, %llu bytes, free heap %d bytes", static_cast<int>(reason),
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

void BleCaptureActivity::activateIndex(const int index) {
  if (index != 0) return;
  if (state == State::CAPTURING) {
    stopCapture(StopReason::USER);
  } else {
    startCapture();
  }
}

void BleCaptureActivity::rebuildRow() {
  row = fui::ListItem{};
  row.label = state == State::CAPTURING ? tr(STR_CAPTURE_STOP) : tr(STR_CAPTURE_START);
  row.value = statusText;
  row.actionValue = 0;
}

void BleCaptureActivity::buildScreen(UiScreen& screen) {
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
