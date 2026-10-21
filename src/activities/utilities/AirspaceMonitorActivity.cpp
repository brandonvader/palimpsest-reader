#include "AirspaceMonitorActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalMemory.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "MappedInputManager.h"
#include "OuiVendors.h"
#include "Radiotap.h"
#include "activities/RenderLock.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
// 802.11 frame-control subtypes we care about (type=00 management, so
// subtype occupies the top nibble of byte 0 -- see ChannelSurveyActivity for
// the full byte layout this is a superset of).
constexpr uint8_t SUBTYPE_BEACON = 0x80;
constexpr uint8_t SUBTYPE_PROBE_RESP = 0x50;
constexpr uint8_t SUBTYPE_DISASSOC = 0xA0;
constexpr uint8_t SUBTYPE_DEAUTH = 0xC0;

// Non-QoS management frame header: FrameControl(2) Duration(2) Addr1(6)
// Addr2(6) Addr3(6) SeqCtrl(2) = 24 bytes. Addr2 is the transmitter -- the
// radio that actually sent the frame, which is what we want to fingerprint
// (a deauth's Addr1/Addr3 claim to be the victim/AP, not the attacker; a
// beacon's Addr2 is its own BSSID, which is what evil-twin tracking wants).
constexpr size_t ADDR2_OFFSET = 10;
constexpr size_t MGMT_HEADER_LEN = 24;
// Beacon/probe-response fixed fields before Information Elements start
// (identical layout for both frame types): Timestamp(8) + Beacon Interval(2)
// + Capability Info(2).
constexpr size_t BEACON_FIXED_LEN = 12;
// Capability Info is the last 2 bytes of the 12-byte fixed-field block:
// Timestamp(8, offset 0-7) + Beacon Interval(2, offset 8-9) + Capability
// Info(2, offset 10-11).
constexpr size_t CAP_INFO_OFFSET = MGMT_HEADER_LEN + 10;
constexpr uint16_t CAP_PRIVACY_BIT = 0x0010;  // 0 = open, 1 = some encryption (WEP/WPA/WPA2/WPA3)
constexpr uint8_t IE_TAG_SSID = 0;

// Pwnagotchy's status "beacon" always transmits from this fixed address, with
// its name and pwned-network count as JSON text in the SSID -- the same
// fingerprint ESP32Marauder's own pwnagotchi detector uses
// (https://github.com/justcallmekoko/ESP32Marauder/wiki/detect-pwnagotchi).
constexpr uint8_t PWNAGOTCHY_MAC[6] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};

// Mirrors FrameCaptureActivity's CapturedFrame/ring shape, sized smaller
// since only escalated findings flow through this one.
constexpr size_t FORENSICS_RING_SLOTS = 32;
constexpr size_t FORENSICS_SNAPLEN = 512;

struct ForensicFrame {
  uint32_t tsSec = 0;
  uint32_t tsUsec = 0;
  uint8_t channel = 0;
  int8_t rssi = 0;
  uint16_t len = 0;
  uint16_t origLen = 0;
  uint8_t data[FORENSICS_SNAPLEN];
};

portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

AirspaceDeauthSource g_deauthSources[AirspaceMonitorActivity::MAX_DEAUTH_SOURCES];
int g_deauthSourceCount = 0;
bool g_pwnagotchySeen = false;
char g_pwnagotchySsid[33] = {};
AirspaceSsidSighting g_ssidSightings[AirspaceMonitorActivity::MAX_TRACKED_SSIDS];
int g_ssidCount = 0;
AirspaceKarmaCandidate g_karmaCandidates[AirspaceMonitorActivity::MAX_KARMA_CANDIDATES];
int g_karmaCount = 0;
volatile bool g_monitoring = false;

HalMemory::PsramBuffer g_forensicsRingStorage;
ForensicFrame* g_forensicsRing = nullptr;
volatile size_t g_forensicsHead = 0;
volatile size_t g_forensicsTail = 0;

// Caller holds g_mux. Fixed-capacity find-or-insert, same shape as the SDK's
// BleKeyboardHost ring: bounded memory, existing entries keep counting if the
// table fills rather than growing unbounded. Returns the source's count
// after this frame (0 if the table was full and this is a brand new,
// untracked source -- naturally below any threshold, so callers skip it).
uint32_t recordDeauthSource(const uint8_t* mac) {
  for (int i = 0; i < g_deauthSourceCount; i++) {
    if (memcmp(g_deauthSources[i].mac, mac, 6) == 0) {
      return ++g_deauthSources[i].count;
    }
  }
  if (g_deauthSourceCount < AirspaceMonitorActivity::MAX_DEAUTH_SOURCES) {
    memcpy(g_deauthSources[g_deauthSourceCount].mac, mac, 6);
    g_deauthSources[g_deauthSourceCount].count = 1;
    g_deauthSourceCount++;
    return 1;
  }
  return 0;
}

// Caller holds g_mux. Tracks which addresses have beaconed each SSID and
// whether they agree on the Privacy bit. Returns whether this SSID is now
// flagged (two or more addresses disagreeing), so the callback can decide
// whether to save this frame for forensics without a second lookup.
bool recordSsidSighting(const char* ssid, const uint8_t* bssid, const bool privacyEnabled) {
  AirspaceSsidSighting* entry = nullptr;
  for (int i = 0; i < g_ssidCount; i++) {
    if (strcmp(g_ssidSightings[i].ssid, ssid) == 0) {
      entry = &g_ssidSightings[i];
      break;
    }
  }
  if (!entry) {
    if (g_ssidCount >= AirspaceMonitorActivity::MAX_TRACKED_SSIDS) return false;
    entry = &g_ssidSightings[g_ssidCount++];
    strlcpy(entry->ssid, ssid, sizeof(entry->ssid));
  }
  bool known = false;
  for (int i = 0; i < entry->bssidCount; i++) {
    if (memcmp(entry->bssids[i], bssid, 6) == 0) {
      known = true;
      break;
    }
  }
  if (!known && entry->bssidCount < AirspaceMonitorActivity::MAX_BSSIDS_PER_SSID) {
    memcpy(entry->bssids[entry->bssidCount], bssid, 6);
    entry->privacy[entry->bssidCount] = privacyEnabled;
    entry->bssidCount++;
  }
  if (entry->bssidCount >= 2) {
    const bool first = entry->privacy[0];
    for (int i = 1; i < entry->bssidCount; i++) {
      if (entry->privacy[i] != first) {
        entry->flagged = true;
        break;
      }
    }
  }
  return entry->flagged;
}

// Caller holds g_mux. Tracks the set of distinct SSIDs each address has sent
// probe responses for. Returns the address's distinct-SSID count after this
// response.
int recordKarmaResponse(const uint8_t* bssid, const char* ssid) {
  AirspaceKarmaCandidate* entry = nullptr;
  for (int i = 0; i < g_karmaCount; i++) {
    if (memcmp(g_karmaCandidates[i].bssid, bssid, 6) == 0) {
      entry = &g_karmaCandidates[i];
      break;
    }
  }
  if (!entry) {
    if (g_karmaCount >= AirspaceMonitorActivity::MAX_KARMA_CANDIDATES) return 0;
    entry = &g_karmaCandidates[g_karmaCount++];
    memcpy(entry->bssid, bssid, 6);
  }
  for (int i = 0; i < entry->ssidCount; i++) {
    if (strcmp(entry->ssids[i], ssid) == 0) return entry->ssidCount;
  }
  if (entry->ssidCount < AirspaceMonitorActivity::MAX_SSIDS_PER_KARMA) {
    strlcpy(entry->ssids[entry->ssidCount], ssid, sizeof(entry->ssids[0]));
    entry->ssidCount++;
  }
  return entry->ssidCount;
}

// Walks Information Elements looking for the SSID tag. Bounds-checked against
// the captured length at every step: this parses attacker-controlled radio
// data, and a malformed or adversarial length byte must stop the walk rather
// than read past the buffer. Shared by beacon and probe-response parsing --
// both frame types have the identical fixed-field layout ahead of their IEs.
bool extractSsid(const uint8_t* frame, const size_t len, char* out, const size_t outCap) {
  size_t pos = MGMT_HEADER_LEN + BEACON_FIXED_LEN;
  while (pos + 2 <= len) {
    const uint8_t tag = frame[pos];
    const uint8_t tagLen = frame[pos + 1];
    if (pos + 2 + tagLen > len) break;  // truncated/malformed: stop, don't overread
    if (tag == IE_TAG_SSID) {
      const size_t copyLen = std::min(static_cast<size_t>(tagLen), outCap - 1);
      memcpy(out, &frame[pos + 2], copyLen);
      out[copyLen] = '\0';
      return true;
    }
    pos += 2 + tagLen;
  }
  return false;
}

// Capability Info's Privacy bit: 0 = open network, 1 = some encryption
// scheme is in use (WEP/WPA/WPA2/WPA3 all set it; this does not distinguish
// among them -- see the class-level comment on why that is enough for the
// most common evil-twin pattern without overclaiming precision).
bool extractPrivacy(const uint8_t* frame, const size_t len) {
  if (len < CAP_INFO_OFFSET + 2) return false;
  uint16_t capInfo = 0;
  memcpy(&capInfo, &frame[CAP_INFO_OFFSET], 2);  // little-endian on the wire, matches native byte order here
  return (capInfo & CAP_PRIVACY_BIT) != 0;
}

// Caller holds g_mux. Drop-on-overflow, same reasoning as the capture tools'
// rings: a full ring means the consumer (loop()) is behind, not that the
// newest evidence matters less than what is already queued.
void enqueueForensicFrame(const uint8_t* frame, const uint16_t len, const uint16_t origLen, const uint8_t channel,
                          const int8_t rssi) {
  if (!g_forensicsRing) return;
  const size_t next = (g_forensicsHead + 1) % FORENSICS_RING_SLOTS;
  if (next == g_forensicsTail) return;
  ForensicFrame& slot = g_forensicsRing[g_forensicsHead];
  slot.tsSec = static_cast<uint32_t>(micros() / 1000000);
  slot.tsUsec = static_cast<uint32_t>(micros() % 1000000);
  slot.channel = channel;
  slot.rssi = rssi;
  slot.origLen = origLen;
  slot.len = len > FORENSICS_SNAPLEN ? FORENSICS_SNAPLEN : len;
  memcpy(slot.data, frame, slot.len);
  g_forensicsHead = next;
}

bool forensicsRingAllocate() {
  g_forensicsRingStorage = HalMemory::allocatePsram(sizeof(ForensicFrame) * FORENSICS_RING_SLOTS);
  g_forensicsRing = reinterpret_cast<ForensicFrame*>(g_forensicsRingStorage.get());
  g_forensicsHead = 0;
  g_forensicsTail = 0;
  return g_forensicsRing != nullptr;
}

void forensicsRingFree() {
  g_forensicsRing = nullptr;
  g_forensicsRingStorage.reset();
}

// Runs on the WiFi driver's internal task, not a hardware ISR (same
// assumption as the other promiscuous-mode tools), so plain
// portENTER_CRITICAL is correct here. Per-frame work is bounded: an IE walk
// over a beacon/probe-response is a few dozen byte comparisons at most, cheap
// even at the frame rates a busy venue produces.
void onPromiscuousPacket(void* buf, const wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !buf || !g_monitoring) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < MGMT_HEADER_LEN) return;  // shorter than a mgmt header: noise
  const uint8_t subtype = pkt->payload[0] & 0xF0;
  const uint8_t* transmitter = &pkt->payload[ADDR2_OFFSET];

  if (subtype == SUBTYPE_DEAUTH || subtype == SUBTYPE_DISASSOC) {
    portENTER_CRITICAL(&g_mux);
    const uint32_t count = recordDeauthSource(transmitter);
    if (count >= AirspaceMonitorActivity::DEAUTHER_THRESHOLD) {
      enqueueForensicFrame(pkt->payload, len, len, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);
    }
    portEXIT_CRITICAL(&g_mux);
    return;
  }

  if (subtype == SUBTYPE_BEACON) {
    if (memcmp(transmitter, PWNAGOTCHY_MAC, 6) == 0) {
      char ssid[sizeof(g_pwnagotchySsid)];
      if (extractSsid(pkt->payload, len, ssid, sizeof(ssid))) {
        portENTER_CRITICAL(&g_mux);
        g_pwnagotchySeen = true;
        strlcpy(g_pwnagotchySsid, ssid, sizeof(g_pwnagotchySsid));
        portEXIT_CRITICAL(&g_mux);
      }
      return;
    }
    char ssid[33];
    if (!extractSsid(pkt->payload, len, ssid, sizeof(ssid)) || ssid[0] == '\0')
      return;  // hidden/empty: nothing to compare
    const bool privacy = extractPrivacy(pkt->payload, len);
    portENTER_CRITICAL(&g_mux);
    const bool flagged = recordSsidSighting(ssid, transmitter, privacy);
    if (flagged) enqueueForensicFrame(pkt->payload, len, len, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);
    portEXIT_CRITICAL(&g_mux);
    return;
  }

  if (subtype == SUBTYPE_PROBE_RESP) {
    char ssid[33];
    if (!extractSsid(pkt->payload, len, ssid, sizeof(ssid)) || ssid[0] == '\0') return;
    portENTER_CRITICAL(&g_mux);
    const int distinctSsids = recordKarmaResponse(transmitter, ssid);
    if (distinctSsids >= AirspaceMonitorActivity::KARMA_SSID_THRESHOLD) {
      enqueueForensicFrame(pkt->payload, len, len, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);
    }
    portEXIT_CRITICAL(&g_mux);
  }
}
}  // namespace

AirspaceMonitorActivity::AirspaceMonitorActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("AirspaceMonitor", renderer, mappedInput) {}

const char* AirspaceMonitorActivity::headerTitle() const { return tr(STR_UTILITIES_AIRSPACE_MONITOR); }

int AirspaceMonitorActivity::listCount() const { return rowCount; }

void AirspaceMonitorActivity::onEnter() {
  UiListActivity::onEnter();
  snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_IDLE));
  rebuildRows();
}

void AirspaceMonitorActivity::onExit() {
  if (state == State::MONITORING) stopMonitoring();
  UiListActivity::onExit();
}

void AirspaceMonitorActivity::loop() {
  if (state == State::MONITORING) {
    drainForensicsRing();

    if (millis() - channelStartMs >= DWELL_MS) {
      currentChannel = currentChannel >= LAST_CHANNEL ? FIRST_CHANNEL : currentChannel + 1;
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      channelStartMs = millis();
    }

    if (millis() - monitorStartMs >= MAX_DURATION_MS) {
      stopMonitoring();
    } else if (millis() - lastStatusMs >= STATUS_REFRESH_MS) {
      // Periodic refresh, same pattern as the capture tools: an occasional
      // aggregate update, not a live stream of individual frames.
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

void AirspaceMonitorActivity::startMonitoring() {
  if (!forensicsRingAllocate()) {
    // Not fatal: monitoring still works, just without forensic pcap saving.
    LOG_ERR("AIRM", "OOM: forensics ring (PSRAM); continuing without forensic capture");
  }
  forensicsOpen = false;
  forensicsPath.clear();

  // Acquire the radio: promiscuous mode needs the WiFi driver started but not
  // connected or scanning under us (same acquire as ChannelSurveyActivity).
  priorWifiMode = static_cast<int>(WiFi.getMode());
  if ((priorWifiMode & WIFI_MODE_STA) == 0) {
    WiFi.mode(static_cast<wifi_mode_t>(priorWifiMode | WIFI_MODE_STA));
  }
  WiFi.disconnect();
  delay(100);

  portENTER_CRITICAL(&g_mux);
  g_deauthSourceCount = 0;
  g_pwnagotchySeen = false;
  g_pwnagotchySsid[0] = '\0';
  g_ssidCount = 0;
  g_karmaCount = 0;
  portEXIT_CRITICAL(&g_mux);

  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&onPromiscuousPacket);
  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    LOG_ERR("AIRM", "Failed to enable promiscuous mode");
    WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));
    return;
  }
  promiscuousOn = true;
  g_monitoring = true;

  currentChannel = FIRST_CHANNEL;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  channelStartMs = millis();
  monitorStartMs = millis();
  lastStatusMs = millis();

  {
    RenderLock lock(*this);
    state = State::MONITORING;
    snprintf(summary, sizeof(summary), "%s", tr(STR_CAPTURE_STARTING));
    rebuildRows();
    activeNav().reset();
  }
  requestUpdate();
}

void AirspaceMonitorActivity::stopMonitoring() {
  g_monitoring = false;
  if (promiscuousOn) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    promiscuousOn = false;
  }
  WiFi.mode(priorWifiMode == WIFI_MODE_NULL ? WIFI_OFF : static_cast<wifi_mode_t>(priorWifiMode));

  drainForensicsRing();  // flush whatever is left before closing the file
  const uint32_t forensicFrames = forensicsWriter.frameCount();
  if (forensicsOpen) {
    forensicsWriter.close();
    forensicsOpen = false;
  }
  forensicsRingFree();

  RenderLock lock(*this);
  state = State::STOPPED;
  if (forensicFrames > 0) {
    snprintf(summary, sizeof(summary), tr(STR_FORENSICS_SAVED), static_cast<unsigned>(forensicFrames));
  } else {
    snprintf(summary, sizeof(summary), "%s", tr(STR_RESCAN));
  }
  rebuildRows();
  requestUpdate();
}

void AirspaceMonitorActivity::drainForensicsRing() {
  for (;;) {
    static ForensicFrame frame;  // reused scratch; drainForensicsRing always runs on this activity's own task
    bool got = false;
    portENTER_CRITICAL(&g_mux);
    if (g_forensicsTail != g_forensicsHead) {
      frame = g_forensicsRing[g_forensicsTail];
      g_forensicsTail = (g_forensicsTail + 1) % FORENSICS_RING_SLOTS;
      got = true;
    }
    portEXIT_CRITICAL(&g_mux);
    if (!got) break;

    if (!forensicsOpen) {
      if (!Storage.ensureDirectoryExists(CAPTURE_DIR)) {
        LOG_ERR("AIRM", "Failed to create %s", CAPTURE_DIR);
        return;
      }
      forensicsPath = buildForensicsPath();
      if (!forensicsWriter.open(forensicsPath, radiotap::DLT_IEEE802_11_RADIOTAP,
                                radiotap::HEADER_LEN + FORENSICS_SNAPLEN)) {
        return;
      }
      forensicsOpen = true;
    }
    if (forensicsWriter.frameCount() >= MAX_FORENSIC_FRAMES || forensicsWriter.bytesWritten() >= MAX_FORENSIC_BYTES) {
      return;  // safety cap reached; stop saving but keep monitoring
    }

    static uint8_t record[radiotap::HEADER_LEN + FORENSICS_SNAPLEN];
    radiotap::build(record, frame.channel, frame.rssi);
    memcpy(record + radiotap::HEADER_LEN, frame.data, frame.len);
    if (!forensicsWriter.writeRecord(record, radiotap::HEADER_LEN + frame.len, radiotap::HEADER_LEN + frame.origLen,
                                     frame.tsSec, frame.tsUsec)) {
      LOG_ERR("AIRM", "Forensic pcap write failed; stopping forensic capture");
      return;
    }
  }
}

std::string AirspaceMonitorActivity::buildForensicsPath() const {
  char stamp[24] = {};
  struct tm timeinfo{};
  if (halClock.isAvailable() && halClock.localTime(timeinfo)) {
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &timeinfo);
  } else {
    snprintf(stamp, sizeof(stamp), "boot-%lu", static_cast<unsigned long>(millis()));
  }
  char path[96];
  snprintf(path, sizeof(path), "%s/airspace-%s.pcap", CAPTURE_DIR, stamp);
  return std::string(path);
}

void AirspaceMonitorActivity::rebuildRows() {
  int deauthCount;
  bool pwnSeen;
  char pwnSsid[sizeof(g_pwnagotchySsid)];
  int ssidCount;
  int karmaCount;
  portENTER_CRITICAL(&g_mux);
  deauthCount = g_deauthSourceCount;
  memcpy(deauthSnapshot, g_deauthSources, sizeof(AirspaceDeauthSource) * deauthCount);
  pwnSeen = g_pwnagotchySeen;
  strlcpy(pwnSsid, g_pwnagotchySsid, sizeof(pwnSsid));
  ssidCount = g_ssidCount;
  memcpy(ssidSnapshot, g_ssidSightings, sizeof(AirspaceSsidSighting) * ssidCount);
  karmaCount = g_karmaCount;
  memcpy(karmaSnapshot, g_karmaCandidates, sizeof(AirspaceKarmaCandidate) * karmaCount);
  portEXIT_CRITICAL(&g_mux);

  int alertCount = 0;

  if (pwnSeen && alertCount < MAX_ALERTS) {
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_NOTABLE;
    snprintf(a.label, sizeof(a.label), "%s", tr(STR_PWNAGOTCHY_DETECTED));
    snprintf(a.value, sizeof(a.value), "%s", pwnSsid);
    alertCount++;
  }

  for (int i = 0; i < ssidCount && alertCount < MAX_ALERTS; i++) {
    if (!ssidSnapshot[i].flagged) continue;
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_CONFIRMED;
    snprintf(a.label, sizeof(a.label), "%s", ssidSnapshot[i].ssid);
    snprintf(a.value, sizeof(a.value), tr(STR_EVIL_TWIN), static_cast<unsigned>(ssidSnapshot[i].bssidCount));
    alertCount++;
  }

  for (int i = 0; i < karmaCount && alertCount < MAX_ALERTS; i++) {
    if (karmaSnapshot[i].ssidCount < KARMA_SSID_THRESHOLD) continue;
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = SEVERITY_CONFIRMED;
    snprintf(a.label, sizeof(a.label), "%02X:%02X:%02X:%02X:%02X:%02X", karmaSnapshot[i].bssid[0],
             karmaSnapshot[i].bssid[1], karmaSnapshot[i].bssid[2], karmaSnapshot[i].bssid[3], karmaSnapshot[i].bssid[4],
             karmaSnapshot[i].bssid[5]);
    const char* vendor = OuiVendors::lookup(karmaSnapshot[i].bssid);
    snprintf(a.subtitle, sizeof(a.subtitle), "%s", vendor ? vendor : tr(STR_UNKNOWN_VENDOR));
    snprintf(a.value, sizeof(a.value), tr(STR_KARMA_AP), static_cast<unsigned>(karmaSnapshot[i].ssidCount));
    alertCount++;
  }

  std::sort(deauthSnapshot, deauthSnapshot + deauthCount,
            [](const AirspaceDeauthSource& x, const AirspaceDeauthSource& y) { return x.count > y.count; });
  for (int i = 0; i < deauthCount && alertCount < MAX_ALERTS; i++) {
    PendingAlert& a = alerts[alertCount];
    a = PendingAlert{};
    a.severity = deauthSnapshot[i].count >= DEAUTHER_THRESHOLD ? SEVERITY_CONFIRMED : SEVERITY_INFO;
    snprintf(a.label, sizeof(a.label), "%02X:%02X:%02X:%02X:%02X:%02X", deauthSnapshot[i].mac[0],
             deauthSnapshot[i].mac[1], deauthSnapshot[i].mac[2], deauthSnapshot[i].mac[3], deauthSnapshot[i].mac[4],
             deauthSnapshot[i].mac[5]);
    const char* vendor = OuiVendors::lookup(deauthSnapshot[i].mac);
    snprintf(a.subtitle, sizeof(a.subtitle), "%s", vendor ? vendor : tr(STR_UNKNOWN_VENDOR));
    if (deauthSnapshot[i].count >= DEAUTHER_THRESHOLD) {
      snprintf(a.value, sizeof(a.value), tr(STR_LIKELY_DEAUTHER), static_cast<unsigned>(deauthSnapshot[i].count));
    } else {
      snprintf(a.value, sizeof(a.value), "%u", static_cast<unsigned>(deauthSnapshot[i].count));
    }
    alertCount++;
  }

  // stable_sort: same-severity rows keep their relative order across
  // refreshes instead of reshuffling for no reason every 5 seconds.
  std::stable_sort(alerts, alerts + alertCount,
                   [](const PendingAlert& x, const PendingAlert& y) { return x.severity < y.severity; });

  rowCount = 0;
  fui::ListItem& control = rows[rowCount];
  control = fui::ListItem{};
  control.label = state == State::MONITORING ? tr(STR_CAPTURE_STOP) : tr(STR_CAPTURE_START);
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

void AirspaceMonitorActivity::activateIndex(const int index) {
  if (index != 0) return;
  if (state == State::MONITORING) {
    stopMonitoring();
  } else {
    startMonitoring();
  }
}

void AirspaceMonitorActivity::buildScreen(UiScreen& screen) {
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
