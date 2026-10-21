#pragma once

#include <cstdint>
#include <string>

#include "PcapWriter.h"
#include "activities/UiListActivity.h"

// Shared with the .cpp's file-scope tracking tables (the promiscuous
// callback) and the Activity's own snapshot members used to build the result
// list without copying kilobytes onto the stack -- see the stack-safety note
// on AirspaceMonitorActivity's snapshot members below.
struct AirspaceDeauthSource {
  uint8_t mac[6] = {};
  uint32_t count = 0;
};

struct AirspaceSsidSighting {
  char ssid[33] = {};
  uint8_t bssids[4][6] = {};  // AirspaceMonitorActivity::MAX_BSSIDS_PER_SSID
  bool privacy[4] = {};
  int bssidCount = 0;
  bool flagged = false;  // true once two addresses for this SSID disagree on Privacy (open vs protected)
};

struct AirspaceKarmaCandidate {
  uint8_t bssid[6] = {};
  char ssids[6][33] = {};  // AirspaceMonitorActivity::MAX_SSIDS_PER_KARMA
  int ssidCount = 0;
};

// Passive WiFi airspace health monitor: hops channels 1-13 like Channel
// Survey / Frame Capture and flags activity of interest to a defender rather
// than capturing raw frames.
//   - Deauth/disassoc fingerprinting: counts deauth and disassoc frames per
//     transmitter address: a high count from one source is a deauther, not
//     normal client roaming. Each source is looked up against a curated OUI
//     vendor table (OuiVendors.h) for a rough "what is this" hint.
//   - Pwnagotchy: its status "beacon" always transmits from the fixed address
//     de:ad:be:ef:de:ad with its name/stats as JSON text in the SSID field
//     (the fingerprint ESP32Marauder's own pwnagotchi detector uses). Shown
//     as a dedicated row with the raw SSID text, not parsed -- a malformed or
//     adversarial JSON string should never be handed to an on-device parser.
//   - Evil twin: the same SSID broadcast from more than one address with a
//     different Privacy bit (open vs protected) in the beacon's capability
//     info. Deliberately a coarse open-vs-protected check, not full RSN
//     cipher/AKM decoding: it catches the most common and most dangerous
//     pattern (an open clone of a normally-protected network) without
//     claiming precision this tool does not have on e.g. a WPA2-vs-WPA3
//     mismatch, and a legitimate multi-AP deployment broadcasting the same
//     SSID with *matching* security everywhere never trips it.
//   - Karma: one address sending probe responses claiming to be several
//     distinct SSIDs -- a real AP only answers for its own configured name(s).
// Escalated sources/SSIDs/addresses from any of the three detectors above
// have their subsequent frames saved to one pcap file per session (same
// radiotap format as Frame Capture) for offline forensics, opened lazily so a
// clean session writes no extra file at all.
class AirspaceMonitorActivity final : public UiListActivity {
 public:
  // Bounded tracking-table sizes; shared with the promiscuous callback's
  // file-scope tables, so public (same reasoning as
  // ChannelSurveyActivity::LAST_CHANNEL).
  static constexpr int MAX_DEAUTH_SOURCES = 16;
  static constexpr int MAX_TRACKED_SSIDS = 10;    // evil-twin: distinct SSIDs watched
  static constexpr int MAX_BSSIDS_PER_SSID = 4;   // evil-twin: addresses watched per SSID
  static constexpr int MAX_KARMA_CANDIDATES = 8;  // karma: distinct responding addresses watched
  static constexpr int MAX_SSIDS_PER_KARMA = 6;   // karma: distinct SSIDs watched per address
  // A handful of stray deauth/disassoc frames happen during normal client
  // roaming; this many from one transmitter in a session is not normal.
  static constexpr uint32_t DEAUTHER_THRESHOLD = 5;
  // A real AP's multi-SSID setup rarely exceeds a couple of names; this many
  // distinct SSIDs answered by one address in a session is not normal.
  static constexpr int KARMA_SSID_THRESHOLD = 4;

  explicit AirspaceMonitorActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr uint8_t FIRST_CHANNEL = 1;
  static constexpr uint8_t LAST_CHANNEL = 13;
  static constexpr uint32_t DWELL_MS = 350;
  static constexpr uint32_t STATUS_REFRESH_MS = 5000;
  static constexpr uint32_t MAX_DURATION_MS = 10 * 60 * 1000;
  // Forensic pcap of escalated findings only, not the whole session; same
  // caps as Frame Capture as a safety net, rarely approached in practice.
  static constexpr const char* CAPTURE_DIR = "/Palimpsest/captures";
  static constexpr uint32_t MAX_FORENSIC_FRAMES = 20000;
  static constexpr uint64_t MAX_FORENSIC_BYTES = 8ull * 1024 * 1024;

  enum class State { IDLE, MONITORING, STOPPED };
  // Lower sorts first (most severe at the top of the combined list).
  enum Severity : int { SEVERITY_CONFIRMED = 0, SEVERITY_NOTABLE = 1, SEVERITY_INFO = 2 };

  // One row's worth of alert content, built fresh each rebuildRows() call
  // from all four detectors' tracking tables, then stable_sort()ed by
  // severity so repeated refreshes don't needlessly reorder same-tier rows
  // (that would flicker/waste partial refreshes for no reason). Owns its own
  // text so ListItem can point directly into the final sorted array.
  struct PendingAlert {
    int severity = SEVERITY_INFO;
    char label[24] = {};
    char subtitle[18] = {};
    char value[40] = {};
  };
  static constexpr int MAX_ALERTS = 1 /*Pwnagotchy*/ + MAX_DEAUTH_SOURCES + MAX_TRACKED_SSIDS + MAX_KARMA_CANDIDATES;
  static constexpr int MAX_ROWS = 1 /*control*/ + MAX_ALERTS;

  int listCount() const override;
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startMonitoring();
  void stopMonitoring();
  void drainForensicsRing();
  std::string buildForensicsPath() const;
  // Caller holds the render lock.
  void rebuildRows();

  State state = State::IDLE;
  int priorWifiMode = 0;  // wifi_mode_t at entry, restored on exit
  bool promiscuousOn = false;
  uint8_t currentChannel = FIRST_CHANNEL;
  uint32_t channelStartMs = 0;
  uint32_t monitorStartMs = 0;
  uint32_t lastStatusMs = 0;
  char summary[40] = {};
  int rowCount = 0;
  char controlValueText[40] = {};
  freeink::ui::ListItem rows[MAX_ROWS]{};

  // rebuildRows() snapshots the file-scope tracking tables under the shared
  // spinlock and needs somewhere to put the copy; these total a few KB, well
  // over the project's "<256 bytes of locals" stack guidance, so they are
  // Activity members (this instance is heap-allocated) rather than stack
  // locals in rebuildRows() itself.
  AirspaceDeauthSource deauthSnapshot[MAX_DEAUTH_SOURCES];
  AirspaceSsidSighting ssidSnapshot[MAX_TRACKED_SSIDS];
  AirspaceKarmaCandidate karmaSnapshot[MAX_KARMA_CANDIDATES];
  PendingAlert alerts[MAX_ALERTS];

  // Forensic capture of escalated findings, opened lazily on the first one
  // that needs saving so a clean session writes no extra file at all.
  bool forensicsOpen = false;
  std::string forensicsPath;
  PcapWriter forensicsWriter;
};
