#pragma once

#include <vector>

#include "activities/UiListActivity.h"

// Passive WiFi survey: lists nearby access points (SSID, BSSID, channel, RSSI,
// security) as a snapshot. Row 0 rescans. The activity owns the radio while it
// is open: it enters STA mode if WiFi was off and restores the prior mode on exit.
class WifiScanActivity final : public UiListActivity {
 public:
  explicit WifiScanActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void onExit() override;
  void loop() override;

 private:
  static constexpr size_t MAX_APS = 48;

  enum class State { SCANNING, DONE };

  struct AccessPoint {
    char ssid[33];
    char detail[32];  // "AA:BB:CC:DD:EE:FF  ch 11"
    char signal[24];  // "-52 dBm  WPA2"
    int8_t rssi;
  };

  int listCount() const override { return 1 + static_cast<int>(aps.size()); }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startScan();
  void collectResults(int scanResult);
  // Callers hold the render lock.
  void rebuildRows();

  State state = State::SCANNING;
  int priorWifiMode = 0;  // wifi_mode_t at entry, restored on exit
  char summary[40] = {};
  std::vector<AccessPoint> aps;
  std::vector<freeink::ui::ListItem> rows;
};
