#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "activities/UiListActivity.h"

class ScanEndCallbacks;

// Passive BLE survey: lists nearby advertisers (name, address, address type,
// RSSI, connectable) as a snapshot. Row 0 rescans. The activity owns the BLE
// stack while it is open: NimBLE is initialised on entry and fully torn down on exit.
class BleScanActivity final : public UiListActivity {
 public:
  explicit BleScanActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);
  ~BleScanActivity() override;

  void onEnter() override;
  void onExit() override;
  void loop() override;

  // Set from the NimBLE host task when a scan window closes.
  void markScanEnded() { scanEnded.store(true); }

 private:
  static constexpr size_t MAX_DEVICES = 48;

  enum class State { SCANNING, DONE };

  struct Device {
    char name[32];
    char detail[48];  // "AA:BB:CC:DD:EE:FF  rnd  conn"
    char signal[16];  // "-62 dBm"
    int8_t rssi;
    uint8_t addr[6];  // for "Hunt this" (BleHuntingActivity's preset target)
  };

  int listCount() const override { return 1 + static_cast<int>(devices.size()); }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  void startScan();
  void collectResults();
  void finishWithMessage(const char* message);
  // Callers hold the render lock.
  void rebuildRows();
  // NimBLE stack acquire/release, factored out of onEnter()/onExit() so "Hunt
  // this" can release the stack before handing it to BleHuntingActivity (two
  // owners can't both hold it) and reacquire it when that pop returns here --
  // without disturbing the already-shown results list. Returns false on
  // failure (OOM or NimBLE init failure).
  bool acquireBle();
  void releaseBle();

  State state = State::SCANNING;
  bool stackUp = false;
  std::atomic<bool> scanEnded{false};
  std::unique_ptr<ScanEndCallbacks> callbacks;
  char summary[40] = {};
  std::vector<Device> devices;
  std::vector<freeink::ui::ListItem> rows;
};
