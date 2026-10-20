#pragma once

#include "activities/UiListActivity.h"

// Home entry for the security-research tools. Each tool is a child activity
// launched from this list. The first entry shows an authorized-use notice that
// must be confirmed once; the acknowledgement is persisted on the SD card.
class UtilitiesActivity final : public UiListActivity {
 public:
  explicit UtilitiesActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

  void onEnter() override;
  void loop() override;

 private:
  static constexpr int CATEGORY_COUNT = 2;  // WiFi, BLE

  int listCount() const override { return CATEGORY_COUNT; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  void onBackButton() override { onGoHome(); }
  const char* headerTitle() const override;

  void showNotice();

  bool noticePending = false;
  freeink::ui::ListItem rowItems_[CATEGORY_COUNT]{};
};
