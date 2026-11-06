#pragma once

#include "activities/UiListActivity.h"

// Home entry point for app-like features beyond the core reader. Each app is
// a child activity launched from this list; Utilities is the first one.
class AppsActivity final : public UiListActivity {
 public:
  explicit AppsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput);

 private:
  static constexpr int APP_COUNT = 1;  // Utilities

  int listCount() const override { return APP_COUNT; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  void onBackButton() override { onGoHome(); }
  const char* headerTitle() const override;

  freeink::ui::ListItem rowItems_[APP_COUNT]{};
};
