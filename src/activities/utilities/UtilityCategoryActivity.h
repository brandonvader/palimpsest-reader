#pragma once

#include "activities/UiListActivity.h"

enum class UtilityCategory { WIFI, BLE };

// One category page under Utilities (WiFi tools, BLE tools). Each tool is a
// row that launches its own child activity; Back returns to Utilities.
class UtilityCategoryActivity final : public UiListActivity {
 public:
  UtilityCategoryActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, UtilityCategory category);

 private:
  // Tools in this category; an empty category shows one informational row.
  int toolCount() const;
  int listCount() const override { return toolCount() > 0 ? toolCount() : 1; }
  void buildScreen(UiScreen& screen) override;
  void activateIndex(int index) override;
  const char* headerTitle() const override;

  const UtilityCategory category;
  static constexpr int MAX_TOOLS = 4;
  freeink::ui::ListItem rowItems_[MAX_TOOLS]{};
};
