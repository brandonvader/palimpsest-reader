#include "UtilityCategoryActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>

#include "BleScanActivity.h"
#include "ChannelSurveyActivity.h"
#include "FrameCaptureActivity.h"
#include "MappedInputManager.h"
#include "WifiScanActivity.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

UtilityCategoryActivity::UtilityCategoryActivity(GfxRenderer& renderer, MappedInputManager& mappedInput,
                                                 const UtilityCategory category)
    : UiListActivity("UtilitiesTools", renderer, mappedInput), category(category) {}

int UtilityCategoryActivity::toolCount() const { return category == UtilityCategory::WIFI ? 3 : 1; }

const char* UtilityCategoryActivity::headerTitle() const {
  return category == UtilityCategory::WIFI ? tr(STR_UTILITIES_WIFI) : tr(STR_UTILITIES_BLE);
}

void UtilityCategoryActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  if (toolCount() == 0) {
    rowItems_[0].label = tr(STR_UTILITIES_EMPTY);
  } else if (category == UtilityCategory::WIFI) {
    rowItems_[0].label = tr(STR_UTILITIES_WIFI_SCAN);
    rowItems_[1].label = tr(STR_UTILITIES_CHANNEL_SURVEY);
    rowItems_[2].label = tr(STR_UTILITIES_FRAME_CAPTURE);
  } else {
    rowItems_[0].label = tr(STR_UTILITIES_BLE_SCAN);
  }
  for (int i = 0; i < listCount(); i++) {
    rowItems_[i].actionValue = static_cast<int16_t>(i);
  }

  fui::ListProps props;
  props.items = rowItems_;
  props.count = listCount();
  props.action = ACTION_ROW;
  props.inputMask = fui::InputTouch;  // physical buttons stay in loop()
  props.labelText = screen.theme().smallText;
  props.labelText.maxLines = 1;
  syncListViewport(screen, props);
  screen.list(props);
}

void UtilityCategoryActivity::activateIndex(const int index) {
  if (index < 0 || index >= toolCount()) return;
  std::unique_ptr<Activity> tool;
  if (category == UtilityCategory::WIFI) {
    if (index == 0) {
      tool = makeUniqueNoThrow<WifiScanActivity>(renderer, mappedInput);
    } else if (index == 1) {
      tool = makeUniqueNoThrow<ChannelSurveyActivity>(renderer, mappedInput);
    } else if (index == 2) {
      tool = makeUniqueNoThrow<FrameCaptureActivity>(renderer, mappedInput);
    }
  } else if (category == UtilityCategory::BLE && index == 0) {
    tool = makeUniqueNoThrow<BleScanActivity>(renderer, mappedInput);
  }
  if (!tool) {
    LOG_ERR("UTIL", "Failed to create tool activity");
    return;
  }
  app.clearTapFlash();
  startActivityForResult(std::move(tool), [](const ActivityResult&) {});
}
