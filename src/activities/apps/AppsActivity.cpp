#include "AppsActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>

#include "MappedInputManager.h"
#include "activities/utilities/UtilitiesActivity.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

AppsActivity::AppsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("Apps", renderer, mappedInput) {}

const char* AppsActivity::headerTitle() const { return tr(STR_APPS); }

void AppsActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  rowItems_[0].label = tr(STR_UTILITIES);
  rowItems_[0].actionValue = 0;

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

void AppsActivity::activateIndex(const int index) {
  auto child = makeUniqueNoThrow<UtilitiesActivity>(renderer, mappedInput);
  if (!child) {
    LOG_ERR("APPS", "OOM: utilities activity");
    return;
  }
  app.clearTapFlash();
  startActivityForResult(std::move(child), [](const ActivityResult&) {});
}
