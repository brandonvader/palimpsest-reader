#include "UtilitiesActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>

#include "MappedInputManager.h"
#include "UtilityCategoryActivity.h"
#include "activities/util/ConfirmationActivity.h"
#include "components/UITheme.h"

namespace fui = freeink::ui;

namespace {
constexpr char ACK_DIR[] = "/.crosspoint/palimpsest";
constexpr char ACK_FILE[] = "/.crosspoint/palimpsest/utilities_ack";

bool noticeAcknowledged() { return Storage.exists(ACK_FILE); }

void saveAcknowledgement() {
  if (!Storage.ensureDirectoryExists(ACK_DIR) || !Storage.writeFile(ACK_FILE, "1")) {
    LOG_ERR("UTIL", "Failed to persist authorized-use acknowledgement");
  }
}
}  // namespace

UtilitiesActivity::UtilitiesActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
    : UiListActivity("Utilities", renderer, mappedInput) {}

const char* UtilitiesActivity::headerTitle() const { return tr(STR_UTILITIES); }

void UtilitiesActivity::onEnter() {
  UiListActivity::onEnter();
  noticePending = !noticeAcknowledged();
}

void UtilitiesActivity::loop() {
  if (noticePending) {
    noticePending = false;
    showNotice();
    return;
  }
  UiListActivity::loop();
}

void UtilitiesActivity::showNotice() {
  auto notice = makeUniqueNoThrow<ConfirmationActivity>(renderer, mappedInput, tr(STR_UTILITIES_NOTICE_HEADING),
                                                        tr(STR_UTILITIES_NOTICE_BODY));
  if (!notice) {
    LOG_ERR("UTIL", "OOM: authorized-use notice");
    onGoHome();
    return;
  }
  startActivityForResult(std::move(notice), [this](const ActivityResult& result) {
    if (result.isCancelled) {
      onGoHome();
      return;
    }
    saveAcknowledgement();
  });
}

void UtilitiesActivity::buildScreen(UiScreen& screen) {
  const auto& metrics = UITheme::getInstance().getMetrics();
  screen.setContentMarginFromScreen(fui::Insets{static_cast<int16_t>(metrics.topPadding + metrics.headerHeight), 0,
                                                static_cast<int16_t>(metrics.buttonHintsHeight), 0});
  screen.spacer(static_cast<int16_t>(metrics.verticalSpacing));

  rowItems_[0].label = tr(STR_UTILITIES_WIFI);
  rowItems_[1].label = tr(STR_UTILITIES_BLE);
  for (int i = 0; i < CATEGORY_COUNT; i++) {
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

void UtilitiesActivity::activateIndex(const int index) {
  const auto category = index == 0 ? UtilityCategory::WIFI : UtilityCategory::BLE;
  auto child = makeUniqueNoThrow<UtilityCategoryActivity>(renderer, mappedInput, category);
  if (!child) {
    LOG_ERR("UTIL", "OOM: category activity");
    return;
  }
  app.clearTapFlash();
  startActivityForResult(std::move(child), [](const ActivityResult&) {});
}
