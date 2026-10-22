#pragma once

#include <I18n.h>

#include <cstdint>
#include <cstdio>

// Same visual convention as the stock WiFi picker
// (WifiSelectionActivity::getSignalStrengthIndicator), so a signal reads the
// same way everywhere in the app. Not shared code with that function (it is
// private to the reader's own network picker, outside Utilities), just the
// same thresholds and glyphs reimplemented here for Utilities' own tools.
// 1 (weak) .. 4 (excellent); shared by the bar glyph and the Hunting gauge so
// both read the same signal the same way.
inline int signalTier(const int8_t rssiDbm) {
  if (rssiDbm >= -50) return 4;
  if (rssiDbm >= -60) return 3;
  if (rssiDbm >= -70) return 2;
  return 1;
}

inline const char* signalBars(const int8_t rssiDbm) {
  switch (signalTier(rssiDbm)) {
    case 4:
      return "||||";
    case 3:
      return " |||";
    case 2:
      return "  ||";
    default:
      return "   |";
  }
}

// Formats a row's signal subtitle: "<vendor>  <rssi> dBm <bars>" (vendor
// omitted when null), or "<vendor>  Out of range" once nothing has been heard
// from this finding in a while -- a frozen stale number would be misleading
// for fox-hunting, where the point is reading current signal strength.
// `now`/`lastSeenMs` are millis() values; wraparound-safe the same way every
// `millis() - x >= threshold` comparison elsewhere in this codebase is.
inline void formatSignalSubtitle(char* out, const size_t outCap, const char* vendor, const int8_t rssiDbm,
                                 const uint32_t lastSeenMs, const uint32_t now, const uint32_t staleThresholdMs) {
  const bool stale = (now - lastSeenMs) > staleThresholdMs;
  if (stale) {
    if (vendor) {
      snprintf(out, outCap, "%s  %s", vendor, tr(STR_OUT_OF_RANGE));
    } else {
      snprintf(out, outCap, "%s", tr(STR_OUT_OF_RANGE));
    }
  } else if (vendor) {
    snprintf(out, outCap, "%s  %d dBm %s", vendor, rssiDbm, signalBars(rssiDbm));
  } else {
    snprintf(out, outCap, "%d dBm %s", rssiDbm, signalBars(rssiDbm));
  }
}
