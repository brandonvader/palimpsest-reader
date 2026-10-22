#pragma once

#include <GfxRenderer.h>

#include <cstdint>

#include "SignalStrength.h"

// Non-directional signal-strength gauge for the Hunting tools: the hardware
// has one omnidirectional antenna with no bearing data, so this shows
// proximity, not direction. Four concentric target rings (always drawn) frame
// a solid center blip whose radius grows with signalTier() -- a near-full
// blip means "very close/strong", a blip filling only the innermost ring
// means "weak", and no blip at all means nothing has been heard yet (out of
// range). fillRoundedRect/drawRoundedRect with width == height == 2*radius
// and cornerRadius == radius degenerate into a filled/outlined circle -- this
// is the only circle primitive the renderer exposes publicly.
namespace signalgauge {

constexpr int RING_COUNT = 4;

inline void drawRing(const GfxRenderer& renderer, const int cx, const int cy, const int radius) {
  if (radius <= 0) return;
  renderer.drawRoundedRect(cx - radius, cy - radius, radius * 2, radius * 2, /*lineWidth=*/1, radius, true);
}

inline void fillBlip(const GfxRenderer& renderer, const int cx, const int cy, const int radius) {
  if (radius <= 0) return;
  renderer.fillRoundedRect(cx - radius, cy - radius, radius * 2, radius * 2, radius, Color::Black);
}

// `hasSignal` is false until the target has been heard from at least once;
// `stale` means it was heard from before but not within the caller's
// staleness threshold (shown the same as never-heard: no blip).
inline void draw(const GfxRenderer& renderer, const int cx, const int cy, const int outerRadius, const int8_t rssiDbm,
                 const bool hasSignal, const bool stale) {
  for (int ring = 1; ring <= RING_COUNT; ring++) {
    drawRing(renderer, cx, cy, outerRadius * ring / RING_COUNT);
  }
  if (!hasSignal || stale) return;
  const int tier = signalTier(rssiDbm);  // 1..4
  fillBlip(renderer, cx, cy, outerRadius * tier / RING_COUNT);
}

}  // namespace signalgauge
