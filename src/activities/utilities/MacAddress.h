#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

// Parses "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF" (case-insensitive) into 6
// raw bytes. Used by the Hunting tools' manual-entry fallback, when no device
// was tapped from an existing scan to copy an address from. `%2x` width-limits
// each group to two hex digits (so "AAA:.." fails to match rather than
// silently truncating) and `%n` must land exactly on the string's end (so
// trailing garbage after a valid address is rejected, not ignored).
inline bool parseMacAddress(const std::string& text, uint8_t out[6]) {
  int bytes[6];
  int consumed = 0;
  int matched = sscanf(text.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x%n", &bytes[0], &bytes[1], &bytes[2], &bytes[3],
                       &bytes[4], &bytes[5], &consumed);
  if (matched != 6 || static_cast<size_t>(consumed) != text.size()) {
    consumed = 0;
    matched = sscanf(text.c_str(), "%2x-%2x-%2x-%2x-%2x-%2x%n", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4],
                     &bytes[5], &consumed);
    if (matched != 6 || static_cast<size_t>(consumed) != text.size()) return false;
  }
  for (int i = 0; i < 6; i++) out[i] = static_cast<uint8_t>(bytes[i]);
  return true;
}
