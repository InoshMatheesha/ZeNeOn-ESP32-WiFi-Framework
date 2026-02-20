/**
 * WiFi Stack Libraries Bypasser
 *
 * The ESP32 WiFi stack blocks raw management frame injection
 * (deauth, disassoc) via ieee80211_raw_frame_sanity_check().
 * This file provides a weak symbol override that always returns 0,
 * allowing raw 802.11 management frames to be transmitted.
 *
 * IMPORTANT: This MUST be a .c file (not .cpp) for the linker override to work.
 * Place this file in the same folder as your .ino sketch.
 *
 * Based on ESP32-WiFi-Penetration-Tool by risinek
 */

#include <stdint.h>

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}