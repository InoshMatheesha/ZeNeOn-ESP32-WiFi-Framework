/**
 * WiFi Stack Libraries Bypasser
 *
 * The ESP32 WiFi stack blocks raw management frame injection
 * (deauth, disassoc) via ieee80211_raw_frame_sanity_check().
 * This file provides an override that always returns 0,
 * allowing raw 802.11 management frames to be transmitted.
 *
 * IMPORTANT: This MUST be a .c file (not .cpp) for the linker override to work.
 * Place this file in the same folder as your .ino sketch.
 *
 * On ESP32 Arduino core 3.x, libnet80211.a also defines this symbol.
 * The -zmuldefs linker flag (in platform.local.txt) allows our definition
 * to coexist and take precedence.
 *
 * Based on ESP32-WiFi-Penetration-Tool by risinek
 */

#include <stdint.h>

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}
