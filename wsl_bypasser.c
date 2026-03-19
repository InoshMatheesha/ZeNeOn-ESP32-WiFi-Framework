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
 *
 * NOTE: ESP32 Arduino core 3.x (libnet80211.a) already exports this symbol
 * and returns 0 by default, so the override is only needed on core 2.x.
 */

#include <esp_arduino_version.h>
#include <stdint.h>


/* Only provide our own definition on core 2.x.
   On core 3.x the symbol already exists in libnet80211.a and redefining
   it causes a "multiple definition" linker error. */
#if ESP_ARDUINO_VERSION_MAJOR < 3
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}
#endif
