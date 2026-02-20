# ZeNeOn — ESP32 WiFi & Bluetooth Security Assessment Framework

<div align="center">

![Version](https://img.shields.io/badge/version-5.1-00d4ff?style=for-the-badge&labelColor=05080f)
![Platform](https://img.shields.io/badge/platform-ESP32-0066ff?style=for-the-badge&labelColor=05080f)
![License](https://img.shields.io/badge/license-MIT-00d4ff?style=for-the-badge&labelColor=05080f)
![Arduino](https://img.shields.io/badge/Arduino-IDE-00979D?style=for-the-badge&logo=arduino&labelColor=05080f)

**⚠️ Educational Purpose Only ⚠️**

<img src="images/esp32.jpg" alt="ESP32 Development Board" width="200"/>

*ESP32-WROOM-32 Development Board*

</div>

---

<details>
<summary><strong>User Interface</strong></summary>

<div align="center">

<img src="images/1.png" alt="UI Screenshot 1" width="20%"/> <img src="images/2.png" alt="UI Screenshot 2" width="20%"/>
<img src="images/3.png" alt="UI Screenshot 3" width="20%"/> <img src="images/4.png" alt="UI Screenshot 4" width="20%"/>

*Web interface screenshots showing various attack modules*

</div>

</details>

<details open>
<summary><strong>Features</strong></summary>

| Module | Description |
|--------|-------------|
| **Deauth Attack + Handshake Capture** | Automated phased attack: beacon capture → deauth burst → EAPOL 4-way handshake listen. Broadcast + unicast frame injection, automatic client discovery, real-time EAPOL terminal, PCAP download. Configurable duration (30–120s) |
| **Evil Twin** | Fake AP with captive portal for credential harvesting. 5 templates (Generic WiFi, Google, Facebook, Microsoft, Apple). Auto DNS redirect, credential logging to SPIFFS |
| **WiFi Spam** | Beacon frame flooding — spawn up to 50 fake WiFi networks with random SSIDs |
| **Bluetooth Jammer** | BLE advertisement channel flooding across all 3 BLE channels (37, 38, 39). Randomized MAC addresses and advertisement data per burst. Configurable duration (15–120s) |
| **Packet Capture** | Promiscuous mode sniffer with PCAP export. Auto-captures beacons, auth, assoc, and EAPOL frames during attacks |
| **Live Event Terminal** | Real-time web terminal showing EAPOL messages, phase transitions, beacon captures, and error events |

</details>

<details>
<summary><strong>What's New in v5.1</strong></summary>

- **Bluetooth Jammer** — New module: floods BLE advertisement channels with randomized packets to disrupt nearby Bluetooth devices. Timer-based with live status dashboard.
- **Instant Page Loading** — Deauth page loads instantly (network scan moved to async AJAX instead of blocking page render).
- **Reconnect Overlay** — When the AP switches to target channel for an attack, a reconnect overlay guides the user instead of showing a dead page.
- **Resilient Polling** — All live status/event polling uses retry-capable fetch with automatic reconnection after brief WiFi disconnects during channel changes.
- **WiFi Stack Bypass Fix** — Fixed `wsl_bypasser.c` (was accidentally commented out) so deauth frame injection works correctly.
- **Arduino Preprocessor Compatibility** — JS function declarations converted to `var name=function()` style to prevent Arduino IDE preprocessor conflicts.

</details>

<details>
<summary><strong>Hardware Requirements</strong></summary>

- **ESP32** development board (ESP32-WROOM-32 recommended)
- Micro-USB cable
- Computer with Arduino IDE

> **Note:** ESP8266 is **not** supported. This project requires the ESP32's raw 802.11 frame injection and BLE capabilities.

</details>

<details open>
<summary><strong>Installation</strong></summary>

### 1. Install Arduino IDE and ESP32 Board Support

1. Download and install [Arduino IDE](https://www.arduino.cc/en/software)
2. Go to **File > Preferences** and add this URL to "Additional Board Manager URLs":
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Go to **Tools > Board > Boards Manager**, search for `esp32`, and install **esp32 by Espressif Systems**

### 2. Configure Board Settings

| Setting | Value |
|---------|-------|
| Board | ESP32 Dev Module |
| Upload Speed | 921600 |
| CPU Frequency | 240MHz |
| Flash Frequency | 80MHz |
| Flash Size | 4MB (32Mb) |
| **Partition Scheme** | **Huge APP (3MB No OTA/1MB SPIFFS)** |
| PSRAM | Disabled |

> **⚠️ IMPORTANT:** You **must** select **"Huge APP (3MB No OTA/1MB SPIFFS)"** as the Partition Scheme. The default partition is too small (1.3MB) for the firmware which includes WiFi + Bluetooth + all UI templates. The Huge APP scheme provides ~3MB for the sketch.

### 3. Linker Override (Required for Deauth)

The ESP32 Arduino core 2.x requires a linker flag to allow the `wsl_bypasser.c` override. Create this file if it doesn't already exist:

**File:** `{Arduino15}/packages/esp32/hardware/esp32/{version}/platform.local.txt`

Typical path: `C:\Users\{YourName}\AppData\Local\Arduino15\packages\esp32\hardware\esp32\2.0.14\platform.local.txt`

**Contents:**
```
compiler.c.elf.extra_flags=-Wl,--allow-multiple-definition
```

> This tells the linker to use the `wsl_bypasser.c` override instead of the library's built-in function.

### 4. Upload

1. Clone this repository:
   ```bash
   git clone https://github.com/InoshMatheesha/ZeNeOn-ESP32-WiFi-Framework.git
   ```
2. Open `ZeNeOn-ESP32-WiFi-Framework.ino` in Arduino IDE
3. Ensure `wsl_bypasser.c` is in the **same folder** as the `.ino` file
4. Select your ESP32 board and COM port
5. Set Partition Scheme to **Huge APP (3MB No OTA/1MB SPIFFS)**
6. Click **Upload**

</details>

<details>
<summary><strong>Usage</strong></summary>

1. Power on the ESP32
2. Connect to the WiFi network:
   - **SSID:** `ZeNeOn`
   - **Password:** `12345678`
3. Open a browser and navigate to `http://192.168.4.1`
4. Select a module from the web interface

### Deauth Attack + Handshake Capture
1. Select a target network from the scan list
2. Wait for client discovery (automatic)
3. Choose attack duration (30s / 60s / 90s / 120s)
4. The attack runs automatically in phases:
   - **Phase 1:** Capture beacons from target AP
   - **Phase 2:** Deauth burst to disconnect clients
   - **Phase 3:** Listen for EAPOL handshake (clients reconnecting)
   - Repeats deauth/listen cycles until time expires or handshake captured
5. Monitor real-time EAPOL M1/M2/M3/M4 status in the live terminal
6. Download the `.pcap` file after attack completes (compatible with hashcat/hcxpcapngtool)

### Evil Twin
1. Enter the target SSID name
2. Choose a portal template (Google, Facebook, Microsoft, Apple, or Generic)
3. Launch — the ESP32 AP switches to the spoofed SSID
4. Reconnect to the spoofed network
5. Clients connecting will see a login portal
6. Captured credentials are stored and available for download

### WiFi Spam
1. Select the number of fake networks (10–50)
2. Fake SSIDs appear in nearby WiFi scan results
3. Stop anytime from the web interface

### Bluetooth Jammer
1. Select jam duration (15s / 30s / 60s / 120s)
2. The jammer floods all 3 BLE advertisement channels with randomized packets
3. Live status shows packets sent, elapsed time, and remaining time
4. Auto-stops when timer expires, or stop manually

</details>

<details>
<summary><strong>Project Structure</strong></summary>

```
ZeNeOn-ESP32-WiFi-Framework/
├── ZeNeOn-ESP32-WiFi-Framework.ino   # Main firmware (UI + attack logic)
├── wsl_bypasser.c                     # WiFi stack bypass for raw frame injection
├── README.md
└── images/                            # UI screenshots
```

### Key Components

- **wsl_bypasser.c** — Overrides `ieee80211_raw_frame_sanity_check()` to enable raw 802.11 management frame transmission (deauth/disassoc). Must be a `.c` file for the weak symbol linker override to work.
- **Web Interface** — Responsive hacker-themed interface served directly from the ESP32, built with HTML/CSS/JS inside raw string literals.
- **SPIFFS** — Used for storing PCAP capture files and harvested credentials on-device.
- **BLE Stack** — ESP32 Bluetooth controller initialized on-demand for BLE jamming, released when done to free resources.

</details>

<details>
<summary><strong>Technical Details</strong></summary>

- **Frame Injection:** Raw 802.11 deauth (0xC0) and disassoc (0xA0) frames with multiple reason codes
- **Client Discovery:** Passive sniffing of management and data frames to identify connected clients
- **Targeted Deauth:** Unicast frames sent to each discovered client + broadcast floods + spoofed client→AP frames
- **PCAP Format:** Standard libpcap format (magic: `0xa1b2c3d4`, link type: 802.11)
- **EAPOL Parsing:** Identifies all 4 messages of the WPA 4-way handshake with per-message tracking
- **Handshake Detection:** M1+M2 or M2+M3 pair = usable handshake for hashcat
- **DNS Hijack:** Captive portal redirect via DNS server for Evil Twin attack
- **TX Power:** Configured to maximum (84 = 21dBm)
- **BLE Jamming:** Floods BLE channels 37/38/39 with non-connectable undirected advertisements, random MAC per burst, fastest interval (20ms)
- **Phased Attack System:** Automated state machine (PRE_CAPTURE → DEAUTH_BURST → LISTEN → DONE) with configurable cycle timing

</details>

<details>
<summary><strong>Troubleshooting</strong></summary>

| Problem | Solution |
|---------|----------|
| `text section exceeds available space` | Change Partition Scheme to **Huge APP (3MB No OTA/1MB SPIFFS)** in Arduino IDE board settings |
| `multiple definition of ieee80211_raw_frame_sanity_check` | Create `platform.local.txt` with `compiler.c.elf.extra_flags=-Wl,--allow-multiple-definition` (see Installation step 3) |
| `'function' does not name a type` | Ensure all JS `function` declarations inside raw literals use `var name=function()` syntax (already fixed in v5.1) |
| Deauth not working / no packets sent | Verify `wsl_bypasser.c` is NOT commented out — the `#include` and function must be outside any `/* */` block |
| Page loads slowly when clicking Deauth | Fixed in v5.1 — network scan is now async AJAX instead of blocking |
| Disconnect during attack / page dies | Fixed in v5.1 — reconnect overlay + retry-capable fetch polling |
| BT Jammer: "BT init failed" | Ensure your ESP32 board has Bluetooth hardware (ESP32-WROOM-32). Some ESP32-S2 boards lack BT |

</details>

## Disclaimer

> **This tool is intended strictly for educational purposes and authorized security testing only.**
>
> Unauthorized access to computer networks is **illegal**. The author is **not responsible** for any misuse of this software. Always obtain **explicit written permission** before testing networks you do not own.
>
> Use responsibly and ethically. Know your local laws.

## Contributing

Contributions are welcome. Feel free to:
- Open issues for bugs or feature requests
- Submit pull requests with improvements
- Share ideas for new modules

## Acknowledgements

This project was developed as a learning exercise. Special thanks to:
- **Google Gemini** and **OpenAI ChatGPT** — for teaching and guiding me throughout the development process, helping me understand ESP32 programming, 802.11 frame structures, and embedded web server concepts.
- The open-source ESP32 community and Espressif documentation.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

**Inosh Matheesha** — [@InoshMatheesha](https://github.com/InoshMatheesha)

---

<div align="center">

**ZeNeOn** Framework v5.1 — ESP32 WiFi & Bluetooth Security Assessment

</div>
