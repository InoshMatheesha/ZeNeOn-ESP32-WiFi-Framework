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
| **Classic BT Jammer (nRF24L01)** | Jams Classic Bluetooth (A2DP speakers, headphones, etc.) by flooding all 79 BT frequency-hopping channels (2402–2480 MHz) using an nRF24L01 module via SPI. 2Mbps wideband noise, max TX power. Configurable duration (15–120s) |

<details>
<summary><strong>Hardware Requirements</strong></summary>

- **ESP32** development board (ESP32-WROOM-32 recommended)
- Micro-USB cable
- Computer with Arduino IDE
- **nRF24L01** module (required for Classic Bluetooth jamming)
- 100µF capacitor (between nRF24L01 VCC and GND — prevents power instability)
- Jumper wires for SPI connection

#### nRF24L01 Wiring to ESP32

| nRF24L01 Pin | ESP32 Pin |
|-------------|----------|
| VCC | **3.3V** (NOT 5V!) |
| GND | GND |
| CE | GPIO 4 |
| CSN | GPIO 5 |
| SCK | GPIO 18 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |

> **⚠️ Important:** The nRF24L01 is very power-sensitive. Always add a **100µF capacitor** between VCC and GND directly on the module. Without it, the module will behave erratically or fail to initialize. Use the **3.3V** pin — connecting to 5V will damage the module.

> **Tip:** The **nRF24L01+PA+LNA** variant (with external antenna) has much longer range than the standard module.

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


### 3. Install RF24 Library

1. In Arduino IDE, go to **Sketch > Include Library > Manage Libraries**
2. Search for `RF24`
3. Install **RF24 by TMRh20** (latest version)

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
2. Choose a portal template (Google, Facebook, Microsoft, or Generic)
3. Launch — the ESP32 AP switches to the spoofed SSID
4. Reconnect to the spoofed network
5. Clients connecting will see a login portal
6. Captured credentials are stored and available for download

### WiFi Spam
1. Select the number of fake networks (10–50)
2. Fake SSIDs appear in nearby WiFi scan results
3. Stop anytime from the web interface

### Bluetooth Jammer (BLE)
1. Select jam duration (15s / 30s / 60s / 120s)
2. The jammer floods all 3 BLE advertisement channels with randomized packets
3. Live status shows packets sent, elapsed time, and remaining time
4. Auto-stops when timer expires, or stop manually

> **Note:** BLE jammer only affects BLE devices. For Classic Bluetooth devices (speakers, headphones), use the nRF24 jammer below.

### Classic BT Jammer (nRF24L01)
1. Ensure the nRF24L01 module is properly wired (see Hardware Requirements)
2. Select jam duration (15s / 30s / 60s / 120s)
3. The jammer rapidly hops across all 79 Classic Bluetooth channels, transmitting 2Mbps noise on each
4. Live status shows packets sent, progress, and remaining time
5. Auto-stops when timer expires, or stop manually
6. If the module is not connected, you'll see an error message with wiring instructions

> **Tip:** Keep the nRF24L01 within **1–2 meters** of the target device for best results. The nRF24L01+PA+LNA variant with external antenna works at greater distances.

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
- **Classic BT Jamming (nRF24L01):** Hops across all 79 Bluetooth frequency-hopping channels (2402–2480 MHz) at 2Mbps with max TX power (+7 dBm), transmitting 32-byte randomized noise payloads. Uses SPI interface (GPIO 4/5/18/19/23). No ACK, no CRC, no retries — pure RF noise
- **Phased Attack System:** Automated state machine (PRE_CAPTURE → DEAUTH_BURST → LISTEN → DONE) with configurable cycle timing

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
