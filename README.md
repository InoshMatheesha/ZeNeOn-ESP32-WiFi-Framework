# ZeNeOn - ESP32 WiFi & Bluetooth Security Framework

![Version](https://img.shields.io/badge/version-5.1-00d4ff?style=for-the-badge&labelColor=05080f)
![Platform](https://img.shields.io/badge/platform-ESP32-0066ff?style=for-the-badge&labelColor=05080f)
![License](https://img.shields.io/badge/license-MIT-00d4ff?style=for-the-badge&labelColor=05080f)

> **For educational and authorized testing purposes only.**

## Features

| Module | Description |
|--------|-------------|
| Deauth + Handshake Capture | Automated phased WPA handshake capture with PCAP export |
| Evil Twin | Fake AP with captive portal credential harvesting (5 templates) |
| WiFi Spam | Beacon flooding — up to 50 fake networks |
| BLE Jammer | BLE advertisement channel flooding (channels 37, 38, 39) |
| Classic BT Jammer | nRF24L01-based 2.4GHz Classic Bluetooth jamming (79 channels) |

## Requirements

- ESP32-WROOM-32 development board
- Micro-USB cable
- Arduino IDE
- nRF24L01 module (optional, for Classic BT jamming)

## Installation

### 1. Board Setup

Install ESP32 board support in Arduino IDE. Add this URL under **File > Preferences > Additional Board Manager URLs**:

```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```

### 2. Board Configuration

| Setting | Value |
|---------|-------|
| Board | ESP32 Dev Module |
| Partition Scheme | Huge APP (3MB No OTA/1MB SPIFFS) |
| Upload Speed | 921600 |
| CPU Frequency | 240MHz |

The **Huge APP** partition scheme is required — the default partition is too small for this firmware.

### 3. Linker Override

Create `platform.local.txt` at:

```
C:\Users\{YourName}\AppData\Local\Arduino15\packages\esp32\hardware\esp32\{version}\
```

Contents:

```
compiler.c.elf.extra_flags=-Wl,--allow-multiple-definition
```

### 4. Upload

```bash
git clone https://github.com/InoshMatheesha/ZeNeOn-ESP32-WiFi-Framework.git
```

Open the `.ino` file in Arduino IDE. Ensure `wsl_bypasser.c` is in the same folder. Select your board, COM port, and upload.

## Usage

1. Power on the ESP32
2. Connect to **ZeNeOn** (password: `12345678`)
3. Open `http://192.168.4.1`
4. Select a module from the interface

## nRF24L01 Wiring (Classic BT Jammer)

| nRF24L01 | ESP32 |
|----------|-------|
| VCC | 3.3V |
| GND | GND |
| CE | GPIO 4 |
| CSN | GPIO 5 |
| SCK | GPIO 18 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |

Add a 100uF capacitor between VCC and GND on the nRF24 module.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Text section exceeds available space | Set Partition Scheme to **Huge APP** |
| Multiple definition linker error | Create `platform.local.txt` (see step 3) |
| Deauth not sending packets | Verify `wsl_bypasser.c` is not commented out |
| BT init failed | Ensure your board has Bluetooth (ESP32-S2 does not) |
| nRF24 not found | Check wiring and 3.3V power with capacitor |

## Disclaimer

This tool is for educational purposes and authorized security testing only. Unauthorized access to networks is illegal. The author is not responsible for misuse. Obtain written permission before testing networks you do not own.

## License

[MIT License](LICENSE)

## Author

Inosh Matheesha — [@InoshMatheesha](https://github.com/InoshMatheesha)
