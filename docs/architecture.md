# Architecture

## Overview

The firmware is a small cooperative loop, not an RTOS application. The WiFi
driver delivers frames through a promiscuous callback, the callback copies
candidate frames into a FreeRTOS queue, and the main loop parses them, updates
state, writes the PCAP, and redraws the display.

```text
                     +----------------------+
  802.11 frames ---> | wifiRx() callback    |
                     | strip FCS, filter,   |
                     | throttle, enqueue    |
                     +----------+-----------+
                                |
                          Pkt queue (16)
                                |
                     +----------v-----------+
                     | snifferLoop()        |
                     | drain up to 8 frames |
                     +----+------------+----+
                          |            |
              processBeacon()     processEapol()
                    |                  |
              AP table (64)     handshake table (16)
                    |                  |
                    +--------+---------+
                             |
                      PCAP writer (SD)
                             |
                      faceTick() -> ST7789
```

## Source map

| File | Responsibility |
| --- | --- |
| `firmware/pwnagotchi/pwnagotchi.ino` | Setup, main loop, BOOT button, serial command parser, mood changes, RGB LED. |
| `firmware/pwnagotchi/config.h` | Pins, screen geometry, limits, timings, colors. |
| `firmware/pwnagotchi/sniffer.cpp` | Promiscuous RX, AP table, EAPOL state machine, PMKID extraction, PCAP writer, channel control, boost mode, self-test. |
| `firmware/pwnagotchi/sniffer.h` | Public sniffer types and API. |
| `firmware/pwnagotchi/face.cpp` | Landscape UI layout and partial redraw logic. |
| `firmware/pwnagotchi/face.h` | Face moods and display state. |
| `firmware/pwnagotchi/face_assets.h` | Generated 1-bit face bitmaps. Do not edit by hand. |
| `host/pwnagotchi.py` | Serial event viewer and optional hcxpcapngtool/hashcat pipeline. |
| `tools/gen_faces.py` | Renders the Pwnagotchi text faces into `face_assets.h` and a preview. |

## Packet path

1. `wifiRx()` receives a `wifi_promiscuous_pkt_t`.
2. The 4-byte FCS is stripped from `sig_len`.
3. Management subtypes 8 (beacon) and 5 (probe response) are throttled per
   BSSID: one beacon every 3 seconds, one probe response every 500 ms.
4. Data frames are checked for an EAPOL LLC/SNAP header.
5. Accepted frames are copied into a `Pkt` (maximum 640 bytes) and sent to the
   queue without blocking. A full queue increments `drops`.
6. `snifferLoop()` drains up to 8 packets per iteration, parses them, and
   writes every drained packet to the PCAP.

## AP table

`ApInfo` stores BSSID, SSID, SSID length, channel, RSSI, security type, hidden
flag, handshake/PMKID flags, timestamps, and a beacon counter. The table holds
`MAX_APS` (64) entries. When it is full, the entry with the oldest `lastSeen`
is replaced.

Security classification:

- RSN IE (tag 48) is parsed for AKM suites.
- PSK AKMs map to `WPA2`.
- SAE AKMs map to `WPA3`.
- Both PSK and SAE map to `WPA2/3`.
- Vendor WPA IE (tag 221, `00:50:F2:01`) maps to `WPA`.
- Privacy bit without RSN or WPA maps to `WEP`.
- Otherwise the AP is `OPEN`.

Only `WPA`, `WPA2`, and `WPA2/3` are counted as crackable targets.

## Handshake state machine

`HsEntry` is keyed by the AP and station MAC pair. The table holds `MAX_HS`
(16) entries and reuses the oldest slot when full.

- EAPOL-Key frames with the pairwise bit are classified as M1, M2, M3, or M4
  from the key information bits.
- A handshake is reported once when M1+M2 or M2+M3 have been seen.
- A PMKID is extracted from the key data KDE with vendor `00:0f:ac:04` in M1.
- `reported` and `pmkidReported` prevent duplicate events for the same pair.

`HS` is the number of handshakes detected. `SAVED` increments only when the
frame that completed the handshake was successfully written to the PCAP. This
distinction is intentional: with no SD card, `HS` can rise while `SAVED`
stays at 0.

## PCAP format

- Classic PCAP, magic `0xA1B2C3D4`, version 2.4.
- Link type 105 (`LINKTYPE_IEEE802_11`).
- Snaplen 65535.
- Timestamps come from `esp_timer_get_time()`, so they are relative to boot,
  not wall-clock time. `hcxpcapngtool` accepts them.
- Each boot creates a new `/pwn_NNN.pcap`. The next index is found by scanning
  the card root for `pwn_N.pcap`.
- Pausing closes the file. Resuming reopens the same path in append mode and
  restores `g_pcapSize` from the file length, so one session stays in one file.
- The file is flushed every 5 seconds and closed on pause.

## Channel control

- Hop mode cycles channels 1 to 13 every `HOP_MS` (300 ms).
- Lock mode stays on the selected channel.
- Target selection forces lock mode on the target's channel.
- Boost mode forces the target channel and sends a broadcast deauth frame
  every `DEAUTH_INTERVAL_MS` (2500 ms) from the AP's BSSID.
- `esp_wifi_80211_tx()` is used for deauth. The firmware overrides
  `ieee80211_raw_frame_sanity_check()` and the build uses `-zmuldefs` so the
  override wins over the ESP-IDF library copy.

## Display

`face.cpp` uses Arduino_GFX with a hardware SPI bus and an ST7789 panel.

- The static frame is drawn once in `faceBegin()`.
- The face is redrawn only when the mood or look direction changes.
- The status line is redrawn only when the message changes.
- The top bar refreshes every 500 ms.
- The middle and bottom statistics refresh every 1000 ms.
- The cursor blinks every 500 ms.

Faces are 170x58 1-bit bitmaps packed MSB-first, with 1 meaning ink. They are
generated from the same text strings as upstream Pwnagotchi and rendered with
DejaVuSansMono-Bold at 45 px.

## Memory and limits

| Limit | Value |
| --- | ---: |
| AP table | 64 |
| Handshake table | 16 |
| Packet queue | 16 |
| Maximum frame | 640 bytes |
| Beacon interval per BSSID | 3000 ms |
| Probe response interval per BSSID | 500 ms |
| SD retry interval | 30000 ms |
| PCAP flush interval | 5000 ms |

The current build uses about 1.1 MB of the 3.3 MB application partition and
about 49 KB of static RAM.

## Testing

- `selftest` feeds a synthetic M1+M2 and PMKID through the real parser. It
  proves the state machine without transmitting anything.
- `demo hs`, `demo pmkid`, `demo happy`, and `demo sleep` exercise the face
  moods.
- `raw <index>` prints the next raw beacon and parser debug data for one AP.
- The host tool is useful for watching the JSON stream and for running the
  offline cracking pipeline.

## Known limitations

- 2.4 GHz only.
- One channel at a time.
- Broadcast deauth is crude. Per-client tracking would be more precise.
- No on-device cracking.
- No web UI. The serial protocol is the interface.
- The microSD card is required for PCAP capture.
- WPA3-SAE is detected but not captured by this workflow.
