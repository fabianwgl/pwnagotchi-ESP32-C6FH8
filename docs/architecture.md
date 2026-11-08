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
                     +----+------------+----+
                          |            |
                    Pkt queue     ClientObs queue
                       (16)            (32)
                          |            |
                 +--------v-----+  +---v-----------+
                 | snifferLoop()|  | updateClient()|
                 | drain 8      |  | client table  |
                 +--+--------+--+  +---------------+
                    |        |
        processBeacon()  processEapol()
        processAssoc()        |
             |                |
       AP table (64)    handshake table (16)
             |                |
             +--------+-------+
                      |
               PCAP writer (SD)
                      |
               faceTick() -> ST7789
```

The targeted deauth state machine runs from `snifferLoop()` and reads the
client table. It sends only when boost is explicitly armed and a target is
selected.

## Source map

| File | Responsibility |
| --- | --- |
| `firmware/pwnagotchi/pwnagotchi.ino` | Setup, main loop, BOOT button, serial command parser, mood changes, RGB LED. |
| `firmware/pwnagotchi/config.h` | Pins, screen geometry, limits, timings, colors. |
| `firmware/pwnagotchi/sniffer.cpp` | Promiscuous RX, AP table, client table, EAPOL state machine, PMKID extraction, targeted and broadcast deauth, PCAP writer, channel control, self-test. |
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
4. Association and reassociation requests are throttled per client to one per
   second and queued for SSID and PMKID parsing.
5. Data frames are checked for an EAPOL LLC/SNAP header. Their `toDS`/`fromDS`
   addresses are sampled at most once per 50 ms globally and pushed to the
   client observation queue.
6. Accepted frames are copied into a `Pkt` (maximum 640 bytes) and sent to the
   queue without blocking. A full queue increments `drops`.
7. `snifferLoop()` drains client observations, then up to 8 packets, parses
   them, and writes every drained packet to the PCAP.

## Client table

`ClientInfo` is keyed by client MAC. The table holds `MAX_CLIENTS` (48)
entries and replaces the oldest when full.

- A client is learned from `toDS` and `fromDS` data frame addresses, even when
  the payload is encrypted.
- Association requests add the client and confirm the AP.
- `CLIENT_ACTIVE_MS` (5 seconds) decides whether a client is fresh enough for
  a targeted deauth burst.
- `CLIENT_STALE_MS` (30 seconds) is the cleanup age. A periodic pass marks
  older entries unused, and new clients reuse those slots.
- `clients` prints the table. `stat` reports total and active counts.

## AP table

`ApInfo` stores BSSID, SSID, SSID length, channel, RSSI, security type, hidden
flag, PMF state, skip flag, handshake/PMKID flags, timestamps, and a beacon
counter. The table holds `MAX_APS` (64) entries. When it is full, the entry
with the oldest `lastSeen` is replaced.

Security classification:

- RSN IE (tag 48) is parsed for AKM suites and RSN capabilities.
- PSK AKMs map to `WPA2`.
- SAE AKMs map to `WPA3`.
- Both PSK and SAE map to `WPA2/3`.
- Vendor WPA IE (tag 221, `00:50:F2:01`) maps to `WPA`.
- Privacy bit without RSN or WPA maps to `WEP`.
- Otherwise the AP is `OPEN`.
- RSN capability bit 6 marks PMF capable, bit 7 marks PMF required.

Only `WPA`, `WPA2`, and `WPA2/3` are counted as crackable targets.

A truncated beacon can lose the RSN IE. `processBeacon()` detects truncation
from `origLen` and an incomplete IE walk. It does not downgrade a known AP's
security type in that case. A new AP seen only in a truncated frame starts as
`AUTH_UNKNOWN` until a complete beacon arrives.

## Skip list

The skip list is an exact, case-sensitive SSID list stored in NVS under the
`pwnagotchi` namespace. It is not part of the repository. Add entries with
`skip add <ssid>`, remove them with `skip del <ssid>`, clear with
`skip clear`, and print with `skips`. A matching AP stays visible in `aps`
with `SKIP Y`, but `strongestIndex()`, `target`, and `boost` all refuse it.

## Handshake state machine

`HsEntry` is keyed by the AP and station MAC pair. The table holds `MAX_HS`
(16) entries and reuses the oldest slot when full.

- EAPOL-Key frames with the pairwise bit are classified as M1, M2, M3, or M4
  from the key information bits.
- The 8-byte EAPOL replay counter is stored for M1, M2, and M3.
- M1+M2 is valid only when the replay counters match.
- M2+M3 is valid only when `m3Replay == m2Replay + 1`.
- A new M1 with a different replay counter re-arms the pair, so a later
  reconnect can be captured and counted again.
- A PMKID is extracted from the key data KDE with vendor `00:0f:ac:04` in M1.
- A second PMKID source is the RSN IE PMKID list in association requests.
  The association frame is written to the PCAP so `hcxpcapngtool` can use it.
- `reported` and `pmkidReported` prevent duplicate events within one attempt.

`HS` is the number of handshakes detected. `SAVED` increments only when the
frame that completed the handshake was successfully written to the PCAP and
flushed. This distinction is intentional: with no SD card, `HS` can rise while
`SAVED` stays at 0.

## PCAP format

- Classic PCAP, magic `0xA1B2C3D4`, version 2.4.
- Link type 127 (`LINKTYPE_IEEE802_11_RADIOTAP`).
- Each record starts with a 15-byte radiotap header: flags, rate, channel,
  and antenna signal. This keeps channel and RSSI with every frame.
- Snaplen 65535.
- Timestamps come from `esp_timer_get_time()`, so they are relative to boot,
  not wall-clock time. `hcxpcapngtool` accepts them.
- Each boot creates a new `/pwn_NNN.pcap`. The next index is found by scanning
  the card root for `pwn_N.pcap`.
- Pausing closes the file. Resuming reopens the same path in append mode and
  restores `g_pcapSize` from the file length, so one session stays in one file.
- Each packet is built in one buffer and written with one `File.write()`.
- The file is flushed after every saved handshake or PMKID, and at least every
  5 seconds, then closed on pause.

## Channel control

- Hop mode cycles channels 1 to 13 every `HOP_MS` (300 ms).
- Lock mode stays on the selected channel.
- Target selection forces lock mode on the target's channel.
- `boost on` forces the target channel and sends a targeted unicast burst to
  one learned client:
  - 3 frames per burst.
  - `DEAUTH_BURST_GAP_MS` (100 ms) between frames.
  - `DEAUTH_COOLDOWN_MS` (5 seconds) between bursts.
  - `DEAUTH_MAX_BURSTS` (12) then boost stops.
  - AP to client reason 7 and client to AP reason 3.
- `boost broadcast on` keeps the legacy behavior: a broadcast deauth from the
  AP every `DEAUTH_INTERVAL_MS` (2500 ms).
- `esp_wifi_80211_tx()` is used for deauth. The firmware overrides
  `ieee80211_raw_frame_sanity_check()` and the build uses `-zmuldefs` so the
  override wins over the ESP-IDF library copy.
- Every deauth frame has an incrementing 12-bit sequence number. Reusing the
  same sequence number can make clients treat repeats as duplicates.
- Boost stops automatically when the target handshake or PMKID is saved, after
  the burst limit, on TX failure, on target change, or when the target becomes
  skipped or PMF-required.

## Display

`face.cpp` uses Arduino_GFX with a hardware SPI bus and an ST7789 panel.

- The static frame is drawn once in `faceBegin()`.
- The face is redrawn only when the mood or look direction changes.
- The status line is redrawn only when the message changes.
- The top bar refreshes every 500 ms.
- The middle and bottom statistics refresh every 1000 ms.

The middle block shows the strongest AP, RSSI bars, `TGT n PMK n`,
`HS n SAVED n`, and `CLI active/total PCAP size`. The bottom bar shows
`PWND n`, where `n` is saved handshakes plus saved PMKIDs, and the current
mode: `HOP`, `LOCK`, or `BOOST`.
- The cursor blinks every 500 ms.

Faces are 170x58 1-bit bitmaps packed MSB-first, with 1 meaning ink. They are
generated from the same text strings as upstream Pwnagotchi and rendered with
DejaVuSansMono-Bold at 45 px.

## Memory and limits

| Limit | Value |
| --- | ---: |
| AP table | 64 |
| Client table | 48 |
| Handshake table | 16 |
| Skip list | 8 |
| Packet queue | 16 |
| Client observation queue | 32 |
| Maximum frame | 640 bytes |
| Beacon interval per BSSID | 3000 ms |
| Probe response interval per BSSID | 500 ms |
| Client observation sample | 50 ms |
| Client active window | 5000 ms |
| Deauth burst | 3 frames |
| Deauth cooldown | 5000 ms |
| Deauth waiting retry | 1000 ms |
| Deauth maximum bursts | 12 |
| SD retry interval | 30000 ms |
| PCAP flush interval | 5000 ms |

The current build uses about 1.1 MB of the 3.3 MB application partition and
about 51 KB of static RAM.

## Testing

- `selftest` feeds synthetic valid M1+M2, mismatched replay, PMKID, and
  M2+M3 frames through the real parser. It proves the state machine without
  transmitting anything.
- `clients` shows the learned client table after real traffic.
- `skips` shows the SSID skip list.
- `demo hs`, `demo pmkid`, `demo happy`, and `demo sleep` exercise the face
  moods.
- `raw <index>` prints the next raw beacon and parser debug data for one AP.
- The host tool is useful for watching the JSON stream and for running the
  offline cracking pipeline.

## Known limitations

- 2.4 GHz only.
- One channel at a time.
- Boost is manual and targets one AP and one client at a time.
- Broadcast deauth is still available as an explicit legacy mode.
- Client MAC randomization can make a device appear as a new client. The
  associated MAC is stable for the session, but it can age out.
- PMF-required APs are refused by boost because forged deauth is ignored.
- No on-device cracking.
- No web UI. The serial protocol is the interface.
- The microSD card is required for PCAP capture.
- WPA3-SAE is detected but not captured by this workflow.
