# esp32-pwnagotchi

## Scope

- Firmware for the Waveshare ESP32-C6-LCD-1.47: passive 2.4 GHz WiFi sniffer,
  WPA2 handshake and PMKID capture, SD PCAP writer, and Pwnagotchi-style face.
- Host Python tool: serial JSON viewer plus optional hcxpcapngtool/hashcat.
- Public repo: https://github.com/fabianwgl/pwnagotchi-ESP32-C6FH8
- License: GPL-3.0. Keep the Pwnagotchi and DejaVu attributions in `NOTICE` and
  `assets/DejaVu-LICENSE.txt`.

## Safety and legal

- Keep the README legal warning and the "networks you own or have permission
  to test" language.
- Boost mode must stay off by default and must require an explicit target.
- Do not add automatic deauth, on-device cracking, hidden capture behavior, or
  anything that targets networks without user intent.
- Never commit real PCAPs, handshakes, PMKIDs, SSIDs, BSSIDs, wordlists, or
  personal paths. `.gitignore` already blocks `*.pcap`, `*.pcapng`, `*.22000`,
  `*.csv`, `*.jsonl`, and `.env*`.
- The repo is public. Run a private-data scan before every push.

## Build and flash

Arduino CLI with core `esp32:esp32@3.3.12` and the GFX library:

```sh
arduino-cli core install esp32:esp32@3.3.12
arduino-cli lib install "GFX Library for Arduino"

FQBN="esp32:esp32:esp32c6:CDCOnBoot=cdc,FlashSize=8M,PartitionScheme=default_8MB"

arduino-cli compile --fqbn "$FQBN" \
  --build-property "compiler.c.elf.extra_flags=-zmuldefs" \
  --output-dir build firmware/pwnagotchi

arduino-cli upload -p /dev/cu.usbmodem101 --fqbn "$FQBN" \
  --input-dir build firmware/pwnagotchi
```

- `-zmuldefs` is mandatory for boost mode. It makes the sketch's
  `ieee80211_raw_frame_sanity_check` override win over the ESP-IDF copy. Do not
  remove it.
- `build/`, `firmware/**/build/`, and `.venv/` are ignored. Never commit them.
- The board is 2.4 GHz only and listens to one channel at a time.

## Host tool

```sh
python3 -m venv .venv
.venv/bin/pip install -r host/requirements.txt
.venv/bin/python host/pwnagotchi.py --help
```

- Serial settings: 115200 8N1. Device events are one JSON object per line.
- `aps`, `clients`, and `skips` are plain text, not JSON.
- `--crack` shells out to `hcxpcapngtool` and `hashcat`.
- macOS resets the board when the USB CDC port opens. The host waits 3 seconds.

## Face assets

```sh
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python tools/gen_faces.py
```

- Regenerates `firmware/pwnagotchi/face_assets.h` and
  `assets/faces_preview.png`.
- Never hand-edit `face_assets.h`.
- Face strings and font licensing are described in `NOTICE` and the README.

## Code map

- `firmware/pwnagotchi/config.h`: pins, 320x172 geometry, limits, timings.
- `firmware/pwnagotchi/sniffer.cpp`: promiscuous RX, AP and client tables,
  EAPOL state machine, PMKID extraction, PCAP writer, channel hop/lock,
  targeted and broadcast boost, skip list.
- `firmware/pwnagotchi/face.cpp`: ST7789 layout, moods, partial redraw.
- `firmware/pwnagotchi/pwnagotchi.ino`: setup/loop, BOOT button, serial command
  parser, RGB LED.
- `host/pwnagotchi.py`: serial event viewer and crack helper.
- `tools/gen_faces.py`: 1-bit face bitmap generator.
- `docs/hardware.md`: pins, display, SD, controls.
- `docs/serial-protocol.md`: commands and JSON events.
- `docs/architecture.md`: packet path, state machine, PCAP format.

## Invariants

- Strip the 4-byte FCS from `sig_len` before parsing and PCAP writes.
- `HS` counts detected handshakes. `SAVED` increments only when the completing
  EAPOL frame is written and flushed to the PCAP. The same applies to
  `saved_pmkid`.
- `clear` resets detected counters, per-AP flags, and the full handshake pair
  state, but not `SAVED`.
- Pause closes the PCAP. Resume reopens the same path in append mode. Do not
  create a new file or rewrite the header on resume.
- Each boot creates `/pwn_NNN.pcap` with link type 127 and radiotap headers.
  Timestamps are relative to boot.
- Beacon throttle is 3 seconds per BSSID. Probe response throttle is 500 ms.
  Association request throttle is 1 second per client.
- Queue length 16, client observation queue 32, max frame 640 bytes, AP table
  64, client table 48, handshake table 16.
- Clients are learned only from data frames and association requests. A client
  must be active within 5 seconds to be selected for boost.
- The display redraws only changed regions. Keep the static frame and rules.
- Boost is targeted unicast deauth to one learned client. It must stay opt-in,
  require an explicit target, and stay within 3 frames per burst, 100 ms
  between frames, 5 seconds between bursts, and 12 bursts.
- `boost broadcast on` is the explicit legacy mode, 2500 ms per frame. It is
  never the default.
- Boost stops automatically when the target handshake or PMKID is saved.
- SSIDs in `SKIP_SSIDS` are never selected by `target`, `strongestIndex`, or
  boost. `PrivateNet` is in the list by default.
- PMF-required APs are never boosted. PMF-capable APs may be boosted.
- Replay counters must match for M1+M2 and `m3Replay == m2Replay + 1` for
  M2+M3.
- Only WPA, WPA2, and WPA2/3 count as crackable targets.

## Testing

- Minimum firmware check: the exact `arduino-cli compile` command above.
- Python syntax: `python3 -m py_compile host/pwnagotchi.py tools/gen_faces.py`.
- Generator check: run `tools/gen_faces.py` to a temp path and `cmp` its output
  with `firmware/pwnagotchi/face_assets.h`.
- Hardware checks: `selftest`, `demo hs`, `demo pmkid`, `aps`, `clients`,
  `skips`, `status`.
- There is no hardware CI. State exactly what was compiled or tested.

## Style

- C++: 2-space indent, same-line braces, `static` for file-local functions,
  JSON lines via `Serial.printf`, no dynamic allocation in hot paths.
- Python: 4-space indent, standard library plus pyserial in `host`, Pillow only
  in `tools`.
- Docs: short sentences, no em dashes, keep commands exact.
- Git: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`), no agent or
  tool labels in branch names or messages, do not force-push.
- Update this file and the relevant docs when behavior, build steps, or limits
  change.

## Current limits

- 2.4 GHz only, one channel at a time.
- WPA3-SAE is detected but not captured.
- microSD is required for PCAP capture.
- No web UI. Serial is the interface.
- Boost is manual and targets one AP and one client at a time.
- Broadcast deauth remains available as an explicit legacy mode.
- Client MAC randomization can hide devices over time.
