# Hardware

## Board

The firmware targets the **Waveshare ESP32-C6-LCD-1.47**.

- ESP32-C6FH8, 8 MB flash
- 2.4 GHz WiFi 6 radio, 802.11 b/g/n/ax
- 1.47 inch ST7789 LCD, 172x320 native, used as 320x172 landscape
- microSD card slot on the shared SPI bus
- WS2812 RGB LED on GPIO 8
- BOOT button on GPIO 9

The board has one radio. It listens to one channel at a time and cannot see
5 GHz. It is not a full monitor-mode adapter: promiscuous mode captures
management and data frames, but not control frames, and frames can be missed
under heavy load.

## Pin map

| Signal | GPIO | Notes |
| --- | ---: | --- |
| LCD MOSI | 6 | shared SPI data out |
| LCD SCLK | 7 | shared SPI clock |
| LCD MISO | 5 | shared SPI data in |
| LCD CS | 14 | display chip select |
| LCD DC | 15 | display data/command |
| LCD RST | 21 | display reset |
| LCD BL | 22 | backlight, driven high |
| SD CS | 4 | microSD chip select |
| RGB LED | 8 | WS2812 data |
| BOOT | 9 | active low, internal pull-up |

The display and the microSD card share MOSI, MISO, and SCLK. The firmware
starts the display at 40 MHz and the SD card at 4 MHz.

## Display

- Controller: ST7789, IPS panel.
- Native orientation: 172x320.
- Firmware orientation: 320x172 landscape with `DISPLAY_ROTATION 1`.
- Column offsets: 34 on both sides. Row offsets: 0.
- If the image is upside down on your board, set `DISPLAY_ROTATION` to `3`
  in `firmware/pwnagotchi/config.h` and reflash.

The UI uses a near-white paper background (`#FAFAF5`) and near-black ink
(`#0C0C0C`), with thin horizontal rules. The static frame is drawn once. The
face, status line, top bar, and statistics are redrawn separately to avoid
flicker.

## microSD card

- FAT32 is required.
- The card is mounted at boot and retried every 30 seconds if it is missing.
- Each boot creates a new `/pwn_NNN.pcap` file, so resetting the board does
  not overwrite the previous session.
- Pausing closes the file. Resuming reopens the same file in append mode, so
  a pause does not split the session.
- The PCAP is flushed every 5 seconds.
- Remove the card after a session and copy the newest file to the host.

Without a card the sniffer still runs and reports detected handshakes, but
`SAVED` stays at 0 because nothing can be written.

## Controls and indicators

| Control | Action |
| --- | --- |
| BOOT short press | Toggle channel lock. Locked mode stays on the strongest crackable AP's channel. Unlocked mode hops channels 1 to 13. |
| BOOT long press (1 second) | Pause or resume. While paused the face sleeps. |
| RGB LED, green pulse | A new AP was added to the table. |
| RGB LED, amber pulse | A handshake was detected. |
| RGB LED, magenta pulse | A PMKID was detected. |

The top bar shows channel, AP count, uptime, and SD state. The middle block
shows the strongest visible AP, RSSI bars, target count, PMKID count,
`HS n  SAVED n`, and PCAP size. The bottom bar shows the detected handshake
count and the current mode: `HOP`, `LOCK`, or `BOOST`.

## Power

The board is powered over USB-C. Use a stable 5 V supply. Deauthentication
bursts in boost mode draw short current spikes, so a weak cable or hub can
cause resets. The firmware does not implement battery charging or sleep
management.

## Troubleshooting

- **Display is upside down.** Set `DISPLAY_ROTATION` to `3`.
- **No SD state.** Check that the card is FAT32 and seated. The firmware
  retries every 30 seconds.
- **`boost on` reports a TX error.** Build with
  `compiler.c.elf.extra_flags=-zmuldefs`. Without it, the ESP-IDF library
  version of `ieee80211_raw_frame_sanity_check` blocks deauth frames.
- **No serial port on macOS.** Check `ls /dev/cu.*`. The C6 uses native USB
  CDC, so no extra driver is normally needed. The host tool waits 3 seconds
  after opening the port because macOS resets the board on connect.
- **No handshakes.** Lock to the target's channel, make sure a client
  reconnects, and remember that PMKIDs are not present on every AP.
