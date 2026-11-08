# Serial protocol

The firmware exposes a line-oriented protocol over the native USB CDC port.

- Baud rate: 115200, 8 data bits, no parity, 1 stop bit.
- Each message is one UTF-8 line terminated by `\n`.
- Device events are JSON objects. The ROM boot messages and the `aps` table
  are plain text, so ignore lines that do not start with `{`.
- The host tool auto-detects the Espressif USB vendor ID (`0x303A`).

## Commands

Send one command per line.

| Command | Effect | Reply |
| --- | --- | --- |
| `help` | List commands. | `help` event |
| `status` | Print one statistics object. | `stat` event |
| `aps` | Print the AP table. | Plain text table |
| `clients` | Print the client table. | Plain text table |
| `skips` | Print the SSID skip list. | Plain text list |
| `pcap` | Print the current capture path and size. | `pcap` event |
| `pause` | Stop sniffing and close the PCAP. | `state` event |
| `resume` | Start sniffing and reopen the PCAP. | `state` event |
| `hop` | Enable channel hopping. | `mode` event |
| `lock <1-13>` | Lock a channel. | `mode` event |
| `target <index>` | Select an AP from `aps` and lock its channel. | `target` event |
| `raw <index>` | Print the next raw beacon for an AP. | `rawwait`, then `raw` and `parsedbg` |
| `boost on` | Start targeted unicast deauth. Requires a target. | `boost` event or `error` |
| `boost off` | Stop boost. | `boost` event |
| `boost broadcast on` | Start legacy broadcast deauth. Requires a target. | `boost` event or `error` |
| `boost broadcast off` | Stop legacy broadcast deauth. | `boost` event |
| `clear` | Reset detected HS/PMKID counters. | `clear` event |
| `selftest` | Feed synthetic handshake, replay, and PMKID frames through the parser. | `selftest` event |
| `demo hs` | Show the excited face. | `demo` event |
| `demo pmkid` | Show the love face. | `demo` event |
| `demo happy` | Show the happy face. | `demo` event |
| `demo sleep` | Show the sleeping face. | `demo` event |
| `reboot` | Restart the board. | `reboot` event |

`target` and `boost` are deliberately separate. Selecting a target only locks
the radio to its channel. `boost on` starts targeted unicast deauth to one
client learned on that AP. It sends 3 frames per burst, waits 5 seconds, and
stops after 12 bursts or when the target capture is saved. `boost broadcast on`
is the legacy broadcast mode and is explicit only. Use either one only on
networks you own or have written permission to test.

APs whose SSID is in the skip list are never selected by `target` or used by
boost. `PrivateNet` is skipped by default. Edit `SKIP_SSIDS` in
`firmware/pwnagotchi/sniffer.cpp` to change the list.

`clear` resets the detected counters, the per-AP handshake/PMKID flags, and the
handshake pair state. It does not reset `SAVED`, because the current PCAP file
still contains the captures that were already written.

`selftest` changes the counters and does not write to the PCAP. Run `clear`
afterwards if you want a clean display.

## Events

### `boot`

Emitted once at startup.

```json
{"t":"boot","name":"esp32-pwnagotchi","board":"waveshare-c6-lcd-1.47"}
```

### `help`

Lists the supported command strings.

```json
{"t":"help","commands":["help","status","aps","clients","skips","pcap","pause","resume","hop","lock <ch>","target <index>","raw <index>","boost on|off","boost broadcast on|off","clear","selftest","demo hs|pmkid|happy|sleep","reboot"]}
```

### `ap`

Emitted when a new AP enters the table. The table holds up to 64 APs; the
oldest entry is replaced when it is full.

```json
{"t":"ap","new":1,"ssid":"ExampleNet","bssid":"aa:bb:cc:dd:ee:ff","ch":6,"rssi":-48,"enc":"WPA2","pmf":".","skip":0}
```

`enc` is one of `OPEN`, `WEP`, `WPA`, `WPA2`, `WPA2/3`, `WPA3`, `EAP`, or
`?`. `pmf` is `R` when PMF is required, `C` when capable, and `.` otherwise.
`skip` is 1 when the SSID is in the skip list. Skipped APs stay in the table
but are never selected or boosted.

### `eapol`

Emitted for each EAPOL-Key frame that belongs to a pairwise handshake.

```json
{"t":"eapol","ap":"aa:bb:cc:dd:ee:ff","sta":"11:22:33:44:55:66","msg":2}
```

`msg` is 1, 2, 3, or 4.

### `hs`

Emitted when a 4-way handshake is detected, meaning M1+M2 or M2+M3 have been
seen for the same AP and station pair.

```json
{"t":"hs","ap":"aa:bb:cc:dd:ee:ff","ssid":"ExampleNet","ch":6,"count":3}
```

`count` is the number of handshakes detected since boot or the last `clear`.

### `pmkid`

Emitted when an M1 frame carries a PMKID key data element, or when an
association request carries a PMKID in its RSN IE. `src` is `m1` or `assoc`.

```json
{"t":"pmkid","ap":"aa:bb:cc:dd:ee:ff","ssid":"ExampleNet","pmkid":"00112233445566778899aabbccddeeff","count":1,"src":"m1"}
```

### `client`

Emitted when a new client enters the client table. Updates do not emit an
event; use `clients` to read the current table.

```json
{"t":"client","new":1,"mac":"11:22:33:44:55:66","ap":"aa:bb:cc:dd:ee:ff","ch":6,"rssi":-55}
```

### `deauth`

Emitted when a targeted burst starts waiting or completes. `frames` is the
burst size. `burst` is the number of completed bursts since boost was armed.

```json
{"t":"deauth","state":"waiting_client","ap":"aa:bb:cc:dd:ee:ff"}
{"t":"deauth","ap":"aa:bb:cc:dd:ee:ff","client":"11:22:33:44:55:66","frames":3,"burst":1}
```

### `stat`

Emitted every 2 seconds, and in reply to `status`.

```json
{"t":"stat","ms":12345,"aps":23,"hs":3,"saved":2,"pmkid":1,"saved_pmkid":1,"eapol":17,"targets":20,"skips":1,"clients":4,"active":2,"ch":6,"sd":1,"pcap":12288,"drops":0,"client_drops":0,"paused":0,"lock":0,"boost":0,"boost_bcast":0,"target":"aa:bb:cc:dd:ee:ff","target_ch":6,"deauth":0,"bursts":0}
```

| Field | Meaning |
| --- | --- |
| `ms` | Uptime in milliseconds. |
| `aps` | APs in the table. |
| `hs` | Handshakes detected this boot. |
| `saved` | Handshakes confirmed written to the current PCAP. |
| `pmkid` | PMKIDs detected this boot. |
| `saved_pmkid` | PMKIDs confirmed written to the current PCAP. |
| `eapol` | EAPOL frames processed. |
| `targets` | Non-skipped APs with WPA/WPA2/WPA2-3 security. |
| `skips` | APs in the table whose SSID is in the skip list. |
| `clients` | Clients in the table. |
| `active` | Clients seen in the last 5 seconds. |
| `ch` | Current channel. |
| `sd` | 1 if the SD card and PCAP are open. |
| `pcap` | Current PCAP size in bytes. |
| `drops` | Packets dropped because the queue was full. |
| `client_drops` | Client observations dropped because the client queue was full. |
| `paused` | 1 while paused. |
| `lock` | 1 while channel lock is active. |
| `boost` | 1 while boost mode is active. |
| `boost_bcast` | 1 when boost uses legacy broadcast mode. |
| `target` | Target BSSID, or an empty string. |
| `target_ch` | Target channel. |
| `deauth` | Deauth frames sent. |
| `bursts` | Targeted deauth bursts completed. |

### `sd`

Emitted when the SD card mounts successfully and the PCAP opens.

```json
{"t":"sd","ok":1,"pcap":24}
```

### `pcap`

Reply to the `pcap` command.

```json
{"t":"pcap","path":"/pwn_001.pcap","size":12288,"open":1,"sd":1}
```

### `target`

Reply to a successful `target` command.

```json
{"t":"target","ssid":"ExampleNet","bssid":"aa:bb:cc:dd:ee:ff","ch":6,"enc":"WPA2","pmf":".","skip":0}
```

### `mode`

Emitted when channel lock changes.

```json
{"t":"mode","lock":1,"ch":6,"ssid":"ExampleNet","bssid":"aa:bb:cc:dd:ee:ff"}
```

The `ssid` and `bssid` fields are present when locking to the strongest AP.

### `boost`

Emitted when boost mode changes. `mode` is `client` or `broadcast`. `reason`
is present when boost stops, for example `captured`, `off`, `max_bursts`,
`tx_failed`, `target_blocked`, or `target_changed`.

```json
{"t":"boost","on":1,"mode":"client","target":"aa:bb:cc:dd:ee:ff","ch":6}
{"t":"boost","on":0,"mode":"client","reason":"captured"}
```

### `state`

Emitted when pause state changes.

```json
{"t":"state","paused":1}
```

### `clear`

```json
{"t":"clear","ok":1}
```

### `selftest`

```json
{"t":"selftest","ok":1,"stored":0,"valid":1,"mismatch":1,"pmkid":1,"m2m3":1,"skip":1,"assoc_pmkid":1,"pmf":1}
```

`valid`, `mismatch`, `pmkid`, `m2m3`, `skip`, `assoc_pmkid`, and `pmf` show
which synthetic parser cases passed. `ok` is 1 only when all of them passed.

### `demo`

```json
{"t":"demo","mood":"love"}
```

### `face`

Emitted when the display initializes.

```json
{"t":"face","ok":1,"layout":"pwnagotchi-landscape"}
```

### `sniffer`

Emitted when the WiFi sniffer initializes.

```json
{"t":"sniffer","ok":1}
```

### `rawwait`, `raw`, `parsedbg`

Debug events for the `raw <index>` command. `rawwait` is emitted immediately.
The next beacon or probe response from that BSSID produces `raw` with up to
160 bytes of hex, and `parsedbg` with the parsed SSID and IE walker result.

```json
{"t":"rawwait","bssid":"aa:bb:cc:dd:ee:ff"}
{"t":"raw","bssid":"aa:bb:cc:dd:ee:ff","len":180,"hex":"80000000..."}
{"t":"parsedbg","inLen":8,"inSsid":"ExampleNet","storedLen":8,"stored":"ExampleNet","hidden":0,"ies":12,"b36":"00","b37":"0c","b38":"45","end":180,"trunc":0}
```

### `reboot`

```json
{"t":"reboot"}
```

### `error` and `warn`

Errors are emitted for unknown commands, bad indexes, invalid channels, and
deauth transmit failures. Warnings are advisory.

```json
{"t":"error","msg":"bad AP index"}
{"t":"error","msg":"deauth tx failed","code":-1}
{"t":"error","msg":"AP is in the skip list"}
{"t":"error","msg":"target requires PMF; deauth would be ignored"}
{"t":"warn","msg":"target is not WPA/WPA2-PSK; no PSK handshake to capture"}
```

## Plain text `aps` table

`aps` prints a header and one line per AP. It is not JSON.

```text
#   SSID                             BSSID             CH  dBm ENC     PMF SKIP HS PMK
0   ExampleNet                       aa:bb:cc:dd:ee:ff  6  -48 WPA2    .   .    Y  .
1   PrivateNet                         11:22:33:44:55:66 11  -71 WPA2    .   Y    .  .
```

`PMF` is `R` when PMF is required, `C` when capable, and `.` otherwise.
`SKIP` is `Y` when the SSID is in the skip list. `HS` is `Y` when a handshake
was seen for that AP. `PMK` is `Y` when a PMKID was seen.

## Plain text `clients` table

`clients` prints a header and one line per learned client.

```text
#   CLIENT            AP                CH  dBm   AGE   OBS FLAGS
0   11:22:33:44:55:66 aa:bb:cc:dd:ee:ff  6  -55    2s    14 DA
```

`AGE` is seconds since the last observation. `OBS` is the observation count.
`FLAGS` is `D` for data frames and `A` for association requests.

## Plain text `skips` list

`skips` prints the compiled-in SSID skip list.

```text
SKIP 1
PrivateNet
```

## Host tool

```sh
python3 -m venv .venv
.venv/bin/pip install -r host/requirements.txt
.venv/bin/python host/pwnagotchi.py
```

Send commands at startup with `--cmd`, limit the session with `--duration`,
and convert a captured PCAP with `--crack`.

```sh
.venv/bin/python host/pwnagotchi.py --cmd aps --duration 3
.venv/bin/python host/pwnagotchi.py --cmd clients --duration 3
.venv/bin/python host/pwnagotchi.py --cmd "target 4" --cmd "boost on"
.venv/bin/python host/pwnagotchi.py --crack /Volumes/CARD/pwn_001.pcap -w rockyou.txt
```
