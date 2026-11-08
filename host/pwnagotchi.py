#!/usr/bin/env python3
"""Host companion for esp32-pwnagotchi.

Live event viewer and small cracking helper. The firmware writes the capture
to the microSD card; mount the card and pass the PCAP to --crack.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    print("pyserial is required: python3 -m pip install pyserial", file=sys.stderr)
    raise SystemExit(1)


VID_ESPRESSIF = 0x303A


def find_port() -> str:
    for p in list_ports.comports():
        if p.vid == VID_ESPRESSIF:
            return p.device
    raise SystemExit("No Espressif USB serial port found. Use --port.")


def open_serial(port: str) -> serial.Serial:
    s = serial.Serial()
    s.port = port
    s.baudrate = 115200
    s.timeout = 0.2
    s.dsrdtr = False
    s.rtscts = False
    s.open()
    # pyserial asserts DTR/RTS on open on macOS; drop them immediately so a
    # reconnect does not hold the board in reset.
    try:
        s.dtr = False
        s.rts = False
    except OSError:
        pass
    # Opening the native USB CDC port resets the C6 on macOS. Give it time to
    # boot before sending commands; the boot log is left in the stream and the
    # event loop prints it.
    time.sleep(3.0)
    return s


def print_event(line: str) -> None:
    if not line.startswith("{"):
        print(line)
        return

    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        print(line)
        return

    t = e.get("t")
    if t == "ap":
        if e.get("new"):
            flags = ""
            if e.get("skip"):
                flags += " SKIP"
            if e.get("pmf") == "R":
                flags += " PMF-R"
            elif e.get("pmf") == "C":
                flags += " PMF-C"
            print(f"+ AP  {e.get('ssid',''):<32} {e.get('bssid','')}  "
                  f"ch {e.get('ch'):>2}  {e.get('rssi'):>4} dBm  "
                  f"{e.get('enc','')}{flags}")
    elif t == "eapol":
        print(f"  EAPOL {e.get('ap')} <- {e.get('sta')}  msg {e.get('msg')}")
    elif t == "hs":
        print("\n  *** HANDSHAKE ***  "
              f"{e.get('ssid','')}  {e.get('ap','')}  ch {e.get('ch')}  "
              f"(total {e.get('count')})\n")
    elif t == "pmkid":
        src = e.get("src", "m1")
        print("\n  *** PMKID ***  "
              f"{e.get('ssid','')}  {e.get('ap','')}  {e.get('pmkid','')}  "
              f"({src}, total {e.get('count')})\n")
    elif t == "client":
        if e.get("new"):
            print(f"+ CLIENT {e.get('mac')} -> {e.get('ap')}  "
                  f"ch {e.get('ch'):>2}  {e.get('rssi'):>4} dBm")
    elif t == "deauth":
        if e.get("state") == "waiting_client":
            print(f"  deauth waiting for a client on {e.get('ap')}")
        else:
            print(f"  deauth {e.get('client')} via {e.get('ap')}  "
                  f"{e.get('frames')} frames  burst {e.get('burst')}")
    elif t == "boost":
        print(f"boost {e.get('on')}  {e.get('mode','')}  {e.get('reason','')}")
    elif t == "stat":
        sd = "SD" if e.get("sd") else "--"
        mode = "BOOST" if e.get("boost") else ("LOCK" if e.get("lock") else "HOP")
        print(f"[AP {e.get('aps'):>3}] [CL {e.get('active',0)}/{e.get('clients',0)}] "
              f"[HS {e.get('hs'):>2}] [SAVED {e.get('saved',0):>2}] "
              f"[PMKID {e.get('pmkid'):>2}] [TGT {e.get('targets'):>2}] "
              f"[ch {e.get('ch'):>2} {mode}] [{sd}] "
              f"[pcap {e.get('pcap',0)} B] [drop {e.get('drops',0)}]")
    elif t in {"error", "warn"}:
        print(f"! {e.get('msg')}", file=sys.stderr)
    elif t == "selftest":
        print(f"self-test: ok={e.get('ok')} valid={e.get('valid')} "
              f"mismatch={e.get('mismatch')} pmkid={e.get('pmkid')} "
              f"m2m3={e.get('m2m3')} skip={e.get('skip')} "
              f"assoc_pmkid={e.get('assoc_pmkid')} pmf={e.get('pmf')}")
    elif t in {"sd", "pcap", "target", "mode", "state", "clear", "face", "sniffer", "demo", "skip"}:
        print(json.dumps(e, separators=(",", ":")))
    # ignore periodic noise unless it is a table or an unknown event


def run(cmd: list[str]) -> int:
    print("$", " ".join(cmd))
    return subprocess.call(cmd)


def crack(pcap: str, wordlist: str) -> int:
    if not os.path.exists(pcap):
        print(f"PCAP not found: {pcap}", file=sys.stderr)
        return 1
    if not shutil.which("hcxpcapngtool"):
        print("hcxpcapngtool not found: brew install hcxtools", file=sys.stderr)
        return 1
    if not shutil.which("hashcat"):
        print("hashcat not found: brew install hashcat", file=sys.stderr)
        return 1

    out = os.path.join(tempfile.mkdtemp(prefix="pwnagotchi-"), "capture.22000")
    rc = run(["hcxpcapngtool", "-o", out, pcap])
    if rc != 0:
        return rc
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        print("No WPA2 handshake or PMKID was found in this PCAP.")
        return 2

    with open(out, "rb") as f:
        lines = sum(1 for _ in f)
    print(f"{lines} hash line(s) -> {out}")
    rc = run(["hashcat", "-m", "22000", out, wordlist])
    print(f"\nHash file kept at: {out}")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="esp32-pwnagotchi host tool")
    ap.add_argument("--port", help="serial port (auto-detects Espressif USB)")
    ap.add_argument("--cmd", action="append", default=[], help="command to send at start")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds")
    ap.add_argument("--crack", metavar="PCAP", help="convert a PCAP and run hashcat")
    ap.add_argument("-w", "--wordlist", default="rockyou.txt", help="wordlist for --crack")
    args = ap.parse_args()

    if args.crack:
        return crack(args.crack, args.wordlist)

    port = args.port or find_port()
    ser = open_serial(port)
    print(f"connected to {port}  (ctrl-c to quit)")

    for c in args.cmd:
        ser.write((c + "\n").encode())
        time.sleep(0.15)

    start = time.time()
    try:
        while True:
            raw = ser.readline()
            if raw:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    print_event(line)
            if args.duration and time.time() - start >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            ser.dtr = False
            ser.rts = False
        except OSError:
            pass
        ser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
