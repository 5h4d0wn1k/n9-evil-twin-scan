> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N9 — Wi-Fi Evil Twin / Rogue AP Scanner

Duplicate-SSID and rogue-access-point scanner that detects cloned SSIDs and
anomalous beacons for **Wi-Fi security** monitoring and **wireless
penetration-testing** labs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/n9-evil-twin-scan)](https://github.com/5h4d0wn1k/n9-evil-twin-scan)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/n9-evil-twin-scan)](https://github.com/5h4d0wn1k/n9-evil-twin-scan/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n9-evil-twin-scan)](https://github.com/5h4d0wn1k/n9-evil-twin-scan)

## Why

Evil-twin attacks work because Wi-Fi clients trust an SSID, not the access
point behind it: an attacker clones a legitimate network name onto their own
radio and lures victims into credential harvesting or MITM. Detecting that
requires identifying the same SSID broadcast by multiple BSSIDs, on the same
channel, with inconsistent encryption — signal-level anomalies a normal scan
misses. N9 is an offline-first scanner that hand-constructs genuine 802.11
beacon frames, parses them through a pure-Python beacon parser, and flags the
duplicate-SSID patterns that indicate an evil twin, while never raising false
positives on single-BSSID networks. Live scanning is gated behind `--live` for
authorized own-lab use with a monitor-capable NIC, keeping the tool inside the
scope of wireless security education and authorized testing.

## Features

- **Dual scan engine** — uses both `iw` and `iwlist` for device compatibility
- **Evil-twin detection** — flags SSIDs served by multiple BSSIDs (duplicate SSID)
- **Signal analysis** — measures signal range and consistency across beacons
- **Encryption comparison** — detects mixed open/closed variants of one SSID
- **Channel analysis** — flags same-channel duplicate BSSIDs
- **Monitor mode** — optional live monitor-mode management on a lab NIC
- **Offline harness** — unprivileged `--harness` demo with no radio privileges

## Quickstart

Python standard library + system wireless tools only — no third-party packages.

```bash
# Install wireless tools (Linux)
sudo apt install iw wireless-tools

# Offline, unprivileged, deterministic harness (default): parses beacon bytes,
# asserts the duplicate-SSID twin is HIGH risk and the single-BSSID AP is not.
python3 firmware/evil_twin_scan.py --harness

# Live scan on an authorized lab interface
sudo python3 firmware/evil_twin_scan.py --interface lab-wlan0 --live

# Live scan with monitor-mode toggle and channel hop list
sudo python3 firmware/evil_twin_scan.py --interface lab-wlan0 --live --monitor --channels 1,6,11

# Unit tests (9 cases)
python3 -m unittest discover -s tests
```

CLI options: `--harness`, `--interface/-i` (default `wlan0`), `--live`,
`--monitor`, `--channels`.

## Live lab plan

Stand up two access points broadcasting the same SSID (placeholders like
`lab-public-wifi`) from different BSSIDs on the same channel, then run the live
scan and confirm the duplicate SSID is reported as `POTENTIAL EVIL TWIN` /
`HIGH`. Bring one AP down, re-scan, and confirm the report clears. Test only
inside your own controlled lab.

## Project structure

- `firmware/evil_twin_scan.py` — scanner CLI, beacon parser, risk engine
- `tests/test_evil_twin_scan.py` — 9 unit tests

## Legal & authorized use

For **educational and authorized security testing purposes only**. The default
harness is fully unprivileged and offline; live scanning must be limited to
networks you own or hold written authorization to assess. See
[ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md)
before use.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).