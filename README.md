# N9 — WiFi Evil Twin Scanner

Scan for rogue access points, detect duplicate SSIDs, and analyze signal patterns.

## Overview

This project is a Python companion for WiFi evil twin detection that:
- Scans nearby APs using iwlist or iw commands
- Detects potential evil twin APs via duplicate SSID analysis
- Identifies suspicious signal patterns (same channel, mixed encryption)
- Reports risk levels based on multiple indicators
- Supports monitor mode toggling

## Features

- **Dual scan engine**: Uses both iw and iwlist for compatibility
- **Evil twin detection**: Identifies SSIDs served by multiple BSSIDs
- **Signal analysis**: Measures signal range and consistency
- **Encryption comparison**: Detects mixed open/closed variants
- **Channel analysis**: Flags same-channel duplicates
- **Monitor mode**: Optional monitor mode management

## Installation

No external dependencies — uses only the Python standard library + system tools (iw, iwlist).

```bash
# Ensure wireless tools are available
sudo apt install iw wireless-tools
```

## Usage

```bash
# Offline 802.11 beacon-fixture harness (default, no privileges):
# parses genuine beacon bytes and flags duplicate SSIDs from different BSSIDs
python3 evil_twin_scan.py --harness

# Live scan on a real lab wireless interface (needs a monitor-capable NIC)
sudo python3 evil_twin_scan.py --interface lab-wlan0 --live

# Enable monitor mode before a live scan
sudo python3 evil_twin_scan.py --interface lab-wlan0 --live --monitor
```

The default (`--harness`) runs a fully unprivileged offline harness: it
hand-constructs genuine 802.11 beacon frames (two BSSIDs sharing one SSID,
plus a distinct single-BSSID AP), parses them through the real pure-Python
beacon parser, and asserts the duplicate-SSID twin is flagged high-risk while
the single-BSSID AP is not. Live scanning is gated behind `--live`.

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (00:11:22:33:44:55).

1. In a controlled lab, stand up **two access points broadcasting the same**
   SSID (e.g. `lab-public-wifi`) from different BSSIDs on the same channel.
2. Give monitor mode a try on the lab NIC, then run
   `sudo python3 evil_twin_scan.py --interface lab-wlan0 --live --monitor`.
3. Confirm both APs appear and the duplicate SSID is flagged as
   `POTENTIAL EVIL TWIN` / `HIGH` risk.
4. Bring down one AP and re-scan: the twin report should clear (single BSSID).
5. Confirm a distinct SSID served by one AP is never reported as a twin.

## Metrics

Deterministic, unprivileged, offline fixture harness:

- `python3 -m unittest discover -s tests` — 9 unit tests (exit 0)
- Beacon parser: BSSID, SSID, channel extracted from real wire-format bytes
- Non-beacon and truncated frames rejected
- Duplicate SSID across two BSSIDs -> flagged HIGH risk
- Single-BSSID SSID -> not flagged (no false positive)
- Harness exit code: `0` on success, `1` on failure

## License

MIT

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
