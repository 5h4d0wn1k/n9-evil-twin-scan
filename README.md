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
# Basic scan
python3 evil_twin_scan.py --interface wlan0

# Enable monitor mode before scanning
sudo python3 evil_twin_scan.py --interface wlan0 --monitor
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N9 — Evil Twin Scanner            ║
╚═══════════════════════════════════════╝
Interface: wlan0

=======================================================
  SSID                     BSSID               CH   SIG
=======================================================
  HomeNetwork              AA:BB:CC:DD:EE:01    6   -42
  HomeNetwork              AA:BB:CC:DD:EE:02    6   -45
  CoffeeShop              11:22:33:44:55:01    1   -55

[!] POTENTIAL EVIL TWINS DETECTED: 1

  SSID: HomeNetwork (Risk: HIGH)
  APs with same SSID: 2
  Indicators:
    - 2 different BSSIDs
    - same channel (possible clone)
    - multiple strong signals (co-located?)

[*] Total APs scanned: 3
```

## Legal Disclaimer

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
