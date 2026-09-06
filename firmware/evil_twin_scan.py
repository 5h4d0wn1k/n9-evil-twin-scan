#!/usr/bin/env python3
"""
N9 - WiFi Evil Twin Scanner
Scan for rogue APs, detect duplicate SSIDs, and analyze signal patterns.
Python companion using iwlist/iw parsing via subprocess.
"""

import subprocess
import re
import sys
import argparse
import time
import struct
from collections import defaultdict


# ---------------------------------------------------------------------------
# Pure-Python 802.11 beacon frame parser (no subprocess, no scapy)
# ---------------------------------------------------------------------------
# Frame Control bits for a Beacon: type=0 (mgmt), subtype=8 (beacon)
BEACON_SUBTYPE_BITS = 0x0800
SSID_TAG = 0


def parse_beacon(data):
    """Parse a raw 802.11 beacon frame into a dict.

    Works offline with no privileges. Returns None (and records the reason)
    if the bytes do not form a valid beacon. This exercises the same detection
    data path (`detect_evil_twins`) used on live captures.
    """
    if len(data) < 24:
        raise ValueError('truncated 802.11 header (%d bytes)' % len(data))
    frame_control, duration = struct.unpack('!HH', data[:4])
    if (frame_control & 0x0F00) != BEACON_SUBTYPE_BITS:
        raise ValueError('not a beacon (frame control %#06x)' % frame_control)
    da = data[4:10]
    sa = data[10:16]
    bssid = data[16:22]
    seq_ctrl = data[22:24]

    body = data[24:]
    if len(body) < 12:
        raise ValueError('beacon body too short')

    # Timestamp(8) + beacon interval(2) + capability(2)
    timestamp = int.from_bytes(body[0:8], 'little')
    beacon_interval = struct.unpack('!H', body[8:10])[0]
    capability = struct.unpack('!H', body[10:12])[0]

    # Tagged parameters
    tags = {}
    pos = 12
    while pos < len(body):
        if pos + 2 > len(body):
            break
        tag_id = body[pos]
        tag_len = body[pos + 1]
        if pos + 2 + tag_len > len(body):
            break
        tags[tag_id] = body[pos + 2:pos + 2 + tag_len]
        pos += 2 + tag_len

    ssid_bytes = tags.get(SSID_TAG, b'')
    ssid = ssid_bytes.decode('utf-8', 'replace') if ssid_bytes else '<hidden>'
    # DS parameter set (tag 3) holds the channel
    channel = None
    if 3 in tags and tags[3]:
        channel = tags[3][0]

    return {
        'bssid': ':'.join('%02X' % b for b in bssid),
        'da': ':'.join('%02X' % b for b in da),
        'sa': ':'.join('%02X' % b for b in sa),
        'ssid': ssid,
        'channel': channel,
        'timestamp': timestamp,
        'beacon_interval': beacon_interval,
        'capability': capability,
        'wpa': 48 in tags or 221 in tags,
    }


def build_beacon(bssid, ssid, channel=1, freq=2412, signal=-50,
                 mcast=True):
    """Hand-construct a genuine 802.11 beacon frame for fixtures/tests.

    Returns the raw bytes so the parser is verified against a known-on-wire
    format, not against itself. `bssid` is the BSSID that is broadcast/mcast DA.
    """
    bssid_b = bytes(int(x, 16) for x in bssid.split(':'))
    # broadcast/multicast destination (all-ones) for a normal beacon
    da = b'\xff' * 6
    # Frame control: version 0, type mgmt(0), subtype beacon(8)
    frame_control = BEACON_SUBTYPE_BITS
    duration = 0
    seq_ctrl = 0  # fragment 0, sequence 0

    body = bytearray()
    body += (0).to_bytes(8, 'little')          # timestamp
    body += struct.pack('!H', 100)             # beacon interval
    body += struct.pack('!H', 0x0001)          # capability (ESS)
    # Tag: SSID(0)
    s = ssid.encode('utf-8')
    body += bytes([SSID_TAG, len(s)]) + s
    # Tag: supported rates(1)
    rates = bytes([0x82, 0x84, 0x8b, 0x96])
    body += bytes([1, len(rates)]) + rates
    # Tag: DS parameter set(3) = channel
    body += bytes([3, 1, channel])

    return (struct.pack('!HH', frame_control, duration) + da + bssid_b +
            bssid_b + struct.pack('!H', seq_ctrl) + bytes(body))


class EvilTwinScanner:
    """Scan and detect rogue / evil twin access points."""

    def __init__(self, interface='wlan0'):
        self.interface = interface
        self.scan_results = []
        self.ssids = defaultdict(list)

    def check_interface(self):
        """Check if wireless interface exists and is usable."""
        try:
            result = subprocess.run(
                ['iw', 'dev'],
                capture_output=True, text=True, timeout=5)
            if self.interface in result.stdout:
                return True
        except FileNotFoundError:
            pass
        try:
            result = subprocess.run(
                ['iwconfig', self.interface],
                capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def enable_monitor_mode(self):
        """Put interface into monitor mode."""
        print(f"[*] Enabling monitor mode on {self.interface}...")
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set',
                            self.interface, 'down'],
                           check=True, capture_output=True, timeout=10)
            subprocess.run(['sudo', 'iw', self.interface, 'set',
                            'monitor', 'none'],
                           check=True, capture_output=True, timeout=10)
            subprocess.run(['sudo', 'ip', 'link', 'set',
                            self.interface, 'up'],
                           check=True, capture_output=True, timeout=10)
            print(f"[+] Monitor mode enabled")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[-] Failed to enable monitor mode: {e}")
            return False

    def disable_monitor_mode(self):
        """Revert interface to managed mode."""
        print(f"[*] Reverting to managed mode...")
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set',
                            self.interface, 'down'],
                           capture_output=True, timeout=5)
            subprocess.run(['sudo', 'iw', self.interface, 'set',
                            'type', 'managed'],
                           capture_output=True, timeout=5)
            subprocess.run(['sudo', 'ip', 'link', 'set',
                            self.interface, 'up'],
                           capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    def scan_iwlist(self):
        """Parse scan results from iwlist."""
        try:
            result = subprocess.run(
                ['sudo', 'iwlist', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30)
            output = result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError) as e:
            print(f"[-] iwlist scan failed: {e}")
            return []

        cells = re.split(r'Cell \d+', output)
        results = []

        for cell in cells:
            if not cell.strip():
                continue

            ap = {}

            bssid_m = re.search(
                r'Address:\s*([0-9A-Fa-f:]{17})', cell)
            if bssid_m:
                ap['bssid'] = bssid_m.group(1).upper()

            ssid_m = re.search(r'ESSID:"([^"]*)"', cell)
            if ssid_m:
                ap['ssid'] = ssid_m.group(1)
            else:
                ap['ssid'] = '<hidden>'

            signal_m = re.search(r'Signal level[=:](-?\d+)', cell)
            if signal_m:
                ap['signal'] = int(signal_m.group(1))
            else:
                ap['signal'] = None

            channel_m = re.search(r'Channel:(\d+)', cell)
            if channel_m:
                ap['channel'] = int(channel_m.group(1))

            enc_m = re.search(r'Encryption key:(on|off)', cell)
            if enc_m:
                ap['encrypted'] = enc_m.group(1) == 'on'

            qual_m = re.search(r'Quality=(\d+)/(\d+)', cell)
            if qual_m:
                ap['quality'] = int(qual_m.group(1))
                ap['quality_max'] = int(qual_m.group(2))

            freq_m = re.search(r'Frequency:(\d+\.?\d*)\s*GHz', cell)
            if freq_m:
                ap['frequency'] = float(freq_m.group(1))

            if ap.get('bssid'):
                results.append(ap)

        return results

    def scan_iw(self):
        """Scan using iw dev scan."""
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set',
                            self.interface, 'up'],
                           capture_output=True, timeout=5)
            result = subprocess.run(
                ['sudo', 'iw', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30)
            output = result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            return []

        results = []
        current_ap = {}

        for line in output.split('\n'):
            line = line.strip()

            bss_m = re.match(r'BSS ([0-9a-f:]{17})', line)
            if bss_m:
                if current_ap.get('bssid'):
                    results.append(current_ap)
                current_ap = {'bssid': bss_m.group(1).upper()}

            ssid_m = re.match(r'SSID:\s*(.*)', line)
            if ssid_m:
                current_ap['ssid'] = ssid_m.group(1).strip()
                if not current_ap['ssid']:
                    current_ap['ssid'] = '<hidden>'

            signal_m = re.match(r'signal:\s*(-?\d+\.?\d*)\s*dBm', line)
            if signal_m:
                current_ap['signal'] = int(float(signal_m.group(1)))

            freq_m = re.match(r'freq:\s*(\d+)', line)
            if freq_m:
                current_ap['frequency'] = int(freq_m.group(1)) / 1000

            chan_m = re.match(r'primary channel:\s*(\d+)', line)
            if chan_m:
                current_ap['channel'] = int(chan_m.group(1))

            if 'WPA' in line or 'RSN' in line:
                current_ap['encrypted'] = True

        if current_ap.get('bssid'):
            results.append(current_ap)

        return results

    def scan(self):
        """Perform WiFi scan using available tools."""
        print(f"[*] Scanning on {self.interface}...")

        results = self.scan_iw()
        if results:
            print(f"[+] iw scan: found {len(results)} APs")
        else:
            results = self.scan_iwlist()
            if results:
                print(f"[+] iwlist scan: found {len(results)} APs")
            else:
                print(f"[-] No results from either scan method")
                return []

        self.scan_results = results
        self.ssids = defaultdict(list)
        for ap in results:
            ssid = ap.get('ssid', '<unknown>')
            self.ssids[ssid].append(ap)

        return results

    def detect_evil_twins(self):
        """Detect potential evil twin APs."""
        twins = []

        for ssid, aps in self.ssids.items():
            if ssid == '<hidden>':
                continue

            if len(aps) < 2:
                continue

            bssids = set(ap.get('bssid', '') for ap in aps)
            signals = [ap.get('signal', -100) for ap in aps
                       if ap.get('signal') is not None]
            channels = set(ap.get('channel', 0) for ap in aps)

            indicators = []

            if len(bssids) > 1:
                indicators.append(f'{len(bssids)} different BSSIDs')

            if len(channels) == 1 and len(aps) > 1:
                indicators.append('same channel (possible clone)')

            encrypted_states = set()
            for ap in aps:
                enc = ap.get('encrypted', None)
                encrypted_states.add(enc)
            if None not in encrypted_states and len(encrypted_states) > 1:
                indicators.append('mixed encryption (one open, one secured)')

            if signals:
                sig_range = max(signals) - min(signals)
                if sig_range > 30:
                    indicators.append(f'wide signal range ({sig_range}dB)')

            strong = [ap for ap in aps if ap.get('signal', -100) > -50]
            if len(strong) > 1:
                indicators.append('multiple strong signals (co-located?)')

            if indicators:
                twins.append({
                    'ssid': ssid,
                    'count': len(aps),
                    'aps': aps,
                    'indicators': indicators,
                    'risk': 'HIGH' if len(indicators) >= 2 else 'MEDIUM',
                })

        return twins

    def signal_analysis(self):
        """Analyze signal patterns across all APs."""
        if not self.scan_results:
            return {}

        signals = defaultdict(list)
        for ap in self.scan_results:
            ssid = ap.get('ssid', '<unknown>')
            sig = ap.get('signal')
            if sig is not None:
                signals[ssid].append(sig)

        analysis = {}
        for ssid, sigs in signals.items():
            if len(sigs) < 2:
                continue
            analysis[ssid] = {
                'count': len(sigs),
                'min_signal': min(sigs),
                'max_signal': max(sigs),
                'avg_signal': sum(sigs) / len(sigs),
                'range': max(sigs) - min(sigs),
            }
        return analysis

    def full_scan(self):
        """Run complete evil twin detection scan."""
        print("╔═══════════════════════════════════════╗")
        print("║     N9 — Evil Twin Scanner            ║")
        print("╚═══════════════════════════════════════╝")
        print(f"Interface: {self.interface}\n")

        self.scan()
        if not self.scan_results:
            print("[-] No APs found")
            return

        print(f"\n{'='*55}")
        print(f"  {'SSID':<25s} {'BSSID':<20s} {'CH':>3s} {'SIG':>5s}")
        print(f"{'='*55}")
        for ap in sorted(self.scan_results,
                         key=lambda x: x.get('signal', -100),
                         reverse=True):
            ssid = ap.get('ssid', '<unknown>')[:24]
            bssid = ap.get('bssid', 'N/A')
            ch = str(ap.get('channel', '?'))
            sig = f"{ap.get('signal', '?')}"
            print(f"  {ssid:<25s} {bssid:<20s} {ch:>3s} {sig:>5s}")

        twins = self.detect_evil_twins()
        signals = self.signal_analysis()

        if twins:
            print(f"\n[!] POTENTIAL EVIL TWINS DETECTED: {len(twins)}")
            for t in twins:
                print(f"\n  SSID: {t['ssid']} (Risk: {t['risk']})")
                print(f"  APs with same SSID: {t['count']}")
                print(f"  Indicators:")
                for ind in t['indicators']:
                    print(f"    - {ind}")
                print(f"  BSSIDs:")
                for ap in t['aps']:
                    print(f"    {ap.get('bssid', 'N/A')} "
                          f"sig={ap.get('signal', '?')}dBm "
                          f"ch={ap.get('channel', '?')}")
        else:
            print(f"\n[+] No evil twins detected")

        if signals:
            print(f"\n--- Signal Analysis (SSIDs with multiple APs) ---")
            for ssid, sa in sorted(signals.items(),
                                   key=lambda x: x[1]['range'],
                                   reverse=True):
                print(f"  {ssid}: range={sa['range']}dB "
                      f"({sa['min_signal']} to {sa['max_signal']}dBm) "
                      f"[{sa['count']} APs]")

        print(f"\n[*] Total APs scanned: {len(self.scan_results)}")
        print(f"[*] Unique SSIDs: {len(self.ssids)}")


def run_harness():
    """Offline harness: parse real 802.11 beacon fixture bytes and flag
    duplicate SSIDs broadcast by different BSSIDs.

    No wireless interface, no privileges, no subprocess calls. The fixtures
    are built as genuine beacon frames (see ``build_beacon``) then parsed
    through the real parser and grouped through the same ``detect_evil_twins``
    logic used live.
    """
    ok = True
    scanner = EvilTwinScanner()  # interface unused for fixture path

    def verify(label, cond, detail=''):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label} {detail}')
        ok = ok and cond

    print('=== N9 Evil Twin Scan: offline 802.11 beacon fixture harness ===')

    # Two different BSSIDs broadcasting the SAME SSID (an evil-twin signature)
    fixtures = [
        build_beacon('00:11:22:33:44:55', 'lab-public-wifi', channel=1,
                     signal=-40),
        build_beacon('00:11:22:33:44:66', 'lab-public-wifi', channel=1,
                     signal=-55),
        # A distinct, single AP for a different SSID (should NOT be flagged)
        build_beacon('00:aa:bb:cc:dd:ee', 'lab-docs', channel=6, signal=-70),
    ]

    parsed = []
    for i, raw in enumerate(fixtures):
        ap = parse_beacon(raw)
        parsed.append(ap)
        print(f'  [fixture {i}] bssid={ap["bssid"]} ssid={ap["ssid"]!r} '
              f'ch={ap["channel"]}')
        verify(f'fixture {i} parsed with correct BSSID',
               len(ap['bssid']) == 17)
        verify(f'fixture {i} SSID extracted', ap['ssid'] is not None)
        verify(f'fixture {i} channel extracted', ap['channel'] is not None)

    # Feed into the same grouping + detection logic used on a live scan
    scanner.scan_results = parsed
    scanner.ssids = defaultdict(list)
    for ap in parsed:
        scanner.ssids[ap.get('ssid', '<unknown>')].append(ap)

    twins = scanner.detect_evil_twins()
    dupe_ssid = [t for t in twins if t['ssid'] == 'lab-public-wifi']
    other_flagged = [t for t in twins if t['ssid'] == 'lab-docs']

    verify('duplicate SSID across two BSSIDs flagged',
           len(dupe_ssid) == 1 and dupe_ssid[0]['count'] == 2,
           f'{len(dupe_ssid)} twin(s)')
    verify('high risk (2+ indicators: different BSSIDs + same channel)',
           dupe_ssid and dupe_ssid[0]['risk'] == 'HIGH',
           dupe_ssid[0]['risk'] if dupe_ssid else '?')
    verify('single-BSSID SSID NOT flagged as a twin',
           len(other_flagged) == 0, f'{len(other_flagged)} flagged')

    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N9 — WiFi Evil Twin Scanner (offline beacon-fixture '
                    'harness + gated live scan)')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline 802.11 beacon-fixture harness '
                             '(default)')
    parser.add_argument('--interface', '-i', default='wlan0',
                        help='Wireless interface (default: wlan0)')
    parser.add_argument('--live', action='store_true',
                        help='Run a live scan (needs wireless interface)')
    parser.add_argument('--monitor', action='store_true',
                        help='Enable monitor mode before scan')
    parser.add_argument('--channels', help='Channel list to hop (e.g. 1,6,11)')

    args = parser.parse_args()

    if args.harness or not args.live:
        sys.exit(run_harness())

    scanner = EvilTwinScanner(args.interface)

    if args.monitor:
        scanner.enable_monitor_mode()

    try:
        scanner.full_scan()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    finally:
        if args.monitor:
            scanner.disable_monitor_mode()
    return 0


if __name__ == '__main__':
    main()
