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
from collections import defaultdict


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


def main():
    parser = argparse.ArgumentParser(
        description='N9 — WiFi Evil Twin Scanner')
    parser.add_argument('--interface', '-i', default='wlan0',
                        help='Wireless interface (default: wlan0)')
    parser.add_argument('--monitor', action='store_true',
                        help='Enable monitor mode before scan')
    parser.add_argument('--channels', help='Channel list to hop (e.g. 1,6,11)')

    args = parser.parse_args()
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


if __name__ == '__main__':
    main()
