#!/usr/bin/env python3
"""Offline unit tests for the N9 evil-twin scanner's 802.11 beacon parser.

Builds genuine beacon frames, parses them through the real parser, and asserts
the duplicate-SSID-from-different-BSSID detection. No wireless interface, no
subprocess, no privileges.
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from evil_twin_scan import (parse_beacon, build_beacon, EvilTwinScanner,  # noqa: E402
                            run_harness)


class TestBeaconParser(unittest.TestCase):
    def test_parse_valid_beacon(self):
        raw = build_beacon('00:11:22:33:44:55', 'lab-net', channel=5)
        ap = parse_beacon(raw)
        self.assertEqual(ap['bssid'], '00:11:22:33:44:55')
        self.assertEqual(ap['ssid'], 'lab-net')
        self.assertEqual(ap['channel'], 5)

    def test_parse_hidden_ssid(self):
        # empty SSID tag -> '<hidden>'
        raw = build_beacon('00:11:22:33:44:55', '', channel=1)
        ap = parse_beacon(raw)
        self.assertEqual(ap['ssid'], '<hidden>')

    def test_parse_different_channel(self):
        raw = build_beacon('00:aa:bb:cc:dd:ee', 'x', channel=11)
        self.assertEqual(parse_beacon(raw)['channel'], 11)

    def test_parse_rejects_non_beacon(self):
        # A probe-request-ish frame (subtype 4, not beacon)
        raw = bytearray(build_beacon('00:11:22:33:44:55', 'x'))
        raw[0] = (0x04)  # subtype 4 in low bits of FC
        with self.assertRaises(ValueError):
            parse_beacon(bytes(raw))

    def test_parse_rejects_truncated(self):
        with self.assertRaises(ValueError):
            parse_beacon(b'\x00' * 10)


class TestDuplicateSSIDDetection(unittest.TestCase):
    def test_two_bssids_same_ssid_flagged(self):
        scanner = EvilTwinScanner()
        ap1 = parse_beacon(build_beacon('00:11:22:33:44:55', 'lab-public-wifi',
                                        channel=1))
        ap2 = parse_beacon(build_beacon('00:11:22:33:44:66', 'lab-public-wifi',
                                        channel=1))
        scanner.scan_results = [ap1, ap2]
        scanner.ssids = {}
        from collections import defaultdict
        scanner.ssids = defaultdict(list)
        for ap in scanner.scan_results:
            scanner.ssids[ap['ssid']].append(ap)
        twins = scanner.detect_evil_twins()
        t = [x for x in twins if x['ssid'] == 'lab-public-wifi']
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0]['count'], 2)
        self.assertEqual(t[0]['risk'], 'HIGH')

    def test_single_bssid_not_flagged(self):
        scanner = EvilTwinScanner()
        ap = parse_beacon(build_beacon('00:11:22:33:44:55', 'only-ap'))
        scanner.scan_results = [ap]
        from collections import defaultdict
        scanner.ssids = defaultdict(list)
        for a in scanner.scan_results:
            scanner.ssids[a['ssid']].append(a)
        self.assertEqual(scanner.detect_evil_twins(), [])


class TestHarness(unittest.TestCase):
    def test_harness_passes(self):
        self.assertEqual(run_harness(), 0)

    def test_harness_cli_exit_zero(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'evil_twin_scan.py'), '--harness'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn('duplicate SSID across two BSSIDs', r.stdout)


if __name__ == '__main__':
    unittest.main()
