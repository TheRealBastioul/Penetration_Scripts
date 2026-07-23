#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Enumeration Tool
Fuzzes object IDs across endpoints to detect missing access control.
"""

import argparse
import requests
import sys
import csv
from urllib.parse import urljoin
from collections import defaultdict

def idor_scan(url_template, id_start, id_end, headers=None, cookie=None, 
              status_filter=None, keyword=None, output_file=None):

    if not headers:
        headers = {}
    if cookie:
        headers['Cookie'] = cookie
    
    baseline_length = None
    baseline_status = None
    results = []
    
    print(f"[*] Starting IDOR scan: {url_template} (IDs {id_start}-{id_end})")
    print(f"[*] Headers: {list(headers.keys())}")
    
    status_codes = defaultdict(int)
    lengths = defaultdict(int)
    
    for id_val in range(id_start, id_end + 1):
        url = url_template.replace("{ID}", str(id_val))
        
        try:
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            status_codes[r.status_code] += 1
            lengths[len(r.text)] += 1
            
            # Detect anomalies
            is_anomaly = False
            reason = ""
            
            # Baseline: first successful response
            if baseline_status is None and r.status_code == 200:
                baseline_status = r.status_code
                baseline_length = len(r.text)
                print(f"[+] Baseline set: Status {baseline_status}, Length {baseline_length}")
            
            # Check status code filter
            if status_filter and r.status_code not in [int(x) for x in status_filter.split(',')]:
                continue
            
            # Check for different status codes than baseline
            if baseline_status and r.status_code != baseline_status:
                is_anomaly = True
                reason = f"Status {r.status_code} (baseline: {baseline_status})"
            
            # Check for different content length (variance > 10%)
            if baseline_length and len(r.text) != baseline_length:
                variance = abs(len(r.text) - baseline_length) / baseline_length * 100
                if variance > 10:
                    is_anomaly = True
                    reason = f"Length {len(r.text)} bytes (baseline: {baseline_length}, variance: {variance:.1f}%)"
            
            # Check for keyword presence
            if keyword and keyword in r.text:
                is_anomaly = True
                reason = f"Contains keyword: '{keyword}'"
            
            # Log anomalies
            if is_anomaly:
                print(f"[!] ID {id_val}: {reason}")
                results.append({
                    'id': id_val,
                    'url': url,
                    'status': r.status_code,
                    'length': len(r.text),
                    'reason': reason
                })
        
        except requests.Timeout:
            print(f"[-] ID {id_val}: Timeout")
        except Exception as e:
            print(f"[-] ID {id_val}: {str(e)}")
    
    # Summary
    print(f"\n[*] Scan complete. Status codes: {dict(status_codes)}")
    print(f"[*] Anomalies detected: {len(results)}")
    
    # Write CSV output
    if output_file and results:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['id', 'url', 'status', 'length', 'reason'])
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Results saved to {output_file}")
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="IDOR enumeration tool: fuzz object IDs to detect missing access control"
    )
    parser.add_argument('-u', '--url', required=True,
                        help='URL template with {ID} placeholder, e.g., http://target.com/api/users/{ID}')
    parser.add_argument('-s', '--start', type=int, default=1,
                        help='Start ID (default: 1)')
    parser.add_argument('-e', '--end', type=int, default=100,
                        help='End ID (default: 100)')
    parser.add_argument('-H', '--header', action='append', dest='headers',
                        help='Custom header, format: "Name: Value" (can be used multiple times)')
    parser.add_argument('-c', '--cookie',
                        help='Cookie header value')
    parser.add_argument('-f', '--filter',
                        help='Only report status codes (comma-separated, e.g., "200,201")')
    parser.add_argument('-k', '--keyword',
                        help='Flag responses containing this keyword')
    parser.add_argument('-o', '--output',
                        help='Output CSV file')
    
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' not in h:
                print(f"[-] Invalid header format: {h}")
                sys.exit(1)
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
    
    # Run scan
    results = idor_scan(
        url_template=args.url,
        id_start=args.start,
        id_end=args.end,
        headers=headers,
        cookie=args.cookie,
        status_filter=args.filter,
        keyword=args.keyword,
        output_file=args.output
    )

if __name__ == '__main__':
    main()
