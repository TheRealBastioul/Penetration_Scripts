# Penetration Scripts

Custom tools built for penetration testing and web application security. Each script targets a specific vulnerability class mapped to the OWASP Top 10:2025.

---

## OWASP Top 10:2025 Mapping

| Script | OWASP Top 10:2025 | Vulnerability Class |
|---|---|---|
| [JWTCreator](#jwtcreator) | A07 — Authentication Failures | JWT forgery, decoding, and alg=none signature bypass |
| [lsuck.py](#lsuckpy) | A05 — Injection | Blind LDAP injection, character by character extraction |
| [nosqlbrute.py](#nosqlbrutepy) | A05 — Injection | NoSQL regex injection used to brute force credentials |
| [pWar.py](#pwarpy) | A07 — Authentication Failures | Targeted credential wordlist generation |
| [reconinject](#reconinject) | A05 — Injection | Automated fuzzing to detect injection points across forms and APIs |

The 2025 list replaced the 2021 version in January 2026. A07:2025 (Authentication Failures) was A07:2021 (Identification and Authentication Failures) under the old naming, and A05:2025 (Injection) was A03:2021 under the old numbering. Reference: [owasp.org/Top10/2025](https://owasp.org/Top10/2025/)

---

## JWTCreator

**OWASP Top 10:2025: A07 — Authentication Failures**

Decodes an existing JWT into its header and payload, or encodes a new JWT from a JSON payload with HMAC-SHA256 signing, or alg=none. Used for manual JWT forgery and inspection when testing token validation logic on a target app. The alg=none path specifically tests whether a server accepts unsigned tokens, a common broken authentication flaw.

**Usage**

```
python3 JWTCreator -d -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123
python3 JWTCreator -e -p '{"user":"admin","role":"admin"}' -s mysecretkey
python3 JWTCreator -e -p '{"user":"admin"}' -a none
```

**Help output**

```
usage: JWTCreator [-h] (--decode | --encode) [-t TOKEN] [-p PAYLOAD]
                  [-s SECRET] [-a ALG]

JWT Multi-Tool

options:
  -h, --help            show this help message and exit
  --decode, -d
  --encode, -e
  -t TOKEN, --token TOKEN
                        The JWT string to decode
  -p PAYLOAD, --payload PAYLOAD
                        JSON string for the payload
  -s SECRET, --secret SECRET
                        Secret key OR path to file
  -a ALG, --alg ALG     Algorithm
```

---

## lsuck.py

**OWASP Top 10:2025: A05 — Injection**

The script's own description is "LDAP Injection via LSUCK anchor." It reads a raw .req HTTP request file, replaces the literal string LSUCK in the body with successive character guesses, and checks the response for a matching HTML tag, id, class, or text to confirm a hit. Used for character by character blind LDAP injection extraction.

**Usage**

```
python3 lsuck.py -f request.req -contain "Welcome"
python3 lsuck.py -f request.req -html div -id result -contain "success"
```

**Help output**

```
usage: lsuck.py [-h] -f FILE [-html TAG] [-id ID] [-class CLS] -contain
                CONTAIN

LDAP Injection via LSUCK anchor

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to .req file
  -html TAG, --tag TAG  HTML tag
  -id ID, --id ID       Tag ID
  -class CLS, --cls CLS
                        Tag Class
  -contain CONTAIN, --contain CONTAIN
                        Text to find in tag
```

---

## nosqlbrute.py

**OWASP Top 10:2025: A05 — Injection**

Brute forces a login endpoint vulnerable to NoSQL regex injection, guessing the password one character at a time by watching for the absence of a known failure string. Used for credential extraction against MongoDB style regex injectable auth. The root cause is unsanitized input reaching a NoSQL query operator, which also touches A07 Authentication Failures since the end result is a compromised login.

**Usage**

```
python3 nosqlbrute.py -u http://10.66.146.113/login.php -un admin -pl 5 -f "err=1"
python3 nosqlbrute.py -u http://10.66.146.113/login.php -un guest -f "Invalid"
```

**Help output**

```
usage: nosqlbrute.py [-h] -u URL -un USERNAME [-pl LENGTH] -f FAIL

NoSQL Regex Password Brute Forcer

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -un USERNAME, --username USERNAME
                        Username to target (e.g., admin)
  -pl LENGTH, --length LENGTH
                        Password length
  -f FAIL, --fail FAIL  String that identifies a failed attempt
```

---

## pWar.py

**OWASP Top 10:2025: A07 — Authentication Failures**

Generates username and password wordlist variants from a first name, last name, keywords, and date of birth combinations, plus special character padding. Used for large scale, targeted credential wordlist generation against a specific person. This supports testing whether an application's authentication layer permits weak or predictable credentials.

**Usage**

```
python3 pWar.py -f John -l Doe -y 1991,1985 -m March,04 -d 1,27 -k "33,pokemon" -on johndoe_wordlist
python3 pWar.py -f John -l Doe -sa 2 -v
```

**Help output**

```
    __        ___    ____  
 _ _\ \      / / \  |  _ \
| '_ \ \ /\ / / _ \ | |_) |
| |_) \ V  V / ___ \|  _ <
| .__/ \_/\_/_/   \_\_| \_\
|_|  
this is war

by TheRealBastioul
https://www.github.com/TheRealBastioul

**Legal Disclaimer**
---------------------------------
For educational and authorized security testing on
accounts and systems you own or have written permission
to test. Unauthorized use against systems you do not
control may violate the Computer Fraud and Abuse Act
and similar state laws.
---------------------------------
usage: pWar.py [-h] [-f F] [-l L] [-k K] [-y Y] [-m M] [-d D] [-on ON]
               [-sa SA] [-sax SAX] [-v]

Generate username and password wordlist variants from personal details.

options:
  -h, --help  show this help message and exit
  -f F        First name
  -l L        Last name
  -k K        Keywords, comma separated, e.g. "33,pokemon,chaos"
  -y Y        Years, comma separated, e.g. "1991,1977"
  -m M        Months, comma separated (name or number), e.g. "March,04"
  -d D        Days, comma separated, e.g. "1,27"
  -on ON      Output filename base (no extension)
  -sa SA      Repeated special char length, front and back. Default 1 if not
              passed.
  -sax SAX    Every N length combination of different special chars, front and
              back. Off by default.
  -v          Print each username and password as it gets written to file. Off
              by default, can slow down very large runs.
```

---

## reconinject

**OWASP Top 10:2025: A05 — Injection**

Modular injection fuzzer for form fields and JSON or AJAX endpoints. Sends payloads from an internal payload map against a target parameter and flags anomalous responses such as timeouts, redirects, or length changes. Used for automated detection of injection points across form and API targets.

**Usage**

```
python3 reconinject -u http://target.com/login.php -d "mail=test&pass=test" -sanity
python3 reconinject -u http://target.com/functions.php -d "username=t&pass=t&function=login" --json --preset AJAX
python3 reconinject -u http://target.com/login.php -d "mail=t&pass=t" --no-follow
```

**Help output**

```
usage: reconinject [-h] -u URL [-c COOKIE] [-d DATA] [-p PARAMETER]
                   [-R REQUEST_TYPE] [-H HEADERS] [--json] [--preset PRESET]
                   [-t TEST_TYPE] [-sanity] [--testsanity] [--proxy PROXY]
                   [--no-follow]

ReconInject

options:
  -h, --help            show this help message and exit
  -u URL, --url URL
  -c COOKIE, --cookie COOKIE
  -d DATA, --data DATA
  -p PARAMETER, --parameter PARAMETER
  -R REQUEST_TYPE, --request-type REQUEST_TYPE
  -H HEADERS, --headers HEADERS
                        Custom headers
  --json                Send data as JSON object
  --preset PRESET       Presets: AJAX
  -t TEST_TYPE, --test-type TEST_TYPE
  -sanity               Try encoding variants (Form mode only)
  --testsanity           Run character reflection test
  --proxy PROXY
  --no-follow           Do not follow redirects
```

---

## Disclaimer

For educational and authorized security testing on
accounts and systems you own or have written permission
to test. Unauthorized use against systems you do not
control may violate the Computer Fraud and Abuse Act
and similar state laws.
