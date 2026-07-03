# Penetration Scripts

Custom tools built for penetration testing and web application security.

---

## JWTCreator

Decodes an existing JWT into its header and payload, or encodes a new JWT from a JSON payload with HMAC-SHA256 signing, or alg=none. Used for manual JWT forgery and inspection when testing token validation logic on a target app.

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

Brute forces a login endpoint vulnerable to NoSQL regex injection, guessing the password one character at a time by watching for the absence of a known failure string. Used for credential extraction against MongoDB style regex injectable auth.

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

Generates username and password wordlist variants from a first name, last name, keywords, and date of birth combinations, plus special character padding. Used for large scale, targeted credential wordlist generation against a specific person.

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
  --testsanity          Run character reflection test
  --proxy PROXY
  --no-follow           Do not follow redirects
```


## Disclaimer

For educational and authorized security testing on
accounts and systems you own or have written permission
to test. Unauthorized use against systems you do not
control may violate the Computer Fraud and Abuse Act
and similar state laws.
