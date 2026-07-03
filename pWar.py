#!/usr/bin/env python3
"""
Username / password wordlist variant generator.

ASSUMPTIONS MADE (your spec had some gaps and internal inconsistencies, listed here
instead of silently guessing, per your instruction not to fill gaps quietly):

1. Special char count: you said First/LastAddSpecial should produce "36 variants" but
   the literal character list you gave only has 32 distinct characters. This script
   uses the literal 32-character list, so you get 32 variants per side, not 36. If you
   actually need 36, tell me which 4 extra characters to add.

2. Year x Month x Day combination mode: you said "whatever gives the most combinations",
   so this script does a FULL CARTESIAN PRODUCT of every value in -y, -m, -d, not
   parallel triples. With N years, M months, D days that is N*M*D DOB combinations, so
   large lists here will grow the wordlist fast.

3. Month/day variants (namemonthscheme/namedayscheme): your spec only described numeric
   single-digit vs zero-padded variants (the "3 and 03" note), not the month name text
   itself. Month names are converted to numbers, and the script generates name+3,
   name+03, 3+name, 03+name (same pattern for day, no name-of-month string is combined
   with the username).

4. DOB string formats: your 7 example strings mostly follow clean Y/M/D permutation
   patterns, except one ("31991" for y=1991,m=3,d=1) does not include the day at all,
   unlike the other 6 which include year, month, and day. This script reproduces that
   literally (month + full year, no day) because that is what your example showed, but
   flagging it here as likely a typo in the original spec.

5. userk / kscheme: your example list mixes case variants, orderings, and number
   placement in a way that is not a clean deterministic rule. This script generates
   kscheme combinatorially: every permutation of the non-numeric keywords, in
   lower/UPPER/Title/as-typed case, with numeric keywords appended as both prefix and
   suffix. This produces more combinations than your literal example list, in line with
   "whatever gives the most combinations." Keyword lists longer than ~4 non-numeric
   items will get very large very fast (factorial growth) — the script warns if the
   generated set exceeds 50,000 entries.

6. leetpass: your spec references a global "leetpass" array but never defines what
   populates it outside of the userleet() description. This script treats leetpass as
   the accumulated output of the userleet() function.

7. userleet position list: your spec lists about a dozen near-duplicate bullets (first
   letter, last letter, first vowel, last vowel, first+last combined, etc.) for both
   names and keywords. This script consolidates that into one function that substitutes
   at: first letter, last letter, first vowel, last vowel, first+last combined, and
   first-vowel+last-vowel combined, then feeds the result into username_variants() or
   k_scheme() as appropriate.

8. userkdobv / comboscheme: interpreted as combining kscheme items with (a) the full DOB
   strings, (b) the raw year value in full/short form, (c) the raw month value in
   short/padded form, (d) the raw day value in short/padded form — each as both a prefix
   and a suffix.

None of the above is presented as fact about what you "meant" — it's what this specific
implementation does, so you can correct any function before relying on the output.
"""

import argparse
import calendar

try:
    from rich.console import Console, Group
    from rich.text import Text
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # banner, colored orange text, and the pinned progress bar all need rich.
    # pip install rich to get those, script still runs fine without it, just plain text.
import itertools
import sys
import time
import functools

# ---------------------------------------------------------------------------
# Static data (from your spec, used as given)
# ---------------------------------------------------------------------------

LEETKEY = {
    'a': ['4', '@', '^', '*'], 'b': ['8'], 'c': ['(', '<', '{', '['],
    'd': [')'], 'e': ['3', '&', '%'], 'f': ['#'], 'g': ['6', '9'],
    'h': ['#'], 'i': ['1', '!', '|'], 'j': [']'], 'k': ['<'],
    'l': ['1', '|', '7'], 'm': [], 'n': [], 'o': ['0', '*'], 'p': ['9'],
    'q': ['9'], 'r': ['2'], 's': ['5', '$'], 't': ['7', '+'], 'u': [],
    'v': [], 'w': [], 'x': ['%'], 'y': ['?'], 'z': ['2'],
    '0': ['o', 'O'], '1': ['i', 'I', 'l', 'L', '!', '|'], '2': ['z', 'Z'],
    '3': ['e', 'E', '&'], '4': ['a', 'A', '@'], '5': ['s', 'S', '$'],
    '6': ['g', 'G'], '7': ['t', 'T', '+'], '8': ['b', 'B'],
    '9': ['g', 'q', 'p', 'P'],
}

VOWELS = set("aeiou")

# Literal char list from your spec: ! @ # $ % ^ & * ( ) _ + - = [ ] { } | ; : ' " , . < > / ? ~ ` \
SPECIALS = list("!@#$%^&*()_+-=[]{}|;:'\",.<>/?~`\\")

BANNER_TEXT = r"""    __        ___    ____  
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
---------------------------------"""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def last_upper(s):
    return s if not s else s[:-1] + s[-1].upper()


def first_upper(s):
    return s if not s else s[0].upper() + s[1:]


def month_to_num(m):
    """Accepts a month name, abbreviation, or numeric string. Raises ValueError if unrecognized."""
    m = str(m).strip()
    if m.isdigit():
        n = int(m)
        if 1 <= n <= 12:
            return n
        raise ValueError(f"Month number out of range: {m}")
    ml = m.lower()
    for i in range(1, 13):
        if calendar.month_name[i].lower() == ml or calendar.month_abbr[i].lower() == ml:
            return i
    raise ValueError(f"Unrecognized month value: {m!r}. Use a full month name, abbreviation, or 1-12.")


def day_to_num(d):
    n = int(str(d).strip())
    if not (1 <= n <= 31):
        raise ValueError(f"Day out of range: {d}")
    return n


def leet_options(ch):
    return LEETKEY.get(ch.lower(), [])


def first_vowel_index(word):
    for i, c in enumerate(word):
        if c.lower() in VOWELS:
            return i
    return None


def last_vowel_index(word):
    for i in range(len(word) - 1, -1, -1):
        if word[i].lower() in VOWELS:
            return i
    return None


def substitute_position(word, idx):
    """All variants of word with a single index replaced by each leet option for that char."""
    if idx is None or not (0 <= idx < len(word)):
        return []
    opts = leet_options(word[idx])
    return [word[:idx] + o + word[idx + 1:] for o in opts]


def substitutable_positions(word):
    """Indices in word where a leet substitution exists at all."""
    return [i for i, c in enumerate(word) if leet_options(c)]


@functools.lru_cache(maxsize=None)
def leet_variants_of_word(word, max_simultaneous=2, max_positions=10):
    """Every subset of substitutable positions UP TO max_simultaneous size, substituted
    together. Capped at pairs by default because full powerset (every subset up to full
    word length) caused a memory crash on real input, singles and pairs cover every
    example given so far (P0k3mon needs 2 positions, H3rrera needs 1). Raise
    max_simultaneous only if you actually need 3+ positions changed at once, it grows
    combinatorially fast.
    Cached because userleet and namekeyword_scheme both call this on the same first
    name, last name, and keywords, this was doing the same substitution work twice."""
    if not word:
        return set()
    positions = substitutable_positions(word)
    if not positions:
        return set()
    if len(positions) > max_positions:
        positions = positions[:max_positions]

    cap = min(max_simultaneous, len(positions))
    variants = set()
    for r in range(1, cap + 1):
        for subset in itertools.combinations(positions, r):
            option_lists = [leet_options(word[i]) for i in subset]
            for combo in itertools.product(*option_lists):
                chars = list(word)
                for idx, val in zip(subset, combo):
                    chars[idx] = val
                variants.add("".join(chars))

    return variants


def leet_full(word):
    chars = list(word)
    changed = False
    for i, c in enumerate(chars):
        opts = leet_options(c)
        if opts:
            chars[i] = opts[0]
            changed = True
    return "".join(chars) if changed else None


def leet_vowels_only(word):
    chars = list(word)
    changed = False
    for i, c in enumerate(chars):
        if c.lower() in VOWELS:
            opts = leet_options(c)
            if opts:
                chars[i] = opts[0]
                changed = True
    return "".join(chars) if changed else None


def leet_first_char(word):
    v = substitute_position(word, 0)
    return v[0] if v else None


def leet_last_char(word):
    v = substitute_position(word, len(word) - 1)
    return v[0] if v else None


# ---------------------------------------------------------------------------
# Core generation functions (named to match your spec: username, usernamey, userm,
# userd, userdob, userk, userleet, userkdobv, createusernames, createp)
# ---------------------------------------------------------------------------

def _username_patterns(f, l):
    return [
        f,
        l,
        f[0] + l,
        f[0] + "." + l,
        f[0:2] + l[0:5],
        f[0] + l[0:5],
        f[0] + l[0:4],
        f + "." + l,
        f + l,
        l + f[0],
        l[0:6] + f[0],
        l[0:4] + f[0],
        l + "." + f,
        l + f,
        f[0] + l[0],
        l[0] + f[0],
    ]


def username_variants(f, l):
    """Builds namescheme from first/last name. Uses both the raw form and the firstUpper
    form of f and l independently, so a single initial pulled from a capitalized name
    (like the V in HerreraV) is possible, not just a capital letter at position 0 of the
    whole joined string."""
    if not f or not l:
        return set()
    forms_f = {f, first_upper(f)}
    forms_l = {l, first_upper(l)}
    variants = set()
    for ff in forms_f:
        for ll in forms_l:
            variants.update(_username_patterns(ff, ll))
    return variants


def nameyear_variants(namescheme, years):
    out = set()
    for name in namescheme:
        for y in years:
            y = str(y).strip()
            y_full = y if len(y) >= 4 else y.zfill(4)
            y_short = y[-2:]
            for val in {y_full, y_short}:
                out.add(name + val)
                out.add(val + name)
    return out


def namemonth_variants(namescheme, months):
    out = set()
    for name in namescheme:
        for m in months:
            num = month_to_num(m)
            for val in {str(num), f"{num:02d}"}:
                out.add(name + val)
                out.add(val + name)
    return out


def nameday_variants(namescheme, days):
    out = set()
    for name in namescheme:
        for d in days:
            num = day_to_num(d)
            for val in {str(num), f"{num:02d}"}:
                out.add(name + val)
                out.add(val + name)
    return out


def namemonthday_variants(namescheme, months, days):
    """Month plus day joined together, no year involved. Covers cases like 7/22 -> 722."""
    out = set()
    for name in namescheme:
        for m in months:
            num_m = month_to_num(m)
            m_short, m_pad = str(num_m), f"{num_m:02d}"
            for d in days:
                num_d = day_to_num(d)
                d_short, d_pad = str(num_d), f"{num_d:02d}"
                for val in {m_short + d_short, m_pad + d_pad, d_short + m_short, d_pad + m_pad}:
                    out.add(name + val)
                    out.add(val + name)
    return out


def dob_strings(years, months, days):
    """Full cartesian product of years x months x days (see assumption 2)."""
    dobs = set()
    for y in years:
        y = str(y).strip()
        y_full = y if len(y) >= 4 else y.zfill(4)
        y_short = y[-2:]
        for m in months:
            num_m = month_to_num(m)
            m_short, m_pad = str(num_m), f"{num_m:02d}"
            for d in days:
                num_d = day_to_num(d)
                d_short, d_pad = str(num_d), f"{num_d:02d}"
                dobs.update([
                    y_full + m_pad + d_pad,     # 19910301
                    y_full + m_short + d_short, # 199131
                    y_short + m_short + d_short,# 9131
                    m_short + d_short + y_short,# 3191
                    m_pad + d_pad + y_short,    # 030191
                    m_short + y_full,           # 31991  (literal per your example; no day)
                    m_pad + d_pad + y_full,     # 03011991
                ])
    return dobs


def namedob_variants(namescheme, dobscheme):
    out = set()
    for name in namescheme:
        for dob in dobscheme:
            out.add(name + dob)
            out.add(dob + name)
    return out


def k_scheme(keywords):
    """Combinatorial keyword variants. See assumption 5."""
    keywords = [k.strip() for k in keywords if k.strip()]
    alpha = [k for k in keywords if not k.isdigit()]
    numeric = [k for k in keywords if k.isdigit()]

    variants = set()
    for r in range(1, len(alpha) + 1):
        for perm in itertools.permutations(alpha, r):
            case_options = [[w.lower(), w.upper(), w.title(), first_upper(w), w] for w in perm]
            for combo in itertools.product(*case_options):
                variants.add("".join(combo))

    full = set(variants)
    for base in variants:
        for num in numeric:
            full.add(base + num)
            full.add(num + base)
    return full


def userleet(f, l, keywords):
    """Leet-substitutes f/l and keywords, feeding results into username_variants / k_scheme."""
    leetpass = set()

    for variant_word in leet_variants_of_word(f):
        leetpass.update(username_variants(variant_word, l))
    for variant_word in leet_variants_of_word(l):
        leetpass.update(username_variants(f, variant_word))

    for kw in keywords:
        if kw.strip().isdigit():
            continue
        for variant_word in leet_variants_of_word(kw):
            new_keywords = [variant_word if x == kw else x for x in keywords]
            leetpass.update(k_scheme(new_keywords))

    return leetpass


def combo_scheme(kscheme, dobscheme, years, months, days):
    """userkdobv: kscheme combined with dob strings and raw y/m/d values, prefix+suffix."""
    combos = set()
    for k in kscheme:
        for dob in dobscheme:
            combos.add(dob + k)
            combos.add(k + dob)
        for y in years:
            y = str(y).strip()
            y_full = y if len(y) >= 4 else y.zfill(4)
            for val in {y_full, y_full[-2:]}:
                combos.add(val + k)
                combos.add(k + val)
        for m in months:
            num = month_to_num(m)
            for val in {str(num), f"{num:02d}"}:
                combos.add(val + k)
                combos.add(k + val)
        for d in days:
            num = day_to_num(d)
            for val in {str(num), f"{num:02d}"}:
                combos.add(val + k)
                combos.add(k + val)
    return combos


def namekeyword_scheme(f, l, keywords):
    """Joins first name OR last name (never combined together) with keyword(s).
    Each side gets its as-typed form, lowercase form, first letter capitalized form,
    and every leet substitution of those forms. Numeric keywords (like 88) are appended
    as an optional suffix on top of the name+keyword base."""
    alpha_kw = [k.strip() for k in keywords if k.strip() and not k.strip().isdigit()]
    numeric_kw = [k.strip() for k in keywords if k.strip() and k.strip().isdigit()]

    def word_forms(word):
        if not word:
            return set()
        forms = {word, word.lower(), first_upper(word)}
        for leet_v in leet_variants_of_word(word):
            forms.add(leet_v)
            forms.add(first_upper(leet_v))
        return forms

    name_sides = set()
    for name in (f, l):
        name_sides |= word_forms(name)

    kw_sides = set()
    for kw in alpha_kw:
        kw_sides |= word_forms(kw)

    combos = set()
    for n in name_sides:
        for k in kw_sides:
            base = n + k
            combos.add(base)
            for num in numeric_kw:
                combos.add(base + num)
    return combos


def capitalize_pool(pool):
    """Adds a first letter capitalized variant of every item in pool, keeps originals too."""
    extra = set()
    for item in pool:
        extra.add(first_upper(item))
    return set(pool) | extra


def name_rawkeyword_suffix(finalusernames, keywords):
    """Appends each raw keyword value (as typed, no leet, no case change) to the end
    of every finalusernames item. This is separate from namekeyword_scheme, which
    only uses alpha keywords and leet substitutes them. This one uses keywords exactly
    as typed, including numeric ones, and only appends at the end."""
    combos = set()
    for item in finalusernames:
        for k in keywords:
            k = k.strip()
            if k:
                combos.add(item + k)
    return combos


def add_special_repeat(items, n):
    """-sa N: same special char repeated N times, appended front and back."""
    out = set()
    for item in items:
        for c in SPECIALS:
            block = c * n
            out.add(item + block)
            out.add(block + item)
    return out


def add_special_combo(items, n):
    """-sax N: every N length combination of different special chars, front and back.
    Size is len(items) * 32^N * 2, grows fast, caller should warn before using n >= 3."""
    out = set()
    for item in items:
        for combo in itertools.product(SPECIALS, repeat=n):
            block = "".join(combo)
            out.add(item + block)
            out.add(block + item)
    return out


def create_passwords(finalusernames, leetpass, kscheme, comboscheme, namekeyword=None, sa=None, sax=None):
    """createp: special-char padding + leet substitution across all schemes."""
    pwar = set()

    def add_special_both(collection):
        for item in collection:
            for c in SPECIALS:
                pwar.add(item + c)
                pwar.add(c + item)

    add_special_both(finalusernames)
    add_special_both(leetpass)
    if namekeyword:
        pwar.update(namekeyword)
        add_special_both(namekeyword)

    if sa is not None or sax is not None:
        base_pool = set(finalusernames) | set(leetpass) | set(kscheme) | set(comboscheme)
        if namekeyword:
            base_pool |= set(namekeyword)
        if sa is not None:
            pwar.update(add_special_repeat(base_pool, sa))
        if sax is not None:
            pwar.update(add_special_combo(base_pool, sax))

    for collection in (finalusernames, kscheme, comboscheme):
        for item in collection:
            for fn in (leet_full, leet_vowels_only, leet_first_char, leet_last_char):
                result = fn(item)
                if result:
                    pwar.add(result)

    return pwar


def write_outputs(finalusernames, pwar, outbase, verbose=False, printer=None):
    """printer, if given, is a callable used for verbose lines instead of print().
    Needed because a plain print() call during an active rich Live render corrupts
    the pinned banner/progress bar, live.console.print() is the safe version.
    File writes are batched into one write() call per file instead of one call per
    line, cuts down on syscall overhead at millions of lines. Verbose printing still
    happens per line since that is the point of -v, that part cannot be batched
    without changing what -v does."""
    if printer is None:
        printer = print
    uname_file = f"{outbase}_usernames.txt"
    pwar_file = f"{outbase}_pwar.txt"

    sorted_unames = sorted(finalusernames)
    with open(uname_file, "w") as fh:
        if sorted_unames:
            fh.write("\n".join(sorted_unames) + "\n")
    if verbose:
        for u in sorted_unames:
            printer(f"[ {u} ] created")

    sorted_pwar = sorted(pwar)
    with open(pwar_file, "w") as fh:
        if sorted_pwar:
            fh.write("\n".join(sorted_pwar) + "\n")
    if verbose:
        for p in sorted_pwar:
            printer(f"[ {p} ] created")

    return uname_file, pwar_file


# ---------------------------------------------------------------------------
# CLI / interactive mode
# ---------------------------------------------------------------------------

def split_csv(s):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def build_parser():
    p = argparse.ArgumentParser(
        description="Generate username and password wordlist variants from personal details."
    )
    p.add_argument("-f", help="First name")
    p.add_argument("-l", help="Last name")
    p.add_argument("-k", help="Keywords, comma separated, e.g. \"33,pokemon,chaos\"")
    p.add_argument("-y", help="Years, comma separated, e.g. \"1991,1977\"")
    p.add_argument("-m", help="Months, comma separated (name or number), e.g. \"March,04\"")
    p.add_argument("-d", help="Days, comma separated, e.g. \"1,27\"")
    p.add_argument("-on", help="Output filename base (no extension)")
    p.add_argument("-sa", type=int, default=1, help="Repeated special char length, front and back. Default 1 if not passed.")
    p.add_argument("-sax", type=int, default=None, help="Every N length combination of different special chars, front and back. Off by default.")
    p.add_argument("-v", action="store_true", help="Print each username and password as it gets written to file. Off by default, can slow down very large runs.")
    return p


def interactive_mode():
    print("=== Interactive mode (no arguments detected) ===")
    f = input("First name: ").strip()
    l = input("Last name: ").strip()
    k = input("Keywords (comma separated, optional): ").strip()
    y = input("Years (comma separated, optional): ").strip()
    m = input("Months, name or number (comma separated, optional): ").strip()
    d = input("Days (comma separated, optional): ").strip()
    sa_raw = input("Special char repeat length -sa [1]: ").strip()
    sa = int(sa_raw) if sa_raw else 1
    sax_raw = input("Special char combination length -sax [blank = off]: ").strip()
    sax = int(sax_raw) if sax_raw else None
    v_raw = input("Print each password as it is written to file? y/N [N]: ").strip().lower()
    verbose = v_raw == "y"
    on = input("Output filename base [variants]: ").strip() or "variants"
    return f, l, split_csv(k), split_csv(y), split_csv(m), split_csv(d), on, sa, sax, verbose


def run_pipeline(f, l, keywords, years, months, days, outbase, sa, sax, verbose, log, tick):
    """Core pipeline, shared by both the rich and plain code paths. log() prints a
    message, tick() advances the progress counter by one stage."""
    log("[*] Building username base variants (namescheme)...")
    namescheme = username_variants(f, l)
    log(f"    {len(namescheme)} variants")
    tick()

    nameyearscheme = nameyear_variants(namescheme, years) if years else []
    namemonthscheme = namemonth_variants(namescheme, months) if months else []
    namedayscheme = nameday_variants(namescheme, days) if days else []
    namemonthdayscheme = namemonthday_variants(namescheme, months, days) if (months and days) else []
    dobscheme = dob_strings(years, months, days) if (years and months and days) else set()
    namedobscheme = namedob_variants(namescheme, dobscheme) if dobscheme else []
    tick()

    log("[*] Building keyword variants (kscheme)...")
    kscheme = k_scheme(keywords) if keywords else set()
    log(f"    {len(kscheme)} variants")
    if len(kscheme) > 50000:
        log("    WARNING: kscheme is very large (permutation count grows factorially "
            "with the number of alpha keywords). Runtime may be slow.")
    tick()

    log("[*] Building leet substitution variants (leetpass)...")
    leetpass = userleet(f, l, keywords)
    log(f"    {len(leetpass)} variants")
    tick()

    namemonthdayscheme_leet = namemonthday_variants(leetpass, months, days) if (months and days) else set()
    log("[*] Building month plus day combos for leet names...")
    log(f"    {len(namemonthdayscheme_leet)} variants")
    tick()

    log("[*] Building combo scheme (kscheme + dob/year/month/day)...")
    comboscheme = combo_scheme(kscheme, dobscheme, years, months, days) if kscheme else set()
    log(f"    {len(comboscheme)} variants")
    tick()

    log("[*] Building name plus keyword combos (namekeyword)...")
    namekeyword = namekeyword_scheme(f, l, keywords) if keywords else set()
    log(f"    {len(namekeyword)} variants")
    tick()

    finalusernames = set(namescheme) | set(nameyearscheme) | set(namemonthscheme) \
        | set(namedayscheme) | set(namemonthdayscheme) | set(namemonthdayscheme_leet) | set(namedobscheme)
    finalusernames = capitalize_pool(finalusernames)
    log(f"[*] finalusernames total (with capitalization): {len(finalusernames)}")
    tick()

    log("[*] Building name plus raw keyword suffix combos...")
    namerawk = name_rawkeyword_suffix(finalusernames, keywords) if keywords else set()
    log(f"    {len(namerawk)} variants")
    namekeyword = namekeyword | namerawk
    tick()

    if sax is not None and sax >= 3:
        log(f"    WARNING: -sax {sax} generates {len(SPECIALS)}^{sax} = "
            f"{len(SPECIALS)**sax:,} combinations PER base word, times 2 for front/back. "
            "This can take a long time and produce a very large file.")

    log("[*] Building password array (pwar)... this is the slow step for large inputs.")
    pwar = create_passwords(finalusernames, leetpass, kscheme, comboscheme, namekeyword=namekeyword, sa=sa, sax=sax)
    log(f"    {len(pwar)} password variants")
    tick()

    return finalusernames, pwar


PIPELINE_STAGES = 9  # number of tick() calls in run_pipeline, keep in sync if you add stages


def main():
    if RICH_AVAILABLE:
        Console().print(Text(BANNER_TEXT, style="dark_orange"))
    else:
        print(BANNER_TEXT)
    time.sleep(1.5)

    if len(sys.argv) == 1:
        f, l, keywords, years, months, days, outbase, sa, sax, verbose = interactive_mode()
    else:
        args = build_parser().parse_args()
        if not args.f or not args.l:
            print("ERROR: -f and -l are required.", file=sys.stderr)
            sys.exit(1)
        f, l = args.f.strip(), args.l.strip()
        keywords = split_csv(args.k)
        years = split_csv(args.y)
        months = split_csv(args.m)
        days = split_csv(args.d)
        outbase = args.on.strip() if args.on else "variants"
        sa = args.sa
        sax = args.sax
        verbose = args.v

    if not RICH_AVAILABLE:
        print("NOTE: pip install rich to get the banner and pinned progress bar. Running plain.")
        try:
            finalusernames, pwar = run_pipeline(
                f, l, keywords, years, months, days, outbase, sa, sax, verbose,
                log=print, tick=lambda: None,
            )
            uf, pf = write_outputs(finalusernames, pwar, outbase, verbose=verbose, printer=print)
            print(f"[+] Wrote {uf}")
            print(f"[+] Wrote {pf}")
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        return

    console = Console()
    progress = Progress(
        TextColumn("Progress[{task.percentage:>3.0f}%]"),
        BarColumn(bar_width=20),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    )
    task = progress.add_task("build", total=PIPELINE_STAGES + 1)  # +1 for the final write step
    banner = Text(BANNER_TEXT, style="dark_orange")
    group = Group(banner, progress)

    try:
        with Live(group, console=console, refresh_per_second=10) as live:
            def log(msg):
                if verbose:
                    live.console.print(msg)

            def tick():
                progress.update(task, advance=1)

            finalusernames, pwar = run_pipeline(
                f, l, keywords, years, months, days, outbase, sa, sax, verbose,
                log=log, tick=tick,
            )

            printer = live.console.print if verbose else (lambda *a, **k: None)
            uf, pf = write_outputs(finalusernames, pwar, outbase, verbose=verbose, printer=printer)
            progress.update(task, advance=1)
            live.console.print(f"[+] Wrote {uf}")
            live.console.print(f"[+] Wrote {pf}")
    except ValueError as e:
        console.print(f"ERROR: {e}", style="bold red")
        sys.exit(1)


if __name__ == "__main__":
    main()
