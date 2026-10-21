#!/usr/bin/env python3
"""Regenerate the indicator index table in README.md.

Run from anywhere:  python3 scripts/build_index.py

Counts unique indicators per IOC file and rewrites the block between
<!-- INDEX:START --> and <!-- INDEX:END --> in README.md. Everything else in
the README is left alone.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# folder -> category label, in display order
CATEGORIES = [
    ("malware/stealers/windows", "Stealer (Windows)"),
    ("malware/stealers/macos", "Stealer (macOS)"),
    ("malware/rats", "RAT / backdoor"),
    ("c2/frameworks", "C2 framework"),
    ("c2/redirectors", "C2 redirector"),
    ("post-exploitation", "Post-exploitation"),
    ("phishing/clickfix", "Phishing: ClickFix"),
    ("phishing/credential-harvesting", "Phishing: credential harvesting"),
    ("phishing/scams", "Phishing: scams"),
    ("threat-actors", "Threat actor"),
    ("campaigns", "Campaign"),
    ("research", "Research"),
    ("hunting-rules", "Hunting rules"),
]

# file stem -> display name (falls back to a title-cased stem)
NAMES = {
    "acrstealer": "ACRStealer", "agenttesla": "AgentTesla", "formbook": "Formbook",
    "lummac2": "LummaC2", "purelogs": "PureLogs", "remus": "Remus",
    "rhadamanthys": "Rhadamanthys", "vidar": "Vidar", "void-stealer": "Void Stealer",
    "amos": "AMOS", "crashstealer": "CrashStealer", "macsync": "MacSync",
    "valleyrat": "ValleyRAT", "cobalt-strike": "Cobalt Strike", "mythic": "Mythic",
    "octopus": "Octopus", "redguard": "RedGuard", "reversessh": "ReverseSSH",
    "claude-clickfix": "Claude ClickFix", "click-fix": "ClickFix",
    "microsoft-login": "Microsoft login", "device-code": "Device code",
    "compromised-wordpress": "Compromised WordPress", "meta-scam": "Meta scam",
    "dprk": "DPRK", "smishing-triad": "Smishing Triad", "unc1069": "UNC1069",
    "survey-bonus-phishing": "Survey-bonus phishing", "e-visa-phishing": "e-Visa phishing",
    "trojanised-notepad-plus-plus": "Trojanised Notepad++",
    "not-a-simple-domain": "Not a simple domain",
}

SKIP = re.compile(r"^(#|=|-{3,}|about\s*:|ref\s*:|refrence|reference)", re.I)
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def classify(line: str):
    """Return 'ip', 'domain', 'url' or None for a single line of an IOC file."""
    s = line.strip()
    if not s or SKIP.match(s):
        return None
    # real (non-defanged) links are references, indicators use hxxp / [.]
    if re.match(r"^https?://", s, re.I):
        return None
    s = s.replace("[.]", ".")
    s = re.sub(r"^hxxp(s?)://", r"http\1://", s, flags=re.I)
    if "://" in s or "/" in s or re.search(r":\d+$", s):
        return "url"  # URLs, tcp:// endpoints, host:port
    return "ip" if IPV4.match(s) else "domain"


def count(path: Path):
    seen = {"ip": set(), "domain": set(), "url": set()}
    for line in path.read_text(encoding="utf-8").splitlines():
        kind = classify(line)
        if kind:
            seen[kind].add(line.strip().lower())
    return {k: len(v) for k, v in seen.items()}


def build_table() -> str:
    rows = []
    totals = {"ip": 0, "domain": 0, "url": 0}
    for folder, label in CATEGORIES:
        for path in sorted((ROOT / folder).glob("*")):
            if not path.is_file() or path.name == "README.md":
                continue
            rel = path.relative_to(ROOT).as_posix()
            name = NAMES.get(path.stem, path.stem.replace("-", " ").title())
            if path.suffix == ".md":
                cells = ["write-up"] * 3
            else:
                c = count(path)
                if not any(c.values()):
                    cells = ["–"] * 3  # placeholder, nothing published yet
                else:
                    cells = [f"{c[k]:,}" if c[k] else "–" for k in ("ip", "domain", "url")]
                    for k in totals:
                        totals[k] += c[k]
            rows.append(f"| {label} | [{name}]({rel}) | " + " | ".join(cells) + " |")
    head = (
        "| Category | Family / campaign | IPs | Domains | URLs & endpoints |\n"
        "|---|---|--:|--:|--:|\n"
    )
    foot = f"\n\n**Total unique indicators:** {sum(totals.values()):,} " \
           f"({totals['ip']:,} IPs, {totals['domain']:,} domains, {totals['url']:,} URLs and endpoints)"
    return head + "\n".join(rows) + foot


def main():
    text = README.read_text(encoding="utf-8")
    block = f"<!-- INDEX:START -->\n{build_table()}\n<!-- INDEX:END -->"
    new, n = re.subn(r"<!-- INDEX:START -->.*?<!-- INDEX:END -->", lambda _: block, text, flags=re.S)
    if n != 1:
        raise SystemExit("README.md must contain exactly one INDEX:START / INDEX:END block")
    README.write_text(new, encoding="utf-8")
    print("README index updated")


if __name__ == "__main__":
    main()
