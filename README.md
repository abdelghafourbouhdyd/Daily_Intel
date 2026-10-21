This repository publishes IOCs and IOAs I personally discover through daily threat hunting. Every indicator comes from custom hunting rules I build on infrastructure intelligence platforms — Validin, Shodan, Censys, FOFA — tuned to fingerprint specific malware families, C2 frameworks, and phishing infrastructure. This is the output of my own hunting, not a re-aggregation of public feeds.

## Repository layout

Indicators are classified by what the infrastructure *is*, then by the family, technique or actor behind it.

```
malware/
  stealers/
    windows/                 ACRStealer, AgentTesla, Formbook, LummaC2, PureLogs, Remus,
                             Rhadamanthys, Vidar, Void Stealer
    macos/                   AMOS, CrashStealer, MacSync
  rats/                      ValleyRAT
c2/
  frameworks/                Cobalt Strike, Mythic, Octopus
  redirectors/               RedGuard
post-exploitation/           ReverseSSH
phishing/
  clickfix/                  ClickFix and fake-docs lures
  credential-harvesting/     Microsoft login, device code, compromised WordPress pages
  scams/                     Brand-abuse and ad scams (Meta)
threat-actors/               DPRK, Smishing Triad, UNC1069
campaigns/                   Named campaigns and write-ups that span several families
research/                    Pivoting stories and longer analyses
hunting-rules/               The Validin / Shodan / Censys / FOFA rules behind the indicators
scripts/                     Helpers (index generator)
```

Where something fits two places, the rule is:

- **Malware family** (it is a tool the actor ships) goes under `malware/`, `c2/` or `post-exploitation/`.
- **Delivery technique** (how the victim is lured) goes under `phishing/`.
- **Who is behind it** goes under `threat-actors/`.
- **One named operation that mixes several of the above** goes under `campaigns/`.

## Conventions

- One file per family, technique, actor or campaign. `.txt` files are plain indicator lists, `.md` files are write-ups.
- One indicator per line, **defanged**: `.` becomes `[.]` and `http`/`https` becomes `hxxp`/`hxxps`, for example `hxxps://example[.]com/path` and `203[.]0[.]113[.]7`. Refang before use.
- Lines starting with `#` (or `ref:` / `about :`) are comments and source references and are left un-defanged on purpose.
- File and folder names are lowercase kebab-case.

## Index

Counts are unique indicators per file. Regenerate with `python3 scripts/build_index.py` after adding indicators.

<!-- INDEX:START -->
| Category | Family / campaign | IPs | Domains | URLs & endpoints |
|---|---|--:|--:|--:|
| Stealer (Windows) | [ACRStealer](malware/stealers/windows/acrstealer.txt) | 3 | 4 | 4 |
| Stealer (Windows) | [AgentTesla](malware/stealers/windows/agenttesla.txt) | – | 3 | – |
| Stealer (Windows) | [Formbook](malware/stealers/windows/formbook.txt) | – | 5 | – |
| Stealer (Windows) | [LummaC2](malware/stealers/windows/lummac2.txt) | 5 | 1 | 8 |
| Stealer (Windows) | [PureLogs](malware/stealers/windows/purelogs.txt) | 6 | 2 | 11 |
| Stealer (Windows) | [Remus](malware/stealers/windows/remus.txt) | – | 34 | 69 |
| Stealer (Windows) | [Rhadamanthys](malware/stealers/windows/rhadamanthys.txt) | – | – | – |
| Stealer (Windows) | [Vidar](malware/stealers/windows/vidar.txt) | 152 | 7 | 101 |
| Stealer (Windows) | [Void Stealer](malware/stealers/windows/void-stealer.txt) | – | – | – |
| Stealer (macOS) | [AMOS](malware/stealers/macos/amos.txt) | 5 | 4 | 1 |
| Stealer (macOS) | [CrashStealer](malware/stealers/macos/crashstealer.txt) | – | – | 3 |
| Stealer (macOS) | [MacSync](malware/stealers/macos/macsync.txt) | – | 232 | – |
| RAT / backdoor | [ValleyRAT](malware/rats/valleyrat.txt) | 7 | 6 | 14 |
| C2 framework | [Cobalt Strike](c2/frameworks/cobalt-strike.txt) | – | – | – |
| C2 framework | [Mythic](c2/frameworks/mythic.txt) | – | – | – |
| C2 framework | [Octopus](c2/frameworks/octopus.txt) | – | – | – |
| C2 redirector | [RedGuard](c2/redirectors/redguard.txt) | 33 | – | – |
| Post-exploitation | [ReverseSSH](post-exploitation/reversessh.txt) | – | – | – |
| Phishing: ClickFix | [Claude ClickFix](phishing/clickfix/claude-clickfix.txt) | – | 1 | – |
| Phishing: ClickFix | [ClickFix](phishing/clickfix/click-fix.txt) | 1 | 10 | – |
| Phishing: credential harvesting | [Compromised WordPress](phishing/credential-harvesting/compromised-wordpress.txt) | – | – | 72 |
| Phishing: credential harvesting | [Device code](phishing/credential-harvesting/device-code.txt) | 1 | – | 2 |
| Phishing: credential harvesting | [Microsoft login](phishing/credential-harvesting/microsoft-login.txt) | – | 84 | – |
| Phishing: scams | [Meta scam](phishing/scams/meta-scam.txt) | – | 1 | – |
| Threat actor | [DPRK](threat-actors/dprk.txt) | 1 | 11 | – |
| Threat actor | [Smishing Triad](threat-actors/smishing-triad.txt) | 85 | 8,940 | 1 |
| Threat actor | [UNC1069](threat-actors/unc1069.txt) | 8 | 43 | – |
| Campaign | [e-Visa phishing](campaigns/e-visa-phishing.txt) | 1 | 2 | – |
| Campaign | [Survey-bonus phishing](campaigns/survey-bonus-phishing.txt) | 1 | 39 | – |
| Campaign | [Trojanised Notepad++](campaigns/trojanised-notepad-plus-plus.md) | write-up | write-up | write-up |
| Research | [Not a simple domain](research/not-a-simple-domain.md) | write-up | write-up | write-up |

**Total unique indicators:** 10,024 (309 IPs, 9,429 domains, 286 URLs and endpoints)
<!-- INDEX:END -->
