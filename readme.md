# ViewState Decoder — Burp Suite Extension

A Burp Suite extension for decoding and analyzing ASP.NET `__VIEWSTATE` parameters directly inside Burp, with auto-highlight for security-sensitive values.

Built for pentesters working against **Telerik UI for ASP.NET AJAX** and standard ASP.NET WebForms applications.

---

## Features

- **Auto URL Decode** — handles URL-encoded ViewState (`%2F`, `%2B`, etc.) automatically before Base64 decoding
- **Three output views** — STRINGS / HEX DUMP / TOKENS (LosFormatter token parser)
- **Auto-highlight** — color-coded keywords across 6 security categories
- **ViewState tab in message editor** — appears next to Pretty / Raw / Hex when `__VIEWSTATE` is detected in any request or response
- **Right-click context menu** — send `__VIEWSTATE` directly from Proxy / Repeater / Intruder to the decoder tab
- **Copy output** — one-click copy decoded result to clipboard

---

## Requirements

| Item | Version |
|------|---------|
| Burp Suite | Pro or Community v2020.x+ |
| Jython | 2.7.x standalone JAR |

---

## Installation

### 1. Install Jython

Download the standalone JAR from https://www.jython.org/download

In Burp Suite:
```
Extender → Options → Python Environment → Select file → jython-standalone-x.x.x.jar
```

### 2. Load the Extension

```
Extender → Extensions → Add
Extension type : Python
Extension file : ViewStateDecoder.py
```

Confirm that the **Output** tab shows:
```
[ViewState Decoder] Loaded OK
```

---

## Usage

### Manual decode (ViewState tab)

1. Go to the **ViewState** tab in Burp's main tab bar
2. Paste a `__VIEWSTATE` value (Base64 or URL-encoded) into the input box
3. Click **[DECODE]**
4. Use the toggle buttons to switch between **STRINGS / HEX DUMP / TOKENS**

### From message editor

When Burp displays a request or response that contains `__VIEWSTATE`, a **ViewState** tab appears automatically next to Pretty / Raw / Hex.  
Click the tab — the value is decoded immediately with no extra steps.

### Right-click context menu

In **Proxy / Repeater / Intruder**, right-click any request or response:

```
Extensions → Send __VIEWSTATE to Decoder
```

The extension extracts the value, sends it to the ViewState tab, and decodes it automatically.

---

## Auto-highlight Reference

Highlights are applied in the **STRINGS** view only.

| Color | Category | Keywords |
|-------|----------|---------|
| 🟡 Amber | Role / Privilege | `role`, `admin`, `superuser`, `privilege`, `permission`, `isAdmin`, `isAuthenticated`, `access` |
| 🔴 Red-pink | Credentials | `password`, `passwd`, `pwd`, `secret`, `token`, `apikey`, `credential` |
| 🔵 Sky blue | User Identity | `username`, `userid`, `email`, `uid`, `fullname`, `displayname` |
| 🟢 Green | Boolean Flag | `true`, `false`, `enabled`, `disabled`, `active`, `locked`, `verified` |
| 🟣 Lavender | Version / Build | `version`, `build`, `release`, `revision`, `PublicKeyToken` |
| 🍑 Peach | Session / ID | `session`, `sessionid`, `viewstate`, `requestid`, `transactionid` |

A legend bar at the bottom of the output panel shows all categories at a glance.

---

## Decode Pipeline

```
Input (raw paste or from context menu)
  │
  ├─ [Step 1]  URL Decode        (if % characters detected)
  ├─ [Step 2]  Base64 Decode     (with auto-padding fix)
  └─ [Step 3]  Decompress        (gzip → deflate → raw, auto-detected)
                │
                ├─ STRINGS   — printable ASCII strings ≥ 3 chars + highlights
                ├─ HEX DUMP  — hex + ASCII side-by-side (first 4096 bytes)
                └─ TOKENS    — LosFormatter token walk (Int32, String, Bool, Null, Pair)
```

---

## Related CVEs (Telerik UI for ASP.NET AJAX)

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2019-18935 | Critical (9.8) | Insecure deserialization → RCE (affects versions before R1 2020) |
| CVE-2017-11317 | Critical | Unrestricted file upload → RCE |
| CVE-2017-11357 | Critical | Arbitrary file upload |
| CVE-2020-0688 | High | MachineKey + ViewState → RCE on ASP.NET (Exchange, IIS) |

If you find `Telerik.Web.UI, Version=` in the STRINGS output, note the version number and cross-reference against known CVEs.

---

## Disclaimer

This tool is intended for **authorized penetration testing and security research only**.  
Do not use against systems you do not have explicit permission to test.

---

## Author

[@mcca123](https://github.com/mcca123)