# PHP CVE Version Checker & Passive Fingerprinter (`php2shell_checker`)

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Design](https://img.shields.io/badge/Design-Zero%20Dependency-brightgreen.svg)]()
[![Type](https://img.shields.io/badge/Type-Passive%20Triage-blue.svg)]()

A lightweight, non-intrusive triage tool and passive HTTP fingerprinter designed to check target assets against PHP vulnerabilities (**CVE-2026-109618** and **CVE-2026-109619**).

Built entirely using Python's standard library (zero external dependencies required), this tool evaluates local PHP CLI runtimes, predefined asset inventories (CSV/TXT), or live HTTP/HTTPS response headers with minimal network overhead.

---

## 🌟 Key Features

- **Zero External Dependencies**: Works out-of-the-box using the Python 3 Standard Library (`urllib`, `ssl`, `argparse`, `csv`, `re`, `subprocess`).
- **Safe & Passive Fingerprinting**: Performs only a single, ordinary HTTP `GET` request to the root URL.
  - ❌ No exploit payloads or brute-forcing
  - ❌ No directory or `phpinfo()` path fuzzing
  - ❌ No port scanning or subdomain enumeration
- **Multi-Mode Operation**:
  - **Local Runtime Check**: Audits installed PHP binary via CLI without any network requests.
  - **Single Target Audit**: Checks individual domain or IP with optional known version or passive header discovery.
  - **Batch Inventory Processing**: Ingests `.txt` or `.csv` asset inventories.
- **Reporting**: Prints clear console results and exports structured findings to `.csv`.
- **Self-Signed / Insecure TLS Support**: Optional `--insecure` flag for auditing internal environments or staging targets.

---

## 🛡️ Vulnerability Threshold Matrix

The tool evaluates detected PHP versions against the following baseline thresholds:

| PHP Branch | Status / Fixed Threshold | Evaluation Notes |
|:---:|:---:|:---|
| **< 8.2** *(e.g., 5.x, 7.x, 8.0, 8.1)* | **VULNERABLE** | End-of-Life (EOL) upstream branch; unsupported without vendor backports |
| **8.2** | Fixed in **`8.2.35`** | Below threshold is flagged as `VULNERABLE` |
| **8.3** | Fixed in **`8.3.36`** | Below threshold is flagged as `VULNERABLE` |
| **8.4** | Fixed in **`8.4.27`** | Below threshold is flagged as `VULNERABLE` |
| **8.5** | Fixed in **`8.5.12`** | Below threshold is flagged as `VULNERABLE` |
| *Other / Hidden* | **UNKNOWN** | Version cannot be parsed from headers or branch is out-of-scope |

> **Note:** A status of `NOT VULNERABLE` means the version meets or exceeds the upstream threshold. Custom operating system backported patches (e.g., Debian, RHEL, Ubuntu) must be verified independently.

---

## 📦 Requirements

- **Python 3.8+** (No `pip install` required)
- Optional: Local `php` binary in your system `$PATH` (for `--local` checks)

---

## 🚀 Usage

### 1. Check Local PHP Runtime (Offline)
Audit the local machine's default PHP CLI binary:
```bash
python php2shell_checker.py --local
```

Or specify a custom PHP binary path:
```bash
python php2shell_checker.py --local --php-bin /usr/bin/php8.2
```

---

### 2. Check a Single Remote Asset

**With Passive Fingerprinting (Inspect HTTP Headers):**
```bash
python php2shell_checker.py --asset https://example.com
```

**Bypass TLS Validation (Self-Signed / Internal Hosts):**
```bash
python php2shell_checker.py --asset https://192.168.1.100 --insecure
```

**With a Pre-Known Version (Offline Assessment):**
```bash
python php2shell_checker.py --asset https://example.com --version 8.2.30
```

---

### 3. Batch Inventory Scan

Scan a list of targets from a text file with automatic HTTP header fingerprinting:
```bash
python php2shell_checker.py assets.txt --detect
```

Export scan results to a CSV report:
```bash
python php2shell_checker.py assets.txt --detect -o report.csv
```

Ignore SSL/TLS certificate errors for batch runs:
```bash
python php2shell_checker.py assets.txt --detect --insecure -o report.csv
```

---

## 📂 Inventory File Formats

### Text Format (`.txt`)
Supports plain lists, comma-separated values, or tab-delimited values. Comments starting with `#` are automatically skipped.

```text
# Domain or IP only (requires --detect)
https://app.example.com
https://192.168.1.50
staging.internal.corp

# Domain/IP with predetermined version
api.example.com,8.2.34
legacy.internal.lan,7.4.33
prod-gateway.example.com,8.3.36
```

### CSV Format (`.csv`)
Requires standard CSV headers: `asset,php_version`

```csv
asset,php_version
https://app.example.com,
https://api.example.com,8.2.34
192.168.1.50,8.3.36
```

---

## 📊 CSV Report Output Structure

When run with `-o report.csv`, the generated report includes:

| Column | Description |
|:---|:---|
| `asset` | Target hostname, URL, IP, or `LOCAL` |
| `php_version` | Detected or user-supplied PHP version |
| `cve` | Evaluated CVE (`CVE-2026-109618`, `CVE-2026-109619`) |
| `status` | `VULNERABLE`, `NOT VULNERABLE`, or `UNKNOWN` |
| `reason` | Technical rationale (e.g. threshold mismatch, EOL branch, missing banner) |

---

## 🔍 How Fingerprinting Works

When `--detect` or single-asset mode is used, the script checks HTTP response headers and cookies for passive indicators:

1. **Headers Analyzed**:
   - `X-Powered-By` (e.g. `PHP/8.2.10`)
   - `X-PHP-Version`
   - `Server` banner containing PHP version strings
   - `X-Generator`
2. **Session Signatures**:
   - Detection of `PHPSESSID` cookie (flags probable PHP presence even if exact version is hidden).

If hardening is applied (e.g., `expose_php = Off` in `php.ini` or reverse proxies stripping banners), the tool cleanly marks the target as `UNKNOWN` rather than guessing.

---

## ⚠️ Disclaimer

This tool is created for authorized penetration testing, vulnerability assessment, and security auditing purposes only. It does not perform exploitation or active service disruption. Users must obtain explicit authorization prior to scanning targets they do not own or administer.
