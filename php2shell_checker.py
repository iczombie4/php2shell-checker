#!/usr/bin/env python3
"""
PHP CVE version triage with optional HTTP version fingerprinting. Checks CVE-2026-109618 and CVE-2026-109619 using configured version thresholds.
"""

import argparse
import shutil
import subprocess
import csv
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
VERSION_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)")
TIMEOUT_SECONDS = 5
USER_AGENT = "Authorized-PHP-Version-Checker/2.0 (passive; no exploit requests)"


def assess_php_version(version_text):
    if not version_text or version_text.strip().lower() in {
        "unknown", "n/a", "none", "-", "null"
    }:
        return "UNKNOWN", "PHP version could not be identified"

    match = VERSION_RE.search(version_text.strip())
    if not match:
        return "UNKNOWN", "No parseable PHP version found"

    current = tuple(int(part) for part in match.groups())
    major, minor, _patch = current

    if major < 8 or (major == 8 and minor <= 1):
        return (
            "VULNERABLE",
            "Unsupported upstream PHP branch; verify vendor backports",
        )

    fixed = FIXED_VERSIONS.get((major, minor))
    if fixed is None:
        return "UNKNOWN", "PHP branch not covered by configured thresholds"

    if current < fixed:
        return (
            "VULNERABLE",
            "Version is below configured upstream fixed threshold "
            + ".".join(map(str, fixed)),
        )

    return (
        "NOT VULNERABLE",
        "Version meets configured upstream threshold; vendor patch status unverified",
    )


def normalize_url(value):
    value = value.strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    return value


def detect_php_version(target, insecure=False):
    """Low-impact fingerprint: one GET to the supplied root URL only.

    No POST, malformed requests, phpinfo-path guessing, origin/CDN bypass,
    port scanning, subdomain enumeration, or exploit/load probes.
    """
    url = normalize_url(target)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "Invalid URL or hostname", {"php_detected": False, "signals": []}

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Connection": "close",
        },
        method="GET",
    )
    context = ssl._create_unverified_context() if insecure and parsed.scheme == "https" else None
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
            headers = response.headers
            status = response.status
    except urllib.error.HTTPError as exc:
        headers = exc.headers or {}
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return None, f"Connection failed: {exc}", {"php_detected": False, "signals": []}

    candidates = []
    for header in ("X-Powered-By", "X-PHP-Version", "Server", "X-Generator"):
        value = headers.get(header, "")
        if value:
            candidates.append((header, value))

    signals = []
    for header, value in candidates:
        if "php" in value.lower():
            signals.append(f"{header}: {value[:160]}")
        # Only classify a version as PHP when the same banner identifies PHP.
        match = VERSION_RE.search(value)
        if match and "php" in value.lower():
            version = ".".join(match.groups())
            return version, f"Detected from {header} response header (HTTP {status})", {
                "php_detected": True, "signals": signals, "http_status": status,
                "server": headers.get("Server", ""),
            }

    cookie = headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookie:
        signals.append("Cookie: PHPSESSID")
    php_detected = bool(signals)
    detail = f"HTTP {status}; PHP may be present but version is not exposed" if php_detected else f"HTTP {status}; no PHP version/presence signal in response headers"
    return None, detail, {
        "php_detected": php_detected, "signals": signals, "http_status": status,
        "server": headers.get("Server", ""),
    }


def detect_local_php(php_bin="php"):
    """Read the local PHP CLI runtime version; no network activity."""
    binary = shutil.which(php_bin)
    if not binary:
        return None, f"PHP binary '{php_bin}' not found in PATH"
    try:
        proc = subprocess.run(
            [binary, "-r", "echo PHP_VERSION, '|', PHP_SAPI;"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if proc.returncode != 0:
            return None, (proc.stderr.strip() or f"php exited with code {proc.returncode}")
        parts = proc.stdout.strip().split("|", 1)
        version = parts[0] if parts else ""
        sapi = parts[1] if len(parts) > 1 else "unknown"
        if not VERSION_RE.search(version):
            return None, "Local PHP ran but returned an unrecognized version"
        return version, f"Local CLI runtime; SAPI={sapi}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"Local PHP check failed: {exc}"


def parse_txt(path):
    rows = []
    with path.open("r", encoding="utf-8-sig") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower() in {"asset,php_version", "asset php_version"}:
                continue

            if "," in line:
                parts = [part.strip() for part in line.split(",", 1)]
            elif "\t" in line:
                parts = [part.strip() for part in line.split("\t", 1)]
            else:
                parts = line.split(None, 1)

            rows.append({
                "asset": parts[0],
                "php_version": parts[1] if len(parts) > 1 else "",
            })
    return rows


def read_inventory(path):
    if path.suffix.lower() == ".txt":
        return parse_txt(path)

    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not {"asset", "php_version"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain columns: asset,php_version")
        return list(reader)


def print_results(rows, auto_detect, insecure=False):
    print("\nPHP CVE VERSION CHECK")
    print("=" * 72)

    for row in rows:
        asset = (row.get("asset") or "").strip()
        version = (row.get("php_version") or "").strip()

        if auto_detect and not version:
            print(f"\nAsset   : {asset}")
            detected, detail, meta = detect_php_version(asset, insecure=insecure)
            version = detected or ""
            print(f"Detection: {detail}")
            if meta.get("signals"):
                print("Signals  : " + "; ".join(meta["signals"]))
        else:
            detected = version or None

        status, reason = assess_php_version(version)
        print(f"Asset   : {asset or '(asset not specified)'}")
        print(f"PHP     : {version or 'unknown'}")
        print(f"Status  : {status}")
        print(f"Reason  : {reason}")
        print(f"CVEs    : {', '.join(CVES)}")

    print("\n" + "=" * 72)
    print(f"Total assets checked: {len(rows)}")
    print("HTTP fingerprinting is best-effort; hidden headers result in UNKNOWN.")
    print("Version status is not proof of exploitability; verify vendor patches.")


def save_csv(rows, output_path, auto_detect, insecure=False):
    fields = ["asset", "php_version", "cve", "status", "reason"]
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            asset = (row.get("asset") or "").strip()
            version = (row.get("php_version") or "").strip()
            if auto_detect and not version:
                version, _, _meta = detect_php_version(asset, insecure=insecure)
                version = version or ""
            status, reason = assess_php_version(version)
            for cve in CVES:
                writer.writerow({
                    "asset": asset,
                    "php_version": version,
                    "cve": cve,
                    "status": status,
                    "reason": reason,
                })


def main():
    parser = argparse.ArgumentParser(
        prog="php2shell_checker.py",
        description=("PHP CVE version checker for CVE-2026-109618 and CVE-2026-109619."),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # Show this help
  python php2shell_checker.py -h

  # Check local PHP CLI runtime (no network)
  python php2shell_checker.py --local

  # Check one domain; attempt to detect PHP version from HTTP headers
  python php2shell_checker.py --asset https://example.com

  # Check one IP address (HTTP)
  python php2shell_checker.py --asset http://192.0.2.10

  # Check one IP address (HTTPS; ignore certificate validation errors)
  python php2shell_checker.py --asset https://192.0.2.10 --insecure

  # Check one asset using a known PHP version
  python php2shell_checker.py --asset https://example.com --version 8.2.34

  # Detect versions for assets listed in a TXT file
  python php2shell_checker.py assets.txt --detect

  # Ignore HTTPS certificate errors during detection (authorized testing only)
  python php2shell_checker.py assets.txt --detect --insecure

  # Read a CSV inventory (columns: asset,php_version)
  python php2shell_checker.py assets.csv

  # Also save results to CSV (optional)
  python php2shell_checker.py assets.txt --detect -o report.csv

TXT format (one domain or IP per line; version is optional):
  https://app.example.com
  https://192.0.2.10
  192.0.2.11,8.3.36
  legacy.example.com

Status meanings:
  VULNERABLE      Version is below the configured threshold, or PHP 8.1 and older
                  are classified as vulnerable by the configured policy.
  NOT VULNERABLE  Version meets the configured threshold; vendor patch status
                  is not verified.
  UNKNOWN         Version could not be identified or branch is not covered.

Safety: remote scan sends one ordinary GET to each supplied URL only. No POST/load probes,
port scan, subdomain expansion, phpinfo-path guessing, or CDN/WAF bypass.""",
    )
    parser.add_argument("input", nargs="?", help="Inventory .txt or .csv file")
    parser.add_argument("--asset", help="Single authorized URL or hostname")
    parser.add_argument("--local", action="store_true", help="Check the local PHP CLI runtime (no network requests)")
    parser.add_argument("--php-bin", default="php", help="PHP executable name/path for --local (default: php)")
    parser.add_argument("--version", help="Known PHP version; skips HTTP detection")
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Attempt HTTP header fingerprinting for assets with no supplied version",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Ignore HTTPS certificate validation errors for HTTP detection only. "
            "Use only on authorized assets; TLS identity will not be verified."
        ),
    )
    parser.add_argument("-o", "--output", help="Optional CSV report; no CSV is created by default")
    args = parser.parse_args()

    if args.local:
        version, detail = detect_local_php(args.php_bin)
        status, reason = assess_php_version(version or "")
        print("PHP CVE VERSION CHECK — LOCAL")
        print(f"PHP     : {version or 'unknown'}")
        print(f"Source  : {detail}")
        print(f"Status  : {status}")
        print(f"Reason  : {reason}")
        print(f"CVEs    : {', '.join(CVES)}")
        print("Note    : local CLI PHP may differ from PHP-FPM/Apache/container runtimes.")
        if args.output:
            save_csv([{"asset": "LOCAL", "php_version": version or ""}], Path(args.output), False)
            print(f"CSV report saved to: {Path(args.output).resolve()}")
        return 0

    if args.asset:
        rows = [{"asset": args.asset, "php_version": args.version or ""}]
    else:
        if not args.input:
            parser.error("provide an inventory file or use --asset")
        path = Path(args.input)
        if not path.is_file():
            print(f"Error: input file not found: {path}", file=sys.stderr)
            return 2
        try:
            rows = read_inventory(path)
        except (OSError, csv.Error, ValueError) as exc:
            print(f"Error reading inventory: {exc}", file=sys.stderr)
            return 2

    if not rows:
        print("Error: no assets found.", file=sys.stderr)
        return 2

    auto_detect = args.detect or (args.asset is not None and not args.version)
    print_results(rows, auto_detect, insecure=args.insecure)

    if args.output:
        try:
            save_csv(rows, Path(args.output), auto_detect, insecure=args.insecure)
            print(f"\nCSV report saved to: {Path(args.output).resolve()}")
        except OSError as exc:
            print(f"Error writing CSV: {exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
