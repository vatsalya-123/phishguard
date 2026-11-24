from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
from ipaddress import ip_address

import tldextract

INPUT_FILE = Path("data/raw/phishing_database_active.txt")

extractor = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)

stats = Counter()

with INPUT_FILE.open(
    "r", encoding="utf-8", errors="replace"
) as file:
    for line in file:
        url = line.strip()

        if not url:
            stats["blank"] += 1
            continue

        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()

            if scheme not in {"http", "https"}:
                stats["unsupported_scheme"] += 1
                continue

            hostname = parsed.hostname

            if not hostname:
                stats["missing_hostname"] += 1
                continue

            hostname = hostname.lower().rstrip(".")

            try:
                ip_address(hostname)
                stats["ip_address_hosts"] += 1
            except ValueError:
                stats["non_ip_hosts"] += 1

            stats["http_https_with_hostname"] += 1

            domain = extractor(hostname).top_domain_under_public_suffix

            if domain:
                stats["with_registered_domain"] += 1
            else:
                stats["without_registered_domain"] += 1

        except (ValueError, UnicodeError):
            stats["parsing_errors"] += 1

print("\nPHISHING URL VALIDATION")
print("=" * 45)

for key, value in stats.items():
    print(f"{key}: {value:,}")

print("\nValidation completed. No URLs were visited.")
