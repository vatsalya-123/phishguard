from pathlib import Path
from collections import Counter
from urllib.parse import urlsplit
import ipaddress

import pandas as pd
import tldextract


RAW_FILE = Path("data/raw/phishing_database_active.txt")
OUTPUT_FILE = Path("data/processed/phishing_url_candidates.csv")

SOURCE_NAME = "Phishing.Database"
CANDIDATE_LABEL = 1


def main():
    if not RAW_FILE.exists():
        raise FileNotFoundError(f"Raw dataset not found: {RAW_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    extractor = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )

    records = []
    excluded_schemes = Counter()
    missing_hostnames = 0
    parsing_errors = 0

    with RAW_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            url = line.strip()

            if not url:
                continue

            try:
                parsed = urlsplit(url)
                scheme = parsed.scheme.lower()

                if scheme not in {"http", "https"}:
                    excluded_schemes[scheme] += 1
                    continue

                hostname = parsed.hostname

                if not hostname:
                    missing_hostnames += 1
                    continue

                hostname = hostname.lower().rstrip(".")

                try:
                    ipaddress.ip_address(hostname)
                    is_ip_host = True
                    registered_domain = None
                except ValueError:
                    is_ip_host = False
                    extracted = extractor(hostname)
                    registered_domain = (
                        extracted.top_domain_under_public_suffix or None
                    )

                records.append({
                    "url": url,
                    "scheme": scheme,
                    "hostname": hostname,
                    "registered_domain": registered_domain,
                    "is_ip_host": is_ip_host,
                    "label": CANDIDATE_LABEL,
                    "source": SOURCE_NAME,
                })

            except (ValueError, UnicodeError):
                parsing_errors += 1

    if not records:
        raise ValueError("No eligible HTTP/HTTPS URL records were found.")

    df = pd.DataFrame(records)

    duplicate_urls = int(df["url"].duplicated().sum())
    missing_urls = int(df["url"].isna().sum())
    invalid_labels = int((df["label"] != CANDIDATE_LABEL).sum())

    expected_rows = 789052

    print("\nPOSITIVE URL CANDIDATE DATASET VALIDATION")
    print("----------------------------------------")
    print(f"Rows created: {len(df):,}")
    print(f"Expected rows: {expected_rows:,}")
    print(f"Duplicate URLs: {duplicate_urls:,}")
    print(f"Missing URLs: {missing_urls:,}")
    print(f"Invalid labels: {invalid_labels:,}")
    print(f"Missing hostnames skipped: {missing_hostnames:,}")
    print(f"Parsing errors skipped: {parsing_errors:,}")
    print(f"Excluded schemes: {dict(excluded_schemes)}")
    print(f"IP-address hosts: {int(df['is_ip_host'].sum()):,}")
    print(
        "Missing registered domains: "
        f"{int(df['registered_domain'].isna().sum()):,}"
    )
    print(f"Unique URLs: {df['url'].nunique():,}")
    print(f"Labels: {sorted(df['label'].unique().tolist())}")

    if len(df) != expected_rows:
        raise ValueError("Row count differs from the inspected source count.")

    if duplicate_urls or missing_urls or invalid_labels:
        raise ValueError("Dataset validation failed.")

    if df["url"].nunique() != len(df):
        raise ValueError("URL uniqueness validation failed.")

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nDataset saved to: {OUTPUT_FILE}")
    print(f"File size: {OUTPUT_FILE.stat().st_size:,} bytes")
    print("\nFirst five records:")
    print(df.head().to_string(index=False))
    print("\nNo URLs were visited.")


if __name__ == "__main__":
    main()
