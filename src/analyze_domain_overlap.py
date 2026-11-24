import json
from collections import Counter
from pathlib import Path

import pandas as pd
import tldextract

PHISHING_FILE = Path("data/raw/phishing_database_active.txt")
TRANCO_FILE = Path("data/raw/tranco_Q2464.csv")
OUTPUT_FILE = Path("results/domain_overlap_summary.json")

# Use the bundled Public Suffix List. No network requests.
extractor = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

print("Loading Tranco domains...")
tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["rank", "domain"],
    dtype={"rank": "int64", "domain": "string"},
)

tranco_domains = {
    domain.strip().lower().rstrip(".")
    for domain in tranco["domain"].dropna()
    if domain.strip()
}

print(f"Tranco domains loaded: {len(tranco_domains):,}")

print("Extracting registered domains from phishing URLs...")

phishing_domain_counts = Counter()
total_urls = 0
urls_without_registered_domain = 0

with PHISHING_FILE.open(
    "r", encoding="utf-8", errors="replace"
) as file:
    for line in file:
        url = line.strip()
        if not url:
            continue

        total_urls += 1
        extracted = extractor(url)
        registered_domain = (
            extracted.top_domain_under_public_suffix.lower().rstrip(".")
        )

        if registered_domain:
            phishing_domain_counts[registered_domain] += 1
        else:
            urls_without_registered_domain += 1

        if total_urls % 100000 == 0:
            print(f"Processed {total_urls:,} phishing URLs...")

phishing_domains = set(phishing_domain_counts)

overlapping_domains = phishing_domains & tranco_domains
overlapping_urls = sum(
    phishing_domain_counts[domain]
    for domain in overlapping_domains
)

summary = {
    "tranco_snapshot": "Q2464",
    "tranco_domains": len(tranco_domains),
    "phishing_urls_processed": total_urls,
    "phishing_urls_with_registered_domain": (
        total_urls - urls_without_registered_domain
    ),
    "phishing_urls_without_registered_domain": (
        urls_without_registered_domain
    ),
    "unique_phishing_registered_domains": len(phishing_domains),
    "overlapping_domains": len(overlapping_domains),
    "phishing_urls_on_overlapping_domains": overlapping_urls,
    "phishing_urls_on_non_overlapping_domains": (
        total_urls - urls_without_registered_domain - overlapping_urls
    ),
}

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(
    json.dumps(summary, indent=4),
    encoding="utf-8",
)

print("\nDOMAIN OVERLAP RESULTS")
print("=" * 45)

for key, value in summary.items():
    print(f"{key}: {value:,}" if isinstance(value, int) else f"{key}: {value}")

print(f"\nSummary saved to: {OUTPUT_FILE}")
