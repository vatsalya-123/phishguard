import csv
from collections import Counter
from pathlib import Path

import pandas as pd
import tldextract

PHISHING_FILE = Path("data/raw/phishing_database_active.txt")
TRANCO_FILE = Path("data/raw/tranco_Q2464.csv")
OUTPUT_FILE = Path("results/overlapping_domains.csv")

extractor = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["rank", "domain"],
    dtype={"rank": "int64", "domain": "string"},
)

tranco_ranks = {
    row.domain.strip().lower(): int(row.rank)
    for row in tranco.itertuples(index=False)
    if pd.notna(row.domain)
}

counts = Counter()

with PHISHING_FILE.open(
    "r", encoding="utf-8", errors="replace"
) as file:
    for line in file:
        url = line.strip()
        if not url:
            continue

        domain = extractor(url).top_domain_under_public_suffix.lower()

        if domain:
            counts[domain] += 1

overlaps = [
    (domain, tranco_ranks[domain], count)
    for domain, count in counts.items()
    if domain in tranco_ranks
]

overlaps.sort(key=lambda item: item[2], reverse=True)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["domain", "tranco_rank", "phishing_url_count"])
    writer.writerows(overlaps)

print("Overlapping domains:", len(overlaps))
print("Detailed report:", OUTPUT_FILE)
print("\nTop 20 overlapping domains:")
print(f"{'DOMAIN':45} {'TRANCO RANK':>12} {'PHISHING URLS':>15}")

for domain, rank, count in overlaps[:20]:
    print(f"{domain:45} {rank:12,} {count:15,}")
