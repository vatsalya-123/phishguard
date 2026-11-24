from pathlib import Path

import pandas as pd

TRANCO_FILE = Path("data/raw/tranco_Q2464.csv")
OVERLAP_FILE = Path("results/overlapping_domains.csv")
OUTPUT_FILE = Path("data/processed/tranco_negative_candidates.csv")

print("Loading Tranco dataset...")

tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["tranco_rank", "domain"],
    dtype={"tranco_rank": "int64", "domain": "string"},
)

print("Loading overlapping domains...")

overlaps = pd.read_csv(
    OVERLAP_FILE,
    dtype={"domain": "string"},
)

tranco["domain"] = tranco["domain"].str.strip().str.lower().str.rstrip(".")
overlaps["domain"] = overlaps["domain"].str.strip().str.lower().str.rstrip(".")

overlap_domains = set(overlaps["domain"].dropna())

print("Filtering overlapping domains...")

filtered = tranco[
    ~tranco["domain"].isin(overlap_domains)
].copy()

filtered["label"] = 0

filtered = filtered[
    ["domain", "tranco_rank", "label"]
]

if filtered["domain"].duplicated().any():
    raise ValueError("Duplicate domains found in filtered dataset.")

if filtered["domain"].isin(overlap_domains).any():
    raise ValueError("Overlapping domains remain in filtered dataset.")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
filtered.to_csv(OUTPUT_FILE, index=False)

print("\nNEGATIVE CANDIDATE DATASET")
print("=" * 40)
print(f"Original Tranco domains: {len(tranco):,}")
print(f"Excluded overlapping domains: {len(overlap_domains):,}")
print(f"Remaining negative candidates: {len(filtered):,}")
print(f"Output file: {OUTPUT_FILE}")
print(f"Columns: {', '.join(filtered.columns)}")
print("\nFirst 5 records:")
print(filtered.head().to_string(index=False))
