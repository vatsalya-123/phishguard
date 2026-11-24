import pandas as pd
from collections import Counter

DATA_PATH = "data/processed/with_domains.csv"

df = pd.read_csv(DATA_PATH)
df = df.dropna(subset=["ClassLabel"]).copy()

def create_group(row):
    registered_domain = row["reg_domain"]

    if pd.notna(registered_domain):
        registered_domain = str(registered_domain).strip().lower()
    else:
        registered_domain = ""

    if registered_domain:
        return registered_domain

    from urllib.parse import urlsplit

    url = str(row["URL"])

    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        hostname = None

    if hostname:
        return hostname.lower()

    return "NO_HOST:" + url


df["group"] = df.apply(create_group, axis=1)

print("=" * 60)
print("PHISHGUARD - GROUP STRUCTURE AUDIT")
print("=" * 60)

print("\nTOTAL RECORDS:", len(df))
print("UNIQUE GROUPS:", df["group"].nunique())

group_sizes = df.groupby("group").size()

print("\nGROUP SIZE DISTRIBUTION:")
print(group_sizes.describe())

print("\nLARGEST GROUPS:")
print(group_sizes.sort_values(ascending=False).head(15))

group_label_counts = (
    df.groupby("group")["ClassLabel"]
    .nunique()
)

mixed_groups = group_label_counts[group_label_counts > 1]

print("\nGROUPS CONTAINING BOTH LABELS:", len(mixed_groups))
print("\nMIXED-LABEL GROUP DETAILS:")

if len(mixed_groups) > 0:
    mixed_details = (
        df[df["group"].isin(mixed_groups.index)]
        .groupby(["group", "ClassLabel"])
        .size()
        .unstack(fill_value=0)
    )

    print(mixed_details)
else:
    print("No mixed-label groups found.")

print("\nLABEL DISTRIBUTION ACROSS GROUPS:")
print(df.groupby("ClassLabel")["group"].nunique())

print("\nGROUP STRUCTURE AUDIT COMPLETED.")