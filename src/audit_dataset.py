
from pathlib import Path

import pandas as pd
import tldextract

from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.tree import DecisionTreeClassifier


# --------------------------------------------------
# 1. Configuration
# --------------------------------------------------

INPUT_PATH = Path(
    "data/raw/legitphish_v2/url_features_extracted1.csv"
)

OUTPUT_PATH = Path("data/processed/with_domains.csv")

LABEL_COL = "ClassLabel"
URL_COL = "URL"


# --------------------------------------------------
# 2. Load and validate dataset
# --------------------------------------------------

df = pd.read_csv(INPUT_PATH)

required_columns = {URL_COL, LABEL_COL}

if not required_columns.issubset(df.columns):
    raise ValueError("Required URL or ClassLabel column is missing.")

print("=" * 60)
print("PHISHGUARD - DAY 3 DATASET AUDIT")
print("=" * 60)

print("\n== 1. DATASET OVERVIEW ==")
print("Shape:", df.shape)

print("\nLabel distribution:")
print(df[LABEL_COL].value_counts(dropna=False).sort_index())

print("\nMissing values:")
missing = df.isna().sum()
print(missing[missing > 0])


# --------------------------------------------------
# 3. Label and duplicate inspection
# --------------------------------------------------

print("\n== 2. DUPLICATE INSPECTION ==")

print("Duplicate URL occurrences:", df[URL_COL].duplicated().sum())

duplicated_urls = df.loc[
    df[URL_COL].duplicated(keep=False), URL_COL
].unique()

duplicate_groups = df[df[URL_COL].isin(duplicated_urls)]

label_counts = (
    duplicate_groups.groupby(URL_COL, dropna=False)[LABEL_COL]
    .nunique(dropna=False)
)

print("Unique duplicated URL groups:", len(label_counts))
print("Groups with conflicting labels:", (label_counts > 1).sum())
print("Groups with consistent labels:", (label_counts == 1).sum())

# --------------------------------------------------
# 4. Suspicious URL patterns by class
# --------------------------------------------------

print("\n== 3. SUSPICIOUS URL PATTERNS ==")

urls = df[URL_COL].fillna("").astype(str)

valid_labels = df[LABEL_COL].isin([0, 1])

pattern_flags = {
    "explicit_port": urls.str.contains(
        r"^\w+://[^/?#]*:\d+", regex=True
    ),
    "double_scheme": urls.str.contains(
        r"^https?://https?://", case=False, regex=True
    ),
    "ends_exe": urls.str.lower().str.endswith(".exe"),
    "https": urls.str.startswith("https://"),
}

for name, mask in pattern_flags.items():
    print(f"\n{name}")

    counts = pd.crosstab(
        df.loc[valid_labels, LABEL_COL],
        mask.loc[valid_labels]
    )

    print("Counts:")
    print(counts)

    rates = (
        mask.loc[valid_labels]
        .groupby(df.loc[valid_labels, LABEL_COL])
        .mean()
    )

    print("Share within each class:")
    print(rates.round(4))


# --------------------------------------------------
# 5. Registered-domain extraction
# --------------------------------------------------

print("\n== 4. REGISTERED DOMAIN EXTRACTION ==")

extractor = tldextract.TLDExtract(suffix_list_urls=())

def extract_registered_domain(url):
    if not url:
        return ""

    result = extractor(url)

    return result.top_domain_under_public_suffix or ""


df["reg_domain"] = urls.map(extract_registered_domain)

empty_domains = df["reg_domain"].eq("")

print("Records without registered domains:", empty_domains.sum())
print("Records with registered domains:", (~empty_domains).sum())

for label_value in [0, 1]:
    class_mask = df[LABEL_COL].eq(label_value)

    class_domains = df.loc[class_mask, "reg_domain"]
    valid_domains = class_domains[class_domains.ne("")]

    counts = valid_domains.value_counts()

    print(f"\nClass {label_value}:")
    print("Rows:", class_mask.sum())
    print("Rows with valid registered domains:", len(valid_domains))
    print("Unique registered domains:", len(counts))
    print("Rows without registered domains:",
          class_domains.eq("").sum())

    if len(valid_domains) > 0:
        top_10_share = counts.head(10).sum() / len(valid_domains)
        print("Top-10 domain share:", round(top_10_share, 4))
        print("Top 10 domains:")
        print(counts.head(10))


# --------------------------------------------------
# 6. Single-feature ROC-AUC
# --------------------------------------------------

print("\n== 5. SINGLE-FEATURE PREDICTIVE STRENGTH ==")

labeled_df = df[df[LABEL_COL].isin([0, 1])].copy()

numeric_features = [
    col
    for col in labeled_df.select_dtypes(include="number").columns
    if col != LABEL_COL
]

X = labeled_df[numeric_features].fillna(-1)
y = labeled_df[LABEL_COL].astype(int)

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=0
)

results = {}

for feature in numeric_features:
    model = DecisionTreeClassifier(
        max_depth=3,
        random_state=0
    )

    scores = cross_val_score(
        model,
        X[[feature]],
        y,
        cv=cv,
        scoring="roc_auc"
    )

    results[feature] = scores.mean()

print("\nMean 5-fold ROC-AUC (positive class = legitimate, label 1):")
print(
    pd.Series(results)
    .sort_values(ascending=False)
    .round(4)
)


# --------------------------------------------------
# 7. Save processed dataset
# --------------------------------------------------

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

df.to_csv(OUTPUT_PATH, index=False)

print("\n== 6. OUTPUT ==")
print("Saved:", OUTPUT_PATH)
print("Saved shape:", df.shape)

print("\nOriginal raw dataset was not modified.")
print("AUDIT COMPLETED.")
