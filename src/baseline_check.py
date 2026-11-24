from urllib.parse import urlsplit
from pathlib import Path

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix


# --------------------------------------------------
# 1. Configuration
# --------------------------------------------------

INPUT_PATH = Path("data/processed/with_domains.csv")

LABEL_COL = "ClassLabel"

SUSPECT_FEATURES = [
    "tld_popularity",
    "tld_length",
    "domain_name_length",
    "subdomain_count",
    "suspicious_file_extension",
]


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

df = pd.read_csv(INPUT_PATH)

# Keep only records with valid binary labels.
df = df[df[LABEL_COL].isin([0, 1])].copy()

df[LABEL_COL] = df[LABEL_COL].astype(int)

# Numeric features only. Exclude target and grouping column.
all_features = [
    col
    for col in df.select_dtypes(include="number").columns
    if col != LABEL_COL
]

reduced_features = [
    col for col in all_features
    if col not in SUSPECT_FEATURES
]

X_all = df[all_features].fillna(-1)
X_reduced = df[reduced_features].fillna(-1)

y = df[LABEL_COL]

print("=" * 65)
print("PHISHGUARD - DAY 3 BASELINE COMPARISON")
print("=" * 65)

print("\nDataset rows:", len(df))
print("Feature count (A and B):", len(all_features))
print("Feature count (C):", len(reduced_features))
print("Label distribution:")
print(y.value_counts().sort_index())

print("\nExcluded features in experiment C:")
print(SUSPECT_FEATURES)


# --------------------------------------------------
# 3. Model and evaluation function
# --------------------------------------------------

def create_model():
    return RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )


def evaluate_experiment(name, X_train, X_test, y_train, y_test):
    model = create_model()

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    # Phishing is class 0, so explicitly set pos_label=0.
    phishing_recall = recall_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    )

    print("\n" + "=" * 65)
    print(name)
    print("=" * 65)

    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))

    print("\nTest label distribution:")
    print(y_test.value_counts().sort_index())

    print("\nAccuracy:", round(accuracy, 4))
    print("Phishing recall:", round(phishing_recall, 4))

    print("\nConfusion matrix (labels [0, 1]):")
    print(matrix)

    print("\nMatrix interpretation:")
    print("Rows = actual labels [phishing, legitimate]")
    print("Columns = predicted labels [phishing, legitimate]")

    return {
        "experiment": name,
        "accuracy": accuracy,
        "phishing_recall": phishing_recall,
    }


# --------------------------------------------------
# 4. Experiment A: Random stratified split
# --------------------------------------------------

print("\n\nEXPERIMENT A: RANDOM STRATIFIED SPLIT")

X_train_A, X_test_A, y_train_A, y_test_A = train_test_split(
    X_all,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

result_A = evaluate_experiment(
    "A - Random split, all features",
    X_train_A,
    X_test_A,
    y_train_A,
    y_test_A
)



# --------------------------------------------------
# 5. Prepare hostname/domain grouping
# --------------------------------------------------

def create_group(row):
    registered_domain = row["reg_domain"]

    if pd.notna(registered_domain):
        registered_domain = str(registered_domain).strip().lower()
    else:
        registered_domain = ""

    if registered_domain:
        return registered_domain

    url = str(row["URL"])

    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        hostname = None

    if hostname:
        return hostname.lower()

    return "NO_HOST:" + url

groups = df.apply(create_group, axis=1)

print("\n\nDOMAIN/HOSTNAME GROUPING CHECK")
print("Unique groups:", groups.nunique())
print("Rows without registered domains:",
      df["reg_domain"].fillna("").eq("").sum())
print("Grouping method:")
print("1. Registered domain where available")
print("2. Hostname, including IP addresses, otherwise")
print("3. Full URL only when hostname is unavailable")


# --------------------------------------------------
# 6. Create one domain-grouped split
# --------------------------------------------------

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X_all, y, groups=groups)
)

y_train_group = y.iloc[train_indices]
y_test_group = y.iloc[test_indices]

# Verify both classes are present in both partitions.
for partition_name, labels in [
    ("Training", y_train_group),
    ("Testing", y_test_group),
]:
    if set(labels.unique()) != {0, 1}:
        raise ValueError(
            f"{partition_name} partition does not contain both classes. "
            "Do not interpret grouped baseline metrics."
        )

train_groups = set(groups.iloc[train_indices])
test_groups = set(groups.iloc[test_indices])

overlap = train_groups.intersection(test_groups)

print("\nGrouped split validation:")
print("Training groups:", len(train_groups))
print("Testing groups:", len(test_groups))
print("Overlapping groups:", len(overlap))

if overlap:
    raise ValueError("Domain leakage detected in grouped split.")


# --------------------------------------------------
# 7. Experiment B: Grouped split, all features
# --------------------------------------------------

print("\n\nEXPERIMENT B: DOMAIN-GROUPED SPLIT")

result_B = evaluate_experiment(
    "B - Domain-grouped split, all features",
    X_all.iloc[train_indices],
    X_all.iloc[test_indices],
    y_train_group,
    y_test_group
)


# --------------------------------------------------
# 8. Experiment C: Grouped split, reduced features
# --------------------------------------------------

print("\n\nEXPERIMENT C: DOMAIN-GROUPED SPLIT, REDUCED FEATURES")

result_C = evaluate_experiment(
    "C - Domain-grouped split, reduced features",
    X_reduced.iloc[train_indices],
    X_reduced.iloc[test_indices],
    y_train_group,
    y_test_group
)


# --------------------------------------------------
# 9. Final comparison
# --------------------------------------------------

print("\n\n" + "=" * 65)
print("FINAL BASELINE COMPARISON")
print("=" * 65)

comparison = pd.DataFrame(
    [result_A, result_B, result_C]
)

print(
    comparison.to_string(
        index=False,
        formatters={
            "accuracy": "{:.4f}".format,
            "phishing_recall": "{:.4f}".format,
        }
    )
)

print("\nBaseline experiments completed.")
print("No source dataset rows or labels were modified.")
