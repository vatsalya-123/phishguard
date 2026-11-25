import pandas as pd

from sklearn.model_selection import train_test_split
from src.url_features import extract, PATH_FEATURES
from src.audit_cross_dataset_overlap import get_domain

TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
SAMPLE_SIZE = 60000


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE, usecols=["URL", "label"])

    train = train.dropna(subset=["URL", "ClassLabel"]).copy()
    test = test.dropna(subset=["URL", "label"]).copy()

    train = train.drop_duplicates(subset=["URL"]).copy()
    test = test.drop_duplicates(subset=["URL"]).copy()

    train["ClassLabel"] = train["ClassLabel"].astype(int)
    test["label"] = test["label"].astype(int)

    test, _ = train_test_split(
        test,
        train_size=SAMPLE_SIZE,
        random_state=0,
        stratify=test["label"]
    )

    train["domain"] = train["URL"].map(get_domain)
    test["domain"] = test["URL"].map(get_domain)

    train_domains = set(train["domain"]) - {""}
    test = test[~test["domain"].isin(train_domains)].copy()

    train["Dataset"] = "LegitPhish"
    train["Label"] = train["ClassLabel"]

    test["Dataset"] = "PhiUSIIL unseen domains"
    test["Label"] = test["label"]

    combined = pd.concat([
        train[["URL", "Dataset", "Label"]],
        test[["URL", "Dataset", "Label"]]
    ], ignore_index=True)

    print("\nFEATURE DISTRIBUTION CHECK")
    print("=" * 75)

    features = pd.DataFrame(
        [extract(url) for url in combined["URL"]],
        columns=PATH_FEATURES,
        index=combined.index
    )

    combined = pd.concat([combined, features], axis=1)

    for feature in [
        "url_len", "path_len", "path_depth",
        "query_len", "num_params", "url_entropy", "is_https"
    ]:
        print(f"\n{feature}")
        print("-" * 75)

        stats = combined.groupby(["Dataset", "Label"])[feature].agg(
            zero_count=lambda x: (x == 0).sum(),
            nonzero_percent=lambda x: (x != 0).mean() * 100,
            minimum="min",
            q25=lambda x: x.quantile(0.25),
            median="median",
            q75=lambda x: x.quantile(0.75),
            maximum="max"
        )

        print(stats.round(3).to_string())

    print("\n\nACTUAL URL EXAMPLES")
    print("=" * 75)

    for (dataset, label), group in combined.groupby(["Dataset", "Label"]):
        print(f"\n{dataset} | Label {label}")
        print("-" * 75)

        print("\nURLs with zero path length:")
        zero_rows = group[group["path_len"] == 0].head(8)

        if zero_rows.empty:
            print("None")
        else:
            for url in zero_rows["URL"]:
                print(url)

        print("\nURLs with nonzero path length:")
        nonzero_rows = group[group["path_len"] > 0].head(8)

        if nonzero_rows.empty:
            print("None")
        else:
            for url in nonzero_rows["URL"]:
                print(url)


if __name__ == "__main__":
    main()
