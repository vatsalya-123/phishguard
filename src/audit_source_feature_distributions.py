import pandas as pd
from sklearn.model_selection import train_test_split

from src.url_features import extract, PATH_FEATURES, normalize
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

    test = test[
        ~test["domain"].isin(train_domains)
    ].copy()

    print("Extracting training features...")
    train_features = pd.DataFrame(
        [extract(url) for url in train["URL"]],
        index=train.index,
        columns=PATH_FEATURES
    )

    print("Extracting external features...")
    test_features = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        index=test.index,
        columns=PATH_FEATURES
    )

    train_data = train_features.copy()
    train_data["Dataset"] = "LegitPhish"
    train_data["Label"] = train["ClassLabel"]

    test_data = test_features.copy()
    test_data["Dataset"] = "PhiUSIIL unseen domains"
    test_data["Label"] = test["label"]

    combined = pd.concat([train_data, test_data])

    print("\nGROUP SIZES")
    print("=" * 60)
    print(combined.groupby(["Dataset", "Label"]).size().to_string())

    for feature in PATH_FEATURES:
        print("\n" + "=" * 60)
        print("FEATURE:", feature)
        print("=" * 60)

        summary = combined.groupby(
            ["Dataset", "Label"]
        )[feature].agg(
            ["count", "mean", "median", "std"]
        )

        print(summary.round(4).to_string())


if __name__ == "__main__":
    main()
