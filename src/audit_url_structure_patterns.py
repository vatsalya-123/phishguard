import pandas as pd
from urllib.parse import urlsplit
from sklearn.model_selection import train_test_split

from src.url_features import extract, PATH_FEATURES
from src.audit_cross_dataset_overlap import get_domain


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
SAMPLE_SIZE = 60000


def prepare_data():
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

    return pd.concat([
        train[["URL", "Dataset", "Label"]],
        test[["URL", "Dataset", "Label"]]
    ], ignore_index=True)


def main():
    data = prepare_data()

    print("Extracting URL features...")
    features = pd.DataFrame(
        [extract(url) for url in data["URL"]],
        columns=PATH_FEATURES,
        index=data.index
    )

    data = pd.concat([data, features], axis=1)

    for (dataset, label), group in data.groupby(["Dataset", "Label"]):
        print("\n" + "=" * 75)
        print(f"DATASET: {dataset} | LABEL: {label}")
        print("=" * 75)

        total = len(group)

        for feature in ["path_len", "path_depth", "query_len"]:
            zero_count = int((group[feature] == 0).sum())
            nonzero_count = total - zero_count

            print(
                f"{feature}: zero={zero_count} "
                f"({zero_count / total:.2%}), "
                f"nonzero={nonzero_count} "
                f"({nonzero_count / total:.2%})"
            )

        for condition, subset in [
            ("ZERO PATH LENGTH", group[group["path_len"] == 0]),
            ("NONZERO PATH LENGTH", group[group["path_len"] > 0])
        ]:
            print(f"\n{condition} — sample URLs")

            if subset.empty:
                print("No records")
                continue

            for url in subset["URL"].sample(
                n=min(8, len(subset)),
                random_state=42
            ):
                parsed = urlsplit(url)
                print(f"URL: {url}")
                print(
                    f"  scheme={parsed.scheme!r}, "
                    f"host={parsed.netloc!r}, "
                    f"path={parsed.path!r}, "
                    f"query={parsed.query!r}"
                )


if __name__ == "__main__":
    main()
