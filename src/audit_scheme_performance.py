import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from src.url_features import extract, FEATURES
from src.audit_cross_dataset_overlap import get_domain


def main():
    train = pd.read_csv("data/processed/legitphish_clean.csv")
    test = pd.read_csv(
        "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
        usecols=["URL", "label"]
    )

    train = train.dropna(subset=["URL", "ClassLabel"]).copy()
    test = test.dropna(subset=["URL", "label"]).copy()

    train = train.drop_duplicates(subset=["URL"]).copy()
    test = test.drop_duplicates(subset=["URL"]).copy()

    train["ClassLabel"] = train["ClassLabel"].astype(int)
    test["label"] = test["label"].astype(int)

    test, _ = train_test_split(
        test,
        train_size=60000,
        random_state=0,
        stratify=test["label"]
    )

    train["domain"] = train["URL"].map(get_domain)
    test["domain"] = test["URL"].map(get_domain)

    train_domains = set(train["domain"]) - {""}
    test = test[~test["domain"].isin(train_domains)].copy()

    print("Extracting features...")
    X_train = pd.DataFrame(
        [extract(url) for url in train["URL"]],
        columns=FEATURES,
        index=train.index
    )

    X_test = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        columns=FEATURES,
        index=test.index
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, train["ClassLabel"])

    phishing_index = list(model.classes_).index(0)
    probabilities = model.predict_proba(X_test)[:, phishing_index]
    predictions = model.predict(X_test)

    external = test[["URL", "label"]].copy()
    external["is_https"] = X_test["is_https"]
    external["phishing_probability"] = probabilities
    external["predicted_phishing"] = (predictions == 0).astype(int)

    print("\nTRAINING DATA: LABEL BY SCHEME")
    print("=" * 70)
    print(pd.crosstab(
        X_train["is_https"],
        train["ClassLabel"],
        margins=True
    ).to_string())

    print("\nEXTERNAL DATA: LABEL BY SCHEME")
    print("=" * 70)
    print(pd.crosstab(
        external["is_https"],
        external["label"],
        margins=True
    ).to_string())

    print("\nEXTERNAL MODEL PERFORMANCE BY SCHEME")
    print("=" * 70)

    for scheme, group in external.groupby("is_https"):
        scheme_name = "HTTPS" if scheme == 1 else "HTTP"

        print(f"\n{scheme_name}")
        print("-" * 60)

        print("Records:", len(group))

        for label, class_name in [(0, "Phishing"), (1, "Legitimate")]:
            subset = group[group["label"] == label]

            if len(subset) == 0:
                print(f"{class_name}: no records")
                continue

            detected = subset["predicted_phishing"].sum()

            print(f"{class_name} records:", len(subset))
            print(
                f"{class_name} predicted as phishing:",
                int(detected)
            )

            if label == 0:
                print(
                    "Phishing detection rate:",
                    round(detected / len(subset), 4)
                )
            else:
                print(
                    "False positive rate:",
                    round(detected / len(subset), 4)
                )

            print(
                "Mean phishing probability:",
                round(subset["phishing_probability"].mean(), 4)
            )


if __name__ == "__main__":
    main()
