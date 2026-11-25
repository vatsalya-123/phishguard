import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from src.url_features import (
    extract,
    FEATURES,
    HOST_FEATURES,
    PATH_FEATURES,
    normalize,
)
from src.audit_cross_dataset_overlap import get_domain


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"

SAMPLE_SIZE = 60000
TOP_FEATURES = ["path_len", "path_depth", "is_https"]


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE, usecols=["URL", "label"])

    train = train.dropna(subset=["URL", "ClassLabel"]).copy()
    test = test.dropna(subset=["URL", "label"]).copy()

    train = train.drop_duplicates(subset=["URL"]).copy()
    test = test.drop_duplicates(subset=["URL"]).copy()

    train["ClassLabel"] = train["ClassLabel"].astype(int)
    test["label"] = test["label"].astype(int)

    train["normalized"] = train["URL"].map(normalize)
    train["domain"] = train["URL"].map(get_domain)

    test["normalized"] = test["URL"].map(normalize)
    test["domain"] = test["URL"].map(get_domain)

    test, _ = train_test_split(
        test,
        train_size=SAMPLE_SIZE,
        random_state=0,
        stratify=test["label"]
    )

    train_domains = set(train["domain"]) - {""}

    domain_disjoint = test[
        ~test["domain"].isin(train_domains)
    ].copy()

    print("Extracting external test features...")

    X_test = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        index=test.index,
        columns=FEATURES
    )

    evaluations = {
        "Original sample": test,
        "Domain-disjoint sample": domain_disjoint,
    }

    feature_sets = {
        "All 22 features": FEATURES,
        "Host features only": HOST_FEATURES,
        "URL/path features only": PATH_FEATURES,
        "All except top 3 features": [
            f for f in FEATURES if f not in TOP_FEATURES
        ],
    }

    for feature_name, columns in feature_sets.items():
        print("\n" + "=" * 65)
        print(feature_name)
        print("Number of features:", len(columns))
        print("=" * 65)

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1
        )

        model.fit(train[columns], train["ClassLabel"])

        phishing_index = list(model.classes_).index(0)

        for evaluation_name, subset in evaluations.items():
            X = X_test.loc[subset.index, columns]
            y = subset["label"]

            predictions = model.predict(X)
            probabilities = model.predict_proba(X)[:, phishing_index]

            print("\n---", evaluation_name, "---")
            print("Records:", len(subset))
            print("Class distribution:")
            print(y.value_counts().sort_index().to_dict())

            print("Accuracy:", round(
                accuracy_score(y, predictions), 4
            ))
            print("Balanced accuracy:", round(
                balanced_accuracy_score(y, predictions), 4
            ))
            print("Phishing ROC-AUC:", round(
                roc_auc_score((y == 0).astype(int), probabilities), 4
            ))

            print("\nClassification report:")
            print(classification_report(
                y,
                predictions,
                labels=[0, 1],
                target_names=["Phishing", "Legitimate"],
                digits=4,
                zero_division=0
            ))

            print("Confusion matrix:")
            print(confusion_matrix(y, predictions, labels=[0, 1]))


if __name__ == "__main__":
    main()
