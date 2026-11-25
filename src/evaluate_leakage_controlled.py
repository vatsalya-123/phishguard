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

from src.url_features import extract, FEATURES, HOST_FEATURES, normalize
from src.audit_cross_dataset_overlap import get_domain


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"

SAMPLE_SIZE = 60000
SAMPLE_RANDOM_STATE = 0
MODEL_RANDOM_STATE = 42


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE, usecols=["URL", "label"])

    train = train.dropna(subset=["URL", "ClassLabel"]).copy()
    test = test.dropna(subset=["URL", "label"]).copy()

    train = train.drop_duplicates(subset=["URL"]).copy()
    test = test.drop_duplicates(subset=["URL"]).copy()

    train["ClassLabel"] = train["ClassLabel"].astype(int)
    test["label"] = test["label"].astype(int)

    if set(train["ClassLabel"].unique()) != {0, 1}:
        raise ValueError("Unexpected training labels.")

    if set(test["label"].unique()) != {0, 1}:
        raise ValueError("Unexpected external labels.")

    train["normalized"] = train["URL"].map(normalize)
    test["normalized"] = test["URL"].map(normalize)

    train["domain"] = train["URL"].map(get_domain)
    test["domain"] = test["URL"].map(get_domain)

    if len(test) > SAMPLE_SIZE:
        test, _ = train_test_split(
            test,
            train_size=SAMPLE_SIZE,
            random_state=SAMPLE_RANDOM_STATE,
            stratify=test["label"]
        )

    train_urls = set(train["normalized"])
    train_domains = set(train["domain"]) - {""}

    exact_disjoint = test[
        ~test["normalized"].isin(train_urls)
    ].copy()

    domain_disjoint = test[
        ~test["domain"].isin(train_domains)
    ].copy()

    evaluations = {
        "Original 60,000-record sample": test,
        "Exact-URL-disjoint sample": exact_disjoint,
        "Domain-disjoint sample": domain_disjoint,
    }

    print("\nLEAKAGE-CONTROLLED CROSS-DATASET EVALUATION")
    print("=" * 55)
    print("Training records:", len(train))
    print("Training normalized URLs:", len(train_urls))
    print("Training domains:", len(train_domains))

    for name, subset in evaluations.items():
        print(f"\n{name}")
        print("Records:", len(subset))
        print("Class distribution:")
        print(subset["label"].value_counts().sort_index())

    print("\nExtracting external test features...")

    X_test = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        index=test.index,
        columns=FEATURES
    )

    def evaluate_model(name, columns):
        print(f"\n{'=' * 65}")
        print(name)
        print("Number of features:", len(columns))
        print("=" * 65)

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=MODEL_RANDOM_STATE,
            n_jobs=-1
        )

        model.fit(train[columns], train["ClassLabel"])

        phishing_index = list(model.classes_).index(0)

        for evaluation_name, subset in evaluations.items():
            print(f"\n--- {evaluation_name} ---")

            if subset.empty or subset["label"].nunique() < 2:
                print("Insufficient records or only one class; metrics unavailable.")
                continue

            X_subset = X_test.loc[subset.index, columns]
            y_subset = subset["label"]

            predictions = model.predict(X_subset)
            probabilities = model.predict_proba(X_subset)[:, phishing_index]

            print("Records:", len(subset))
            print("Accuracy:", round(
                accuracy_score(y_subset, predictions), 4
            ))
            print("Balanced accuracy:", round(
                balanced_accuracy_score(y_subset, predictions), 4
            ))
            print("ROC-AUC (phishing):", round(
                roc_auc_score(
                    (y_subset == 0).astype(int),
                    probabilities
                ), 4
            ))

            print("\nClassification report:")
            print(classification_report(
                y_subset,
                predictions,
                labels=[0, 1],
                target_names=["Phishing", "Legitimate"],
                digits=4,
                zero_division=0
            ))

            print("Confusion matrix")
            print("Rows = actual [phishing, legitimate]")
            print("Columns = predicted [phishing, legitimate]")
            print(confusion_matrix(
                y_subset,
                predictions,
                labels=[0, 1]
            ))

    evaluate_model("Experiment A: All features", FEATURES)
    evaluate_model("Experiment B: Host features only", HOST_FEATURES)


if __name__ == "__main__":
    main()
