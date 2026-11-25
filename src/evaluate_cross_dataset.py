
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

from src.url_features import extract, FEATURES, HOST_FEATURES


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"

SAMPLE_SIZE = 60000
RANDOM_STATE = 42


def main():
    # Load the independently generated training dataset.
    train = pd.read_csv(TRAIN_FILE)

    # Load only the original URL and target from PhiUSIIL.
    test = pd.read_csv(
        TEST_FILE,
        usecols=["URL", "label"]
    )

    # Validate the training labels.
    train["ClassLabel"] = train["ClassLabel"].astype(int)

    if set(train["ClassLabel"].unique()) != {0, 1}:
        raise ValueError("Unexpected training labels.")

    # Remove missing records and duplicate URLs from external data.
    test = test.dropna(subset=["URL", "label"]).copy()
    test = test.drop_duplicates(subset=["URL"]).copy()
    test["label"] = test["label"].astype(int)

    if set(test["label"].unique()) != {0, 1}:
        raise ValueError("Unexpected external test labels.")

    # Select a reproducible, stratified external test sample.
    if len(test) > SAMPLE_SIZE:
        test, _ = train_test_split(
            test,
            train_size=SAMPLE_SIZE,
            random_state=0,
            stratify=test["label"]
        )

    # Independently extract features from PhiUSIIL URLs.
    print("Extracting external test features...")

    X_test = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        index=test.index,
        columns=FEATURES
    )

    y_test = test["label"]

    print("\nExperimental dataset summary")
    print("Training records:", len(train))
    print("External test records:", len(test))
    print("\nTraining class distribution:")
    print(train["ClassLabel"].value_counts().sort_index())
    print("\nExternal test class distribution:")
    print(y_test.value_counts().sort_index())

    def run_experiment(name, columns):
        print(f"\n{'=' * 55}")
        print(name)
        print(f"Number of features: {len(columns)}")
        print("=" * 55)

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
            n_jobs=-1
        )

        model.fit(train[columns], train["ClassLabel"])

        predictions = model.predict(X_test[columns])

        # Probability corresponding to phishing (class 0).
        phishing_index = list(model.classes_).index(0)
        phishing_probabilities = model.predict_proba(
            X_test[columns]
        )[:, phishing_index]

        print("Accuracy:", round(
            accuracy_score(y_test, predictions), 4
        ))

        print("Balanced accuracy:", round(
            balanced_accuracy_score(y_test, predictions), 4
        ))

        print("ROC-AUC (phishing):", round(
            roc_auc_score(
                (y_test == 0).astype(int),
                phishing_probabilities
            ), 4
        ))

        print("\nClassification report:")
        print(
            classification_report(
                y_test,
                predictions,
                labels=[0, 1],
                target_names=["Phishing", "Legitimate"],
                digits=4,
                zero_division=0
            )
        )

        print("Confusion matrix")
        print("Rows = actual [phishing, legitimate]")
        print("Columns = predicted [phishing, legitimate]")
        print(confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        ))

    run_experiment("Experiment A: All features", FEATURES)

    run_experiment("Experiment B: Host features only", HOST_FEATURES)


if __name__ == "__main__":
    main()
