import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix
)

from src.url_features import extract, FEATURES
from src.audit_cross_dataset_overlap import get_domain


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"


def evaluate(name, columns, X_train, X_test, y_train, y_test):
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train[columns], y_train)

    predictions = model.predict(X_test[columns])
    probabilities = model.predict_proba(X_test[columns])

    phishing_index = list(model.classes_).index(0)
    phishing_probabilities = probabilities[:, phishing_index]

    actual_phishing = (y_test == 0).astype(int)
    predicted_phishing = (predictions == 0).astype(int)

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)
    print("Features:", len(columns))
    print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
    print("Balanced accuracy:", round(
        balanced_accuracy_score(y_test, predictions), 4
    ))
    print("Phishing precision:", round(
        precision_score(actual_phishing, predicted_phishing, zero_division=0), 4
    ))
    print("Phishing recall:", round(
        recall_score(actual_phishing, predicted_phishing, zero_division=0), 4
    ))
    print("Phishing ROC-AUC:", round(
        roc_auc_score(actual_phishing, phishing_probabilities), 4
    ))
    print("Confusion matrix [actual 0,1 / predicted 0,1]:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))


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
        train_size=60000,
        random_state=0,
        stratify=test["label"]
    )

    train["domain"] = train["URL"].map(get_domain)
    test["domain"] = test["URL"].map(get_domain)

    train_domains = set(train["domain"]) - {""}
    test = test[~test["domain"].isin(train_domains)].copy()

    print("Training records:", len(train))
    print("External domain-disjoint records:", len(test))

    print("Extracting training features...")
    X_train = pd.DataFrame(
        [extract(url) for url in train["URL"]],
        columns=FEATURES,
        index=train.index
    )

    print("Extracting external features...")
    X_test = pd.DataFrame(
        [extract(url) for url in test["URL"]],
        columns=FEATURES,
        index=test.index
    )

    y_train = train["ClassLabel"]
    y_test = test["label"]

    without_https = [f for f in FEATURES if f != "is_https"]

    evaluate(
        "ALL 22 FEATURES",
        FEATURES,
        X_train,
        X_test,
        y_train,
        y_test
    )

    evaluate(
        "WITHOUT HTTPS",
        without_https,
        X_train,
        X_test,
        y_train,
        y_test
    )

    evaluate(
        "HTTPS ONLY",
        ["is_https"],
        X_train,
        X_test,
        y_train,
        y_test
    )


if __name__ == "__main__":
    main()
