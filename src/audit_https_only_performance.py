import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    roc_auc_score,
    recall_score
)

from src.url_features import extract, FEATURES, HOST_FEATURES, PATH_FEATURES
from src.audit_cross_dataset_overlap import get_domain


def evaluate(name, columns, X_train, y_train, X_test, y_test):
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train[columns], y_train)

    phishing_index = list(model.classes_).index(0)
    probabilities = model.predict_proba(X_test[columns])[:, phishing_index]
    predictions = model.predict(X_test[columns])

    print(f"\n{name}")
    print("-" * 60)
    print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
    print("Balanced accuracy:", round(balanced_accuracy_score(y_test, predictions), 4))
    print("Phishing recall:", round(recall_score(y_test, predictions, pos_label=0), 4))
    print("Phishing ROC-AUC:", round(roc_auc_score((y_test == 0).astype(int), probabilities), 4))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))


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

    from sklearn.model_selection import train_test_split

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

    https_mask = X_test["is_https"] == 1

    X_test = X_test.loc[https_mask].copy()
    y_test = test.loc[https_mask, "label"].copy()

    print("\nHTTPS-ONLY EXTERNAL COHORT")
    print("=" * 60)
    print("Records:", len(y_test))
    print("Phishing:", int((y_test == 0).sum()))
    print("Legitimate:", int((y_test == 1).sum()))

    print("\nTraining scheme distribution:")
    print(pd.crosstab(X_train["is_https"], train["ClassLabel"]).to_string())

    print("\nExternal HTTPS label distribution:")
    print(y_test.value_counts().sort_index().rename(index={0: "Phishing", 1: "Legitimate"}).to_string())

    evaluate("ALL 22 FEATURES", FEATURES, X_train, train["ClassLabel"], X_test, y_test)
    evaluate("WITHOUT HTTPS", [f for f in FEATURES if f != "is_https"], X_train, train["ClassLabel"], X_test, y_test)
    evaluate("HOST FEATURES ONLY", HOST_FEATURES, X_train, train["ClassLabel"], X_test, y_test)


if __name__ == "__main__":
    main()
