import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score

from src.url_features import extract, FEATURES
from src.audit_cross_dataset_overlap import get_domain


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"


def phishing_auc(estimator, X, y):
    probabilities = estimator.predict_proba(X)
    phishing_index = list(estimator.classes_).index(0)

    return roc_auc_score(
        (y == 0).astype(int),
        probabilities[:, phishing_index]
    )


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

    test, _ = train_test_split(
        test,
        train_size=10000,
        random_state=42,
        stratify=test["label"]
    )

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

    print("Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    print("\nBASELINE EXTERNAL ROC-AUC")
    print("=" * 65)
    print(round(phishing_auc(model, X_test, y_test), 4))

    print("\nCalculating permutation importance...")
    result = permutation_importance(
        model,
        X_test,
        y_test,
        scoring=phishing_auc,
        n_repeats=3,
        random_state=42,
        n_jobs=1
    )

    importance = pd.DataFrame({
        "Feature": FEATURES,
        "Mean AUC decrease": result.importances_mean,
        "Std deviation": result.importances_std
    })

    importance = importance.sort_values(
        "Mean AUC decrease",
        ascending=False
    )

    print("\nEXTERNAL PERMUTATION IMPORTANCE")
    print("=" * 65)
    print(importance.round(5).to_string(index=False))


if __name__ == "__main__":
    main()
