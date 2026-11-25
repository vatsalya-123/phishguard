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
SAMPLE_SIZE = 60000


def evaluate_group(name, data, model, feature_columns):
    X = data[feature_columns]
    y = data["Label"]

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    phishing_class_index = list(model.classes_).index(0)
    phishing_probabilities = probabilities[:, phishing_class_index]

    actual_phishing = (y == 0).astype(int)
    predicted_phishing = (predictions == 0).astype(int)

    print(f"\n{name}")
    print("-" * 75)
    print("Records:", len(data))
    print("Phishing:", int((y == 0).sum()))
    print("Legitimate:", int((y == 1).sum()))
    print("Predicted phishing:", int(predicted_phishing.sum()))

    if y.nunique() == 2:
        print("Accuracy:", round(accuracy_score(y, predictions), 4))
        print("Balanced accuracy:", round(
            balanced_accuracy_score(y, predictions), 4
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
        print(confusion_matrix(y, predictions, labels=[0, 1]))

    elif (y == 0).all():
        print("Phishing detection rate:", round(
            predicted_phishing.mean(), 4
        ))
        print("Mean phishing probability:", round(
            phishing_probabilities.mean(), 4
        ))
        print("Median phishing probability:", round(
            pd.Series(phishing_probabilities).median(), 4
        ))


def main():
    print("Loading datasets...")

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

    external = X_test.copy()
    external["Label"] = y_test
    external["path_len"] = X_test["path_len"]

    print("\nEXTERNAL SAMPLE")
    print("=" * 75)
    print("Total records:", len(external))
    print("Phishing:", int((external["Label"] == 0).sum()))
    print("Legitimate:", int((external["Label"] == 1).sum()))

    print("\nPATH LENGTH GROUPS")
    print("-" * 75)

    external["Path group"] = external["path_len"].apply(
        lambda value: "Zero path" if value == 0 else "Nonzero path"
    )

    print(pd.crosstab(
        external["Path group"],
        external["Label"],
        margins=True
    ))

    print("\nMODEL PERFORMANCE BY PATH GROUP")
    print("=" * 75)

    zero_path = external[external["path_len"] == 0]
    nonzero_path = external[external["path_len"] > 0]

    evaluate_group("ZERO-PATH URLS", zero_path, model, FEATURES)
    evaluate_group("NONZERO-PATH URLS", nonzero_path, model, FEATURES)

    print("\nPHISHING DETECTION BY PATH-LENGTH RANGE")
    print("=" * 75)

    phishing = external[external["Label"] == 0].copy()

    phishing["Path range"] = pd.cut(
        phishing["path_len"],
        bins=[-1, 0, 10, 50, float("inf")],
        labels=["0", "1-10", "11-50", "Above 50"]
    )

    phishing_features = phishing[FEATURES]
    phishing_predictions = model.predict(phishing_features)

    phishing["Predicted phishing"] = (
        phishing_predictions == 0
    ).astype(int)

    print(
        phishing.groupby("Path range", observed=False).agg(
            records=("Label", "size"),
            detected=("Predicted phishing", "sum"),
            detection_rate=("Predicted phishing", "mean")
        ).round(4).to_string()
    )


if __name__ == "__main__":
    main()
