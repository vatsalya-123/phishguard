
import pandas as pd

from src.url_features import extract, FEATURES

INPUT_FILE = "data/processed/with_domains.csv"
OUTPUT_FILE = "data/processed/legitphish_clean.csv"


def main():
    df = pd.read_csv(INPUT_FILE)

    # Keep only records with both a URL and a class label.
    df = df.dropna(subset=["URL", "ClassLabel"]).copy()

    if not set(df["ClassLabel"].unique()).issubset({0, 1}):
        raise ValueError("Unexpected class labels found.")

    df["ClassLabel"] = df["ClassLabel"].astype(int)

    # Remove duplicate URLs, retaining their first occurrence.
    df = df.drop_duplicates(subset=["URL"]).copy()

    # Independently extract features from the original URL strings.
    features = pd.DataFrame(
        [extract(url) for url in df["URL"]],
        index=df.index,
        columns=FEATURES
    )

    # Combine original URLs, labels, and newly extracted features.
    output = pd.concat(
        [
            df[["URL", "ClassLabel"]],
            features
        ],
        axis=1
    )

    output.to_csv(OUTPUT_FILE, index=False)

    print("Feature dataset created successfully.")
    print("Output file:", OUTPUT_FILE)
    print("Dataset shape:", output.shape)
    print("\nClass distribution:")
    print(output["ClassLabel"].value_counts().sort_index())
    print("\nMissing values:", output.isnull().sum().sum())
    print("Duplicate URLs:", output["URL"].duplicated().sum())


if __name__ == "__main__":
    main()
