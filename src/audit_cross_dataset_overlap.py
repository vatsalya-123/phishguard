import pandas as pd
from urllib.parse import urlsplit

from src.url_features import normalize, _EXT


TRAIN_FILE = "data/processed/legitphish_clean.csv"
TEST_FILE = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"


def get_domain(url):
    try:
        host = (urlsplit(normalize(url)).hostname or "").lower()
    except ValueError:
        return ""

    if not host:
        return ""

    ext = _EXT(host)

    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"

    return host


def main():
    train = pd.read_csv(TRAIN_FILE, usecols=["URL", "ClassLabel"])
    test = pd.read_csv(TEST_FILE, usecols=["URL", "label"])

    train = train.dropna(subset=["URL", "ClassLabel"]).copy()
    test = test.dropna(subset=["URL", "label"]).copy()

    train = train.drop_duplicates(subset=["URL"])
    test = test.drop_duplicates(subset=["URL"])

    train["normalized"] = train["URL"].map(normalize)
    test["normalized"] = test["URL"].map(normalize)

    train_urls = set(train["normalized"])
    test_urls = set(test["normalized"])

    train_domains = set(train["URL"].map(get_domain))
    test_domains = set(test["URL"].map(get_domain))

    train_domains.discard("")
    test_domains.discard("")

    exact_overlap = train_urls & test_urls
    domain_overlap = train_domains & test_domains

    print("CROSS-DATASET OVERLAP AUDIT")
    print("=" * 45)

    print("Training unique URLs:", len(train_urls))
    print("External unique URLs:", len(test_urls))

    print("\nExact normalized URL overlap:", len(exact_overlap))
    print(
        "Percentage of external URLs:",
        round(len(exact_overlap) / len(test_urls) * 100, 4)
    )

    print("\nTraining unique domains:", len(train_domains))
    print("External unique domains:", len(test_domains))
    print("Shared domains:", len(domain_overlap))
    print(
        "Percentage of external domains:",
        round(len(domain_overlap) / len(test_domains) * 100, 4)
    )


if __name__ == "__main__":
    main()