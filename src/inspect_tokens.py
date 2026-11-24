import pandas as pd
import re

df = pd.read_csv("data/raw/legitphish_v2/url_features_extracted1.csv")

patterns = {
    "words_only": r"\w+",
    "words_and_punctuation": r"\w+|[^\w\s]",
    "letters_digits_punctuation": r"[A-Za-z]+|[0-9]+|[^\w\s]",
    "alphanumeric_groups": r"[A-Za-z0-9]+",
}

for name, pattern in patterns.items():
    calculated = df["URL"].fillna("").astype(str).apply(
        lambda url: len(re.findall(pattern, url))
    )

    print(
        name,
        "| MATCHES:", (calculated == df["token_count"]).sum(),
        "| MISMATCHES:", (calculated != df["token_count"]).sum()
    )

print("\nFIRST 5 URL TOKENIZATIONS:")

for url in df["URL"].head(5):
    print("\nURL:", url)

    for name, pattern in patterns.items():
        print(name, ":", re.findall(pattern, url))