
import pandas as pd
import tldextract
from urllib.parse import urlsplit

PATH = "data/processed/with_domains.csv"

df = pd.read_csv(PATH)

missing = df[df["reg_domain"].fillna("").eq("")].copy()

extractor = tldextract.TLDExtract(suffix_list_urls=())

def inspect_url(url):
    try:
        parsed = urlsplit(str(url))
        hostname = parsed.hostname or ""
        extracted = extractor(str(url))

        return pd.Series({
            "hostname": hostname,
            "has_hostname": bool(hostname),
            "is_ip": bool(
                hostname and all(
                    part.isdigit() and 0 <= int(part) <= 255
                    for part in hostname.split(".")
                ) and len(hostname.split(".")) == 4
            ),
            "suffix": extracted.suffix,
        })
    except Exception:
        return pd.Series({
            "hostname": "",
            "has_hostname": False,
            "is_ip": False,
            "suffix": "",
        })


details = missing["URL"].apply(inspect_url)

missing = pd.concat([missing, details], axis=1)

print("TOTAL MISSING REGISTERED DOMAINS:", len(missing))

print("\nDISTRIBUTION BY CLASS:")
print(missing["ClassLabel"].value_counts(dropna=False))

print("\nHOSTNAME AVAILABILITY:")
print(missing["has_hostname"].value_counts())

print("\nIP ADDRESS HOSTS:")
print(missing["is_ip"].value_counts())

print("\nSUFFIX DISTRIBUTION:")
print(missing["suffix"].value_counts().head(20))

print("\nUNIQUE NONEMPTY HOSTNAMES:",
      missing.loc[missing["hostname"].ne(""), "hostname"].nunique())

print("\nTOP 20 HOSTNAMES:")
print(
    missing["hostname"]
    .replace("", pd.NA)
    .value_counts()
    .head(20)
)

print("\nSAMPLE RECORDS:")
print(
    missing[["URL", "ClassLabel", "hostname", "suffix"]]
    .head(15)
    .to_string(index=False)
)
