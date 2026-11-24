from pathlib import Path
from urllib.parse import urlsplit
import tldextract

source = Path("data/raw/phishing_database_active.txt")

extractor = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)

differences = []

with source.open("r", encoding="utf-8", errors="replace") as file:
    for line_number, line in enumerate(file, start=1):
        url = line.strip()

        if not url:
            continue

        direct = extractor(url).top_domain_under_public_suffix

        try:
            hostname = urlsplit(url).hostname
            parsed = extractor(hostname).top_domain_under_public_suffix if hostname else ""
        except ValueError:
            parsed = ""

        if direct != parsed:
            differences.append((line_number, url, direct, parsed))

print("Extraction differences:", len(differences))

for item in differences[10:]:
    print("\nLine:", item[0])
    print("URL:", item[1])
    print("Direct extraction:", item[2])
    print("Hostname extraction:", item[3])
