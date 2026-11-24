import datetime
import pathlib
import requests

RAW = pathlib.Path("data/raw")
RAW.mkdir(parents=True, exist_ok=True)

STAMP = datetime.date.today().isoformat()

HEADERS = {
    "User-Agent": "phishtank/phishguard-student-project"
}

SOURCES = {
    f"phishtank_{STAMP}.csv":
        "https://data.phishtank.com/data/online-valid.csv",
}

for name, url in SOURCES.items():
    out = RAW / name

    if out.exists():
        print(f"Skipping {name}, already downloaded")
        continue

    try:
        print(f"Downloading {name}...")

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=120
        )
        response.raise_for_status()

        first_line = response.text.splitlines()[0].lstrip("\ufeff")

        if not first_line.startswith("phish_id,url,"):
            raise ValueError(
                "Unexpected response: expected a PhishTank CSV file."
            )

        out.write_bytes(response.content)

        print(
            f"Saved {name} "
            f"({len(response.content) / 1e6:.1f} MB)"
        )

    except Exception as e:
        print(f"FAILED {name}: {e}")
