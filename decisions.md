# PhishGuard — Project Decisions and Data Log

## 1. Project Identity

**Project Title:** PhishGuard: Real-Time Phishing Detection with Human-in-the-Loop Override

**Project Type:** Supervised Machine Learning

**Status:** Work in Progress

## 2. Dataset Collection — 24 November 2026

### Phishing URL Dataset

- **Source:** Phishing.Database
- **Repository:** https://github.com/Phishing-Database/Phishing.Database
- **Feed:** https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
- **Local file:** `data/raw/phishing_database_active.txt`
- **Collection date:** 2026-11-24
- **File size:** 65,823,890 bytes
- **Total entries:** 789,054
- **Blank lines:** 0
- **Unique URLs:** 789,054
- **Exact duplicate URLs:** 0

### URL Scheme Distribution

| Scheme | Entries |
|---|---:|
| HTTPS | 605,641 |
| HTTP | 183,411 |
| FTP | 2 |
| **Total** | **789,054** |

### Initial Observations

- The feed contains one URL entry per line.
- Entries include HTTP, HTTPS, and FTP URLs.
- Some URLs contain unusual paths, credentials, and query parameters.
- All entries are treated as text. Phishing URLs must never be opened or visited.

## 3. Data Handling Decisions

- Preserve the original raw dataset unchanged.
- Store downloaded datasets in `data/raw/`.
- Raw and processed datasets are excluded from Git using `.gitignore`.
- Perform preprocessing on separate copies of the raw data.
- Inspect and validate records before feature extraction.
- Remove exact duplicates during preprocessing if they occur in future datasets.
- Verify dataset licensing and attribution requirements before redistribution.

## 4. Other Data Sources

### PhishTank

- An initial download attempt was made using the public online-valid feed.
- The attempt failed because of a DNS resolution error.
- No successful PhishTank dataset download has been confirmed.
- Phishing.Database is being used as the initial phishing URL source.

### Legitimate URLs

- Not collected yet.
- Tranco is a candidate source for legitimate-domain candidates.
- Its suitability, licensing, and limitations must be checked before use.

### Email Datasets

- Not collected yet.
- Candidate sources include Nazario, SpamAssassin, and Enron.
- Dataset labels, licensing, and suitability must be examined before integration.

## 5. Important Methodological Notes

- A URL feed alone does not constitute a complete phishing-email classification dataset.
- Legitimate URL candidates are still required for binary URL classification.
- Email content and header datasets are still required for the planned multi-signal system.
- Top-ranked domains must not automatically be assumed to be harmless.
- Dataset splitting and evaluation must avoid data leakage.
- No model performance metrics will be reported until experiments are actually conducted.

## 6. Next Steps

1. Verify and collect a legitimate-domain dataset.
2. Inspect and validate the legitimate URL data.
3. Investigate suitable phishing and legitimate email corpora.
4. Build the preprocessing and feature-extraction pipeline.
5. Train and evaluate baseline supervised models.


## 7. Legitimate-Domain Candidate Dataset — Tranco

- **Source:** Tranco
- **Official website:** https://tranco-list.eu/
- **Snapshot ID:** Q2464
- **Download:** https://tranco-list.eu/download/Q2464/1000000
- **Local file:** `data/raw/tranco_Q2464.csv`
- **Collection date:** 2026-11-24
- **File size:** 22,690,828 bytes
- **Requested records:** 1,000,000

### Initial Validation

- Total rows: 1,000,000
- Unique domains: 1,000,000
- Duplicate domains: 0
- Missing values: 0
- Minimum rank: 1
- Maximum rank: 1,000,000
- CSV structure: rank, domain

### Data Handling and Limitations

- Tranco domains are treated as legitimate-domain candidates, not verified safe domains.
- Popularity rankings do not guarantee that a domain is benign.
- The snapshot ID is retained for reproducibility.
- Further validation and comparison against phishing-domain data are required before assigning final training labels.
- Licensing and attribution requirements must be checked before redistribution.


## 8. Phishing–Tranco Domain Overlap Analysis — 24 November 2026

### Methodology

- Extracted registered domains from phishing URLs using `tldextract`.
- Enabled the Public Suffix List private-domain rules using `include_psl_private_domains=True`.
- Used the bundled Public Suffix List without network requests.
- Compared extracted phishing registered domains against the 1,000,000 Tranco domains in snapshot `Q2464`.
- Preserved the original raw datasets unchanged.

### Results

| Metric | Result |
|---|---:|
| Phishing URLs processed | 789,054 |
| URLs with registered domains | 775,964 |
| URLs without registered domains | 13,090 |
| Unique phishing registered domains | 320,967 |
| Overlapping domains | 2,817 |
| URLs on overlapping domains | 110,003 |
| URLs on non-overlapping domains | 665,961 |
| Overlap among URLs with registered domains | 14.18% |

### Generated Reports

- `results/domain_overlap_summary.json` — aggregate analysis.
- `results/overlapping_domains.csv` — overlapping domains, Tranco ranks, and phishing URL counts.

### Interpretation

- Some domains present in the phishing feed also appear in the Tranco popularity ranking.
- Shared hosting and website-building platforms occur among the overlapping domains.
- The presence of a domain in Tranco does not guarantee that it is safe.
- A phishing URL hosted on a popular platform must not automatically make the entire platform domain malicious.
- The 2,817 overlapping domains will be excluded from the initial legitimate-domain candidate pool.
- The remaining Tranco domains will be treated as unverified negative candidates, not confirmed benign domains.

### Methodological Correction

- The initial overlap analysis used public suffix rules without private-domain support.
- This could group separate hosted tenants under a shared hosting domain.
- Both analysis scripts were corrected to enable private-domain support.
- The corrected results documented in this section supersede the initial overlap results.

### Dataset Construction Decision

- Phishing URLs will form the initial positive candidate pool.
- Non-overlapping Tranco domains will form the initial negative candidate pool.
- Overlapping domains will be kept separate for further investigation.
- Additional validation and leakage checks are required before model training.

## 9. Phishing URL Quality Inspection — 24 November 2026

### Initial Raw Feed Validation

- Total entries: 789,054
- Blank entries: 0
- Unique URLs: 789,054
- Exact duplicate URLs: 0

### URL Scheme Distribution

| Scheme | Entries |
|---|---:|
| HTTPS | 605,641 |
| HTTP | 183,411 |
| FTP | 2 |
| **Total** | **789,054** |

### HTTP/HTTPS URL Inspection

- HTTP/HTTPS URLs with hostnames: 789,052
- Non-IP hostname records: 779,925
- IP-address hostname records: 9,127
- URLs with registered domains: 775,963
- URLs without registered domains: 13,089
- Unsupported FTP records: 2

### Extraction Methodology

- URL strings were parsed locally using Python's `urllib.parse`.
- Registered domains were extracted using `tldextract`.
- Private Public Suffix List rules were enabled.
- No phishing URLs were opened, visited, or requested over the network.
- Uppercase and lowercase domain representations were identified as equivalent through case normalization.

### Count Reconciliation

- The initial domain-overlap analysis processed all 789,054 records, including FTP.
- The HTTP/HTTPS inspection excluded the two FTP records.
- One FTP record contains the registered domain `createkindlebooks.org`.
- The other FTP record uses an IP-address host.
- Therefore, the difference between 775,964 and 775,963 registered-domain counts is explained by the FTP exclusion.

### Positive Candidate Dataset Decision

- HTTP and HTTPS records will be used for the initial positive URL candidate dataset.
- FTP records will be excluded from the initial HTTP/HTTPS classification dataset.
- IP-address-hosted URLs will be retained as a distinct feature category rather than automatically discarded.
- URLs without extractable registered domains will be retained for further inspection, not silently removed.
- The positive candidate label will be `1`, representing a phishing-source candidate rather than an independently verified malicious URL.
- Original URLs will remain inert text and will never be visited during preprocessing.

### Limitations

- Source-feed labels are inherited from the source and have not been independently verified.
- A phishing URL feed is not equivalent to a labeled phishing-email corpus.
- Additional validation, feature checks, and leakage-aware dataset splitting are required before model training.

## 10. Positive URL Candidate Dataset Construction — 24 November 2026

### Dataset Created

- File: `data/processed/phishing_url_candidates.csv`
- Source: Phishing.Database active URL feed
- Original raw feed preserved unchanged.
- Only HTTP and HTTPS records with hostnames were included.
- FTP records were excluded.

### Dataset Statistics

| Attribute | Result |
|---|---:|
| Total records | 789,052 |
| HTTPS records | 605,641 |
| HTTP records | 183,411 |
| Unique URLs | 789,052 |
| Duplicate URLs | 0 |
| IP-address hosts | 9,127 |
| Missing registered domains | 13,089 |
| Missing hostnames | 0 |
| Parsing errors | 0 |

### Features and Label

The processed dataset contains:

- `url`: Original URL string
- `scheme`: HTTP or HTTPS
- `hostname`: Extracted hostname
- `registered_domain`: Registered domain, where available
- `is_ip_host`: Whether the hostname is an IP address
- `label`: Source-derived candidate label (1)
- `source`: Source dataset identifier

### Validation

- Independent CSV reload and validation completed successfully.
- Row count matches the expected HTTP/HTTPS source count.
- No duplicate URLs were found.
- No missing URL, hostname, label, or source values were found.
- All records have label 1.
- All records originate from Phishing.Database.
- Missing registered-domain values are retained intentionally.
- No phishing URLs were visited during construction or validation.

### Interpretation and Limitations

- These are source-derived phishing URL candidates, not independently verified malicious URLs.
- The dataset contains positive candidates only; it is not yet a complete supervised training dataset.
- The negative candidate dataset currently contains domains, whereas this dataset contains full URLs.
- These different observation units must not be merged directly for model training.
- A consistent observation unit and defensible negative-example construction strategy must be established before dataset integration.

## 11. Dataset Feature Engineering Audit — 24 November 2026

### Dataset Overview

- Dataset: LegitPhish
- File: `data/raw/legitphish_v2/url_features_extracted1.csv`
- Total records: 101,219
- Total columns: 18 (URL, 16 engineered features, ClassLabel)
- Label interpretation specified by the instructor: `0 = phishing`, `1 = legitimate`.
- Dataset source DOI: `10.17632/hx4m73v2sf.2`
- Associated paper DOI: `10.1016/j.dib.2025.111972`
- Dataset licence has not yet been independently verified.

### Verified Feature Extraction Rules

The following candidate extraction rules were tested against the complete dataset:

| Feature | Candidate extraction rule | Result |
|---|---|---|
| url_length | Length of raw URL string | 101,219 matches |
| dot_count | Number of dots in raw URL | 101,219 matches |
| https_flag | URL starts with `https://` | 101,219 matches |
| number_of_digits | Number of digits in raw URL | 101,219 matches |
| percentage_numeric_chars | Digits divided by URL length × 100 | 101,219 matches |
| query_param_count | Number of `&`-separated query components, minimum 1 | 101,219 matches |
| has_hyphen_in_domain | Hyphen present in parsed netloc | 101,219 matches |
| domain_name_length | Length of second-last dot-separated netloc component | 101,219 matches |
| tld_length | Length of final dot-separated netloc component | 101,219 matches |
| subdomain_count | Number of dots in netloc minus 1 | 101,219 matches |
| url_entropy | Shannon entropy of raw URL characters, base 2 | 101,219 matches |
| suspicious_file_extension | Tested suffix-based candidate rule | 101,219 matches |

These are candidate rules that reproduce the stored values. They do not establish the original authors' exact implementation.

### Features Requiring Qualification

**has_ip_address**
- All records matched both tested IPv4-shaped and strict IPv4 detection methods.
- The available tests do not distinguish which method was originally used.

**path_length**
- 101,218 of 101,219 records matched the tested `urlparse(url).path` length calculation.
- One mismatch remains.
- Further reverse-engineering is deferred.

**token_count**
- The feature contains 32 unique values.
- Multiple common tokenization strategies were tested, but none reproduced the stored values across the dataset.
- Original tokenization methodology remains unresolved.
- Further reverse-engineering is deferred.

### Suspicious File Extension Inspection

Stored positive records: 14,840.

Observed suffix distribution:

| Suffix | Records |
|---|---:|
| .exe | 14,110 |
| .zip | 484 |
| .bin | 173 |
| .apk | 27 |
| .cmd | 14 |
| .js | 12 |
| No extension | 11 |
| .1exe | 9 |

A candidate suffix-based rule, including the tested special cases, reproduced all 101,219 stored values. This is a matching candidate rule, not proof of the original source implementation.

### Potential Data Shortcut: tld_popularity

A candidate rule reproduced all 101,219 stored values:

- The hostname's final label belongs to `{com, org, net, edu, gov}`.
- The URL has no explicit port.

Observed distribution:

| Condition | tld_popularity = 0 | tld_popularity = 1 |
|---|---:|---:|
| No explicit port | 26,911 | 33,229 |
| Explicit port | 41,079 | 0 |

Additional observation:
- 115 records with common TLDs but a stored popularity flag of 0 were all labelled ClassLabel 0.
- The feature may encode source or collection artefacts rather than genuine domain popularity.
- This is a potential shortcut or leakage concern, not yet a proven causal relationship.
- It must be investigated during Day 3 before deciding whether to retain the feature.

### Day 2 Conclusion and Next Steps

- Verified candidate extraction rules are documented above.
- `token_count` remains unresolved.
- One `path_length` mismatch remains.
- No source data was modified to force feature matches.
- No model training was performed as part of this audit.
- Day 3 will investigate label integrity, duplicates, suspicious URL patterns, domain concentration, and feature-level predictive strength.
- Leakage-aware baseline comparisons will be performed before final feature selection.


## 12. Day 3 — Dataset Audit and Baseline Experiments (24 November 2026)

### Dataset validation
- Original dataset: 101,219 records.
- Labelled records used for supervised experiments: 101,218.
- Class 0 (phishing): 63,678.
- Class 1 (legitimate): 37,540.
- One record has a missing class label. It was preserved in the source dataset and excluded only from supervised experiments.
- Duplicate URL occurrences: 346 across 302 duplicated URL groups.
- No duplicated URL groups had conflicting labels.

### Dataset shortcut and collection-pattern investigation
- All 49,070 records without an extracted registered domain belong to Class 0.
- Hostnames were available for 49,066 of these records.
- 49,057 of the available hostnames were IP addresses.
- The dataset shows strong class-specific patterns in explicit ports, HTTPS usage, and suspicious file extensions.
- Several individual features achieved exceptionally high single-feature ROC-AUC scores during diagnostic analysis.
- These observations raise concerns about dataset collection artifacts and potential shortcut learning. They do not independently prove data leakage.

### Grouping correction
An initial grouping implementation converted missing registered domains into the string "nan", incorrectly placing 49,070 records into one group.

This was corrected by:
1. Using a registered domain when available.
2. Otherwise grouping by parsed hostname, including IP addresses.
3. Using the full URL only when a hostname is unavailable.

Corrected grouping results:
- Labelled records: 101,218.
- Unique groups: 62,802.
- Training groups: 50,241.
- Testing groups: 12,561.
- Overlapping groups: 0.
- Mixed-label groups: 7. These were retained without changing their labels.

### Baseline experiments

Random stratified split:
- Features: 16.
- Accuracy: 0.9998.
- Phishing recall: 0.9998.

Corrected domain/hostname-grouped split, all features:
- Features: 16.
- Training records: 80,961.
- Testing records: 20,257.
- Accuracy: 0.9992.
- Phishing recall: 0.9999.
- Confusion matrix: [[12765, 1], [15, 7476]].

Corrected domain/hostname-grouped split, reduced features:
- Features: 11.
- Training records: 80,961.
- Testing records: 20,257.
- Accuracy: 0.9975.
- Phishing recall: 0.9991.
- Confusion matrix: [[12754, 12], [39, 7452]].

Five features excluded in the reduced experiment:
- tld_popularity
- tld_length
- domain_name_length
- subdomain_count
- suspicious_file_extension

### Interpretation and limitations
- The random split and corrected grouped split both produced very high preliminary scores.
- The corrected grouped split had zero group overlap between training and testing.
- The reduced-feature experiment also retained high phishing recall.
- High scores must not be presented as proof of real-world generalization.
- Dataset collection artifacts, class-specific patterns, and possible shortcut learning require further investigation.
- No original source dataset records or labels were modified.

### Day 3 conclusion
Dataset structure, missing labels, duplicates, class-specific patterns, grouping behaviour, and preliminary baseline performance have been investigated.

The corrected grouped experiments are retained as preliminary results. Further validation is required before final model selection or performance claims.
