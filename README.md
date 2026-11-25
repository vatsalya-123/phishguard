# PhishGuard

### Supervised Phishing URL Detection with Human-in-the-Loop Override

PhishGuard is a machine learning project that investigates phishing URL detection through URL-based feature engineering and supervised classification.

The project focuses on extracting structural characteristics from URLs, evaluating classification performance across datasets, and examining the reliability of model predictions under changes in data distribution.

## Current Implementation

- Custom URL feature extraction using 22 engineered features.
- Host-based and URL/path-based feature groups.
- URL normalization and malformed URL handling.
- Random Forest classification using the cleaned LegitPhish dataset.
- External evaluation using the PhiUSIIL phishing URL dataset.
- Exact URL and domain overlap analysis.
- Domain-disjoint evaluation to investigate generalization to unseen domains.
- Feature ablation and permutation importance analysis.
- HTTPS dependence and URL-structure distribution audits.
- Unit testing of URL feature extraction using pytest.

## Evaluation Findings

A sampled, domain-disjoint external cohort of 42,882 URLs was used for evaluation.

The initial 22-feature model achieved:

- Accuracy: 98.00%
- Balanced accuracy: 97.66%
- Phishing recall: 95.31%
- Phishing ROC-AUC: 99.65%

These results are specific to the evaluated dataset and should not be interpreted as real-world performance guarantees.

Further analysis identified substantial differences in URL scheme and URL-structure distributions between the training and external datasets. In particular, the training data has a strong association between HTTPS usage and class labels. The external evaluation cohort also contains no legitimate HTTP URLs.

These findings highlight potential dataset-related shortcuts and generalization limitations. Additional evaluation on more representative datasets is necessary.

## Project Structure

- `src/` - Feature extraction, dataset processing, evaluation and audit scripts.
- `tests/` - Unit tests for URL feature extraction.
- `data/raw/` - Original datasets.
- `data/processed/` - Cleaned datasets and intermediate outputs.

## Technologies

- Python
- Pandas and NumPy
- Scikit-learn
- XGBoost
- Matplotlib and Seaborn
- tldextract
- pytest

## Planned Development

- Further validation across independent and representative datasets.
- Model refinement and reliability analysis.
- Phishing risk assessment and prediction confidence.
- Real-time URL detection.
- Human review, prediction override and feedback logging.

## Project Status

**Work in Progress** - Feature extraction, baseline model evaluation and cross-dataset reliability investigations have been implemented. Further validation and system integration remain.

## Repository

[GitHub - PhishGuard](https://github.com/vatsalya-123/phishguard)
