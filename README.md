\# PhishGuard



\### Real-Time Phishing Detection with Human-in-the-Loop Override



PhishGuard is a supervised machine learning project focused on identifying phishing URLs through URL-based feature extraction and classification.



The system aims to analyse URL characteristics, estimate phishing risk, and provide interpretable predictions. Its planned human-in-the-loop mechanism will allow users to review uncertain predictions, override decisions, and provide feedback.



\## Planned Architecture



1\. Data collection and dataset validation

2\. URL preprocessing and feature engineering

3\. Supervised machine learning and model evaluation

4\. Phishing risk assessment and prediction confidence

5\. Human review, override, and feedback logging



\## Current Progress



\- Collected and examined phishing and legitimate URL datasets.

\- Audited dataset quality, missing values, duplicates, and feature extraction patterns.

\- Investigated domain overlap and potential dataset collection biases.

\- Established preliminary random-split and domain-grouped baseline experiments.

\- Investigating generalization and dataset shortcut risks before final model selection.



\## Technologies



\- Python

\- Pandas and NumPy

\- Scikit-learn

\- XGBoost

\- Matplotlib and Seaborn

\- tldextract



\## Project Status



\*\*Work in Progress\*\* — Dataset auditing and baseline evaluation are underway. Model development and real-time detection integration are planned next.



\## Repository



\[GitHub – PhishGuard](https://github.com/vatsalya-123/phishguard)
