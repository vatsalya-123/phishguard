import numpy as np
import pandas as pd
import tldextract
from urllib.parse import urlsplit
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from src.url_features import entropy, normalize

PHISH_PATH = "data/raw/phishing_database_active.txt"
TRANCO_PATH = "data/raw/tranco_Q2464.csv"
N_PER_CLASS = 150_000
EXT = tldextract.TLDExtract(suffix_list_urls=())

def reg_domain(url):
    try:
        host = urlsplit(normalize(url)).hostname or ""
    except ValueError:
        return ""
    e = EXT(host)
    return e.registered_domain if e.suffix else ""

lines = open(PHISH_PATH, encoding="utf-8", errors="ignore").read().splitlines()
phish = pd.DataFrame({"domain": pd.Series(lines).map(reg_domain)})
phish = phish[phish.domain != ""].drop_duplicates("domain")

tr = pd.read_csv(TRANCO_PATH, header=None, names=["rank", "domain"])
overlap = tr.domain.isin(set(phish.domain)).sum()
print("Tranco domains also in phishing feed (removed):", overlap)
tr = tr[~tr.domain.isin(set(phish.domain))]

n = min(N_PER_CLASS, len(phish), len(tr))
print("Records available — phishing:", len(phish), "| Tranco:", len(tr))
print("Records selected per class:", n)

df = pd.concat([
    phish.sample(n, random_state=0).assign(y=1),
    tr[["domain"]].sample(n, random_state=0).assign(y=0)
], ignore_index=True)

parts = df.domain.map(EXT)
df["name"] = parts.map(lambda e: e.domain)
df["tld"] = parts.map(lambda e: e.suffix)
df["group"] = df["name"].str.replace(r"\d+", "", regex=True)
df["text"] = df["name"] + " tld_" + df["tld"].str.replace(".", "_", regex=False)
df["n_len"] = df.name.str.len()
df["n_digits"] = df.name.str.count(r"\d")
df["n_hyph"] = df.name.str.count("-")
df["n_ent"] = df.name.map(entropy)
NUM = ["n_len", "n_digits", "n_hyph", "n_ent"]

def split(frame, test_size, seed):
    a, b = next(GroupShuffleSplit(
        n_splits=1, test_size=test_size, random_state=seed
    ).split(frame, groups=frame["group"]))
    return frame.iloc[a].copy(), frame.iloc[b].copy()

dev, test = split(df, 0.2, 0)
train, val = split(dev, 0.2, 1)
print("train/val/test:", len(train), len(val), len(test))

vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=5)
X_train = vec.fit_transform(train.text)
X_val = vec.transform(val.text)
X_test = vec.transform(test.text)

lr = LogisticRegression(max_iter=1000, C=2.0)
lr.fit(X_train, train.y)

p_val = lr.predict_proba(X_val)[:, 1]
p_test = lr.predict_proba(X_test)[:, 1]

gb = HistGradientBoostingClassifier(random_state=0)
gb.fit(train[NUM], train.y)
g_test = gb.predict_proba(test[NUM])[:, 1]

for name, p in [
    ("LogReg on char n-grams", p_test),
    ("GradBoost on 4 numeric features", g_test)
]:
    print(
        f"\n{name}: ROC-AUC={roc_auc_score(test.y, p):.4f}  "
        f"PR-AUC={average_precision_score(test.y, p):.4f}"
    )

def pick_thresholds(y, p, prec_target=0.99, rec_target=0.98):
    prec, rec, thr = precision_recall_curve(y, p)
    ok = np.where(prec[:-1] >= prec_target)[0]
    t_high = thr[ok[0]] if len(ok) else 1.0
    ok = np.where(rec[:-1] >= rec_target)[0]
    t_low = thr[ok[-1]] if len(ok) else 0.0
    return t_low, t_high

t_low, t_high = pick_thresholds(val.y.values, p_val)
print(
    f"\nThresholds from validation: "
    f"deliver below {t_low:.3f}, quarantine at/above {t_high:.3f}"
)

y = test.y.values
q = p_test >= t_high
d = p_test < t_low
r = ~q & ~d

print(
    f"auto-quarantine {q.mean():.1%} | "
    f"human review {r.mean():.1%} | deliver {d.mean():.1%}"
)
print(
    "phishing quarantined:", int((q & (y == 1)).sum()),
    "| legit wrongly quarantined:", int((q & (y == 0)).sum())
)
print(
    "phishing delivered (missed):", int((d & (y == 1)).sum()),
    "| legit delivered:", int((d & (y == 0)).sum())
)
print(
    "phishing sent to review:", int((r & (y == 1)).sum()),
    "| legit sent to review:", int((r & (y == 0)).sum())
)

import json
import pathlib
import joblib

pathlib.Path("models").mkdir(exist_ok=True)
pathlib.Path("results").mkdir(exist_ok=True)

joblib.dump({"vectorizer": vec, "model": lr}, "models/domain_model.joblib")
json.dump(
    {"t_low": float(t_low), "t_high": float(t_high)},
    open("models/thresholds.json", "w"),
    indent=2
)
json.dump({
    "roc_auc_lr": float(roc_auc_score(test.y, p_test)),
    "pr_auc_lr": float(average_precision_score(test.y, p_test)),
    "share_quarantine": float(q.mean()),
    "share_review": float(r.mean()),
    "share_deliver": float(d.mean()),
}, open("results/day5_metrics.json", "w"), indent=2)

print("Saved model, thresholds and metrics")
