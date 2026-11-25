
import math
import re
import ipaddress
from collections import Counter
from urllib.parse import urlsplit

import tldextract

_EXT = tldextract.TLDExtract(suffix_list_urls=())
def is_ipv4(host):
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False

_WORDS = (
    "login", "verify", "secure", "account", "update", "bank",
    "signin", "confirm", "password", "wallet"
)

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
}

HOST_FEATURES = [
    "host_len", "domain_len", "tld_len", "subdomain_count",
    "is_ip_host", "has_port", "dots_in_host", "hyphens_in_host",
    "digits_in_host", "digit_ratio_host", "host_entropy",
    "has_punycode", "is_shortener"
]

PATH_FEATURES = [
    "url_len", "path_len", "query_len", "path_depth",
    "num_params", "url_entropy", "has_at_symbol",
    "suspicious_words", "is_https"
]

FEATURES = HOST_FEATURES + PATH_FEATURES


def normalize(url):
    u = str(url).strip()
    u = re.sub(r"^(https?://)(?:https?://)+", r"\1", u, flags=re.I)

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u

    return u


def entropy(s):
    if not s:
        return 0.0

    n = len(s)
    return -sum(
        c / n * math.log2(c / n)
        for c in Counter(s).values()
    )


def extract(url):
    u = normalize(url)

    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        has_port = int(p.port is not None)

    except ValueError:
        p, host, has_port = urlsplit("http://invalid"), "", 0

    ext = _EXT(host)
    low = u.lower()
    digits = sum(ch.isdigit() for ch in host)

    return {
        "host_len": len(host),
        "domain_len": len(ext.domain),
        "tld_len": len(ext.suffix),
        "subdomain_count": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "is_ip_host": int(is_ipv4(host)),
        "has_port": has_port,
        "dots_in_host": host.count("."),
        "hyphens_in_host": host.count("-"),
        "digits_in_host": digits,
        "digit_ratio_host": digits / len(host) if host else 0.0,
        "host_entropy": entropy(host),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(host in _SHORTENERS),
        "url_len": len(u),
        "path_len": len(p.path),
        "query_len": len(p.query),
        "path_depth": len([s for s in p.path.split("/") if s]),
        "num_params": len([q for q in p.query.split("&") if q]),
        "url_entropy": entropy(u),
        "has_at_symbol": int("@" in u),
        "suspicious_words": sum(w in low for w in _WORDS),
        "is_https": int(p.scheme == "https")
    }
