
from src.url_features import extract


def test_basic_url():
    f = extract("https://www.paypal.com/signin")

    assert f["is_https"] == 1
    assert f["subdomain_count"] == 1
    assert f["path_depth"] == 1


def test_ip_with_port():
    f = extract("http://192.168.1.5:8080/a/b")

    assert f["is_ip_host"] == 1
    assert f["has_port"] == 1
    assert f["tld_len"] == 0


def test_double_scheme():
    f = extract("http://http://example.com/x")

    assert f["host_len"] == len("example.com")


def test_malformed_does_not_crash():
    f = extract("http://[bad")

    assert f["host_len"] == 0


def test_invalid_ipv4_is_not_detected():
    f = extract("http://999.999.999.999/path")

    assert f["is_ip_host"] == 0


def test_all_features_are_returned():
    from src.url_features import FEATURES

    f = extract("https://example.com")

    assert set(f.keys()) == set(FEATURES)
    assert len(f) == 22
