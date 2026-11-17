
from script import analyze_url, calculate_risk


def test_legitimate_domain():
    result = analyze_url("https://paypal.com")
    assert result["brand_indicators"] == []
    assert result["suspicious_domain_structure"] == []


def test_brand_impersonation():
    result = analyze_url("https://paypal.com.evil.xyz")

    assert "paypal" in result["brand_indicators"]
    assert "paypal" in result["suspicious_domain_structure"]


def test_fake_brand_domain():
    result = analyze_url("https://notpaypal.com")
    assert result["brand_indicators"] == []


def test_risk_scoring():
    result = analyze_url("http://paypal-login-security.xyz")
    risk = calculate_risk(result)

    assert risk["score"] == 85
    assert risk["level"] == "High Risk"


def test_https_detection():
    result = analyze_url("https://google.com")
    assert result["uses_https"] is True

def test_empty_url():
    result = analyze_url("")
    assert result["error"] == "Invalid URL"


def test_whitespace_url():
    result = analyze_url("   ")
    assert result["error"] == "Invalid URL"


def test_missing_hostname():
    result = analyze_url("https://")
    assert result["error"] == "Invalid URL"


def test_hostname_with_spaces():
    result = analyze_url("https://pay pal.com")
    assert result["error"] == "Invalid URL"


def test_invalid_port():
    result = analyze_url("https://paypal.com:abc")
    assert result["error"] == "Invalid URL"


def test_unsupported_scheme():
    result = analyze_url("ftp://paypal.com")
    assert result["error"] == "Invalid URL"

def test_brand_in_userinfo():
    result = analyze_url("https://paypal.com@evil.xyz")

    assert result["hostname"] == "evil.xyz"
    assert result["has_at_symbol"] is True
    assert "paypal" in result["userinfo_brand_indicators"]

def test_encoded_brand_in_userinfo():
    result = analyze_url("https://pay%70al.com@evil.xyz")

    assert result["hostname"] == "evil.xyz"
    assert "paypal" in result["userinfo_brand_indicators"]

def test_domain_with_port():
    result = analyze_url("example.com:8080")

    assert "error" not in result
    assert result["hostname"] == "example.com"
    assert result["uses_https"] is True

def test_uppercase_https_scheme():
    result = analyze_url("HTTPS://google.com")

    assert "error" not in result
    assert result["uses_https"] is True
    assert result["url"].startswith("https://")

def test_at_symbol_in_path():
    result = analyze_url("https://example.com/user@test")

    assert "error" not in result
    assert result["has_at_symbol"] is False

def test_at_symbol_with_brand_username():
    result = analyze_url("https://paypal.com@evil.xyz")
    risk = calculate_risk(result)

    assert risk["score"] == 60
    assert risk["level"] == "High Risk"
    assert "Brand impersonation combined with @ symbol" in risk["reasons"]