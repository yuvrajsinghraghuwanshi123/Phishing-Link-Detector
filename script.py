from urllib.parse import urlparse, unquote
import tldextract
import ipaddress


def analyze_url(url):

    # Remove leading and trailing whitespace
    url = url.strip()

    # Add HTTPS if no scheme is provided
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):

        if "://" in url:
            return {"error": "Invalid URL"}

        url = "https://" + url
        parsed = urlparse(url)

    else:
        # Normalize scheme to lowercase
        url = parsed._replace(
            scheme=parsed.scheme.lower()
        ).geturl()

        parsed = urlparse(url)

    # Allow only HTTP and HTTPS
    if parsed.scheme not in ("http", "https"):
        return {"error": "Invalid URL"}



    # Validate hostname
    hostname = parsed.hostname

    if not hostname or any(char.isspace() for char in hostname):
        return {"error": "Invalid URL"}

    # Validate port
    try:
        parsed.port
    except ValueError:
        return {"error": "Invalid URL"}

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # Encode spaces in the URL path
    if " " in parsed.path:
        url = url.replace(" ", "%20")
        parsed = urlparse(url)

    # Check HTTPS
    uses_https = parsed.scheme == "https"

    # Check URL length
    url_length = len(url)

    # Check suspicious keywords
    keywords = [
        "login", "verify", "account",
        "update", "secure", "banking",
        "password", "signin"
    ]

    # Official brand domains
    trusted_brands = {
        "paypal": "paypal.com",
        "google": "google.com",
        "amazon": "amazon.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "facebook": "facebook.com"
    }

    # Extract username information from URL
    userinfo = unquote(parsed.username or "")

    # Detect trusted brands in URL username
    userinfo_brand_indicators = []

    for brand in trusted_brands:
        if brand in userinfo.lower():
            userinfo_brand_indicators.append(brand)

    userinfo_keywords = [
        word for word in keywords if word in userinfo.lower()
    ]

    hostname_keywords = [
        word for word in keywords if word in hostname.lower()
    ]

    path_keywords = [
        word for word in keywords if word in parsed.path.lower()
    ]

    # Check special character
    has_at_symbol = "@" in parsed.netloc


    # Extract domain information
    extracted = tldextract.extract(hostname)

    registered_domain = extracted.top_domain_under_public_suffix
    registered_domain = registered_domain.lower()

    # Extract individual subdomain labels
    subdomain_labels = extracted.subdomain.lower().split(".") if extracted.subdomain else []

    # Split labels into individual tokens
    subdomain_tokens = {
        token
        for label in subdomain_labels
        for token in label.split("-")
    }

    # Detect trusted brands used misleadingly in subdomains
    suspicious_domain_structure = []

    for brand, official_domain in trusted_brands.items():
        if brand in subdomain_tokens and registered_domain != official_domain:
            suspicious_domain_structure.append(brand)



    # Count actual subdomains
    subdomain_count = (
        len(extracted.subdomain.split("."))
        if extracted.subdomain else 0
    )

    # Count hyphens
    hyphen_count = hostname.count("-")

    # Split hostname into individual brand tokens
    hostname_labels = hostname.lower().split(".")

    brand_tokens = {
        token
        for label in hostname_labels
        for token in label.split("-")
    }

    # Detect possible brand impersonation
    brand_indicators = []

    for brand, official_domain in trusted_brands.items():
        if brand in brand_tokens and registered_domain != official_domain:
            brand_indicators.append(brand)



    return {
        "url": url,
        "hostname": hostname,
        "uses_https": uses_https,
        "is_ip_address": is_ip,
        "url_length": url_length,
        "hostname_keywords": hostname_keywords,
        "path_keywords": path_keywords,
        "has_at_symbol": has_at_symbol,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "brand_indicators": brand_indicators,
        "userinfo_keywords": userinfo_keywords,
        "suspicious_domain_structure": suspicious_domain_structure,
        "userinfo_brand_indicators": userinfo_brand_indicators
    }



def calculate_risk(analysis):

    score = 0
    reasons = []

    # HTTPS check
    if not analysis["uses_https"]:
        score += 10
        reasons.append("No HTTPS detected")

    # IP address check
    if analysis["is_ip_address"]:
        score += 30
        reasons.append("IP address used as hostname")

    # Suspicious hostname keywords
    if analysis["hostname_keywords"]:
        score += 15
        reasons.append("Suspicious keywords found in hostname")

    # Suspicious path keywords
    if analysis["path_keywords"]:
        score += 5
        reasons.append("Suspicious keywords found in URL path")

    # @ symbol check
    if analysis["has_at_symbol"]:
        score += 20
        reasons.append("@ symbol detected")

    # Brand impersonation in URL username
    if analysis["userinfo_brand_indicators"]:
        score += 30
        reasons.append("Trusted brand found in URL username")

    if analysis["has_at_symbol"] and analysis["userinfo_brand_indicators"]:
        score += 10
        reasons.append("Brand impersonation combined with @ symbol")

    if analysis["userinfo_keywords"]:
        score += 10
        reasons.append("Suspicious keywords found in URL username")

    # Subdomain check
    if analysis["subdomain_count"] > 2:
        score += 15
        reasons.append("Excessive subdomains detected")

    # Hyphen check
    if analysis["hyphen_count"] >= 3:
        score += 10
        reasons.append("Multiple hyphens detected")

    # Brand impersonation check
    if analysis["brand_indicators"]:
        score += 60
        reasons.append("Possible brand impersonation detected")

    # Cap score at 100
    score = min(score, 100)

    # Risk classification
    if score > 50:
        level = "High Risk"
    elif score > 20:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }


if __name__ == "__main__":

    url = "https://google-login-verify-account@evil.xyz"

    analysis = analyze_url(url)

    print("\n--- URL ANALYSIS ---")

    if "error" in analysis:
        print("Error:", analysis["error"])

    else:
        for key, value in analysis.items():
            print(f"{key}: {value}")

        risk = calculate_risk(analysis)

        print("\n--- RISK ASSESSMENT ---")
        print("Risk Score:", risk["score"], "/ 100")
        print("Risk Level:", risk["level"])
        print("Reasons:")

        for reason in risk["reasons"]:
            print("-", reason)
