from urllib.parse import urlparse
import tldextract
import re


def extract_features(url):

    features = []

    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        subdomain = ext.subdomain
        path = parsed.path

        # 1 URL length
        features.append(len(url))

        # 2 Dot count
        features.append(url.count("."))

        # 3 Hyphen count
        features.append(url.count("-"))

        # 4 Digit count
        features.append(sum(c.isdigit() for c in url))

        # 5 Special characters
        features.append(len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url)))

        # 6 HTTPS presence
        features.append(1 if "https" in url else 0)

        # 7 Subdomain length
        features.append(len(subdomain))

        # 8 Path length
        features.append(len(path))

        # 9 Contains @ symbol
        features.append(1 if "@" in url else 0)

        # 10 Contains IP address
        ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
        features.append(1 if re.search(ip_pattern, url) else 0)

    except:
        features = [0]*10

    return features