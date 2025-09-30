import re
import ipaddress
from urllib.parse import urlparse
import tldextract

# 1. Domain of the URL
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2. Check for IP address in URL
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# 3. Check the presence of '@' in URL
def haveAtSign(url):
    return 1 if "@" in url else 0

# 4. Length of URL
def getLength(url):
    return 0 if len(url) < 54 else 1

# 5. Depth of URL
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth+1
    return depth

# 6. Redirection '//'
def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

# 7. Presence of 'https' in domain part of URL
def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

# 8. Using TinyURL or bit.ly (Shortening Service)
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly"
def tinyURL(url):
    match = re.search(shortening_services, url)
    return 1 if match else 0

# 9. Prefix/Suffix Separated by '-'
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# 10. Extracting features from URL
def extract_features(url):
    features = []
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))
    return features

