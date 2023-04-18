from features import *
from urllib.parse import urlparse
import whois
import requests


# Function to extract features
def feature_extraction(url, label):
    features = []
    # Address bar based features (10)
    features.append(getdomain(url))
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))
    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    features.append(dns)
    # features.append(web_traffic(url)) # not using this as similar web allows limited links
    features.append(1 if dns == 1 else domain_age(domain_name))
    features.append(1 if dns == 1 else domain_end(domain_name))
    # HTML & Javascript based features (4)
    try:
        response = requests.get(url, timeout=5)  #timeout of 5 seconds if requests takes too long
    except requests.exceptions.RequestException as e:
        response = ""
    features.append(iframe(response))
    features.append(mouseover(response))
    features.append(right_click(response))
    features.append(forwarding(response))
    features.append(label)
    
    return features


