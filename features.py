from urllib.parse import urlparse
import re
import socket
from datetime import datetime
import requests

""" 3.1. Address Bar Based Features:"""
"""
Domain of URL
IP Address in URL
"@" Symbol in URL
Length of URL
Depth of URL
Redirection "//" in URL
"http/https" in Domain name
Using URL Shortening Services “TinyURL”
Prefix or Suffix "-" in Domain
"""

"""3.1.1. Domain of the URL"""
# 1.Domain of the URL (Domain)
def getdomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

"""3.1.2. IP Address in the URL"""
"""phishers could use ip instead of DNS in domain"""

"""returns 1 for ip as dns in URL"""
def having_ip(url):
    result = urlparse(url).netloc
    try:
        socket.inet_aton(result)
        return 1
    except:
        return 0

"""3.1.3. "@" Symbol in URL"""
"""phishers add @"""
"""1 for @ in url"""
#  Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and
#  the real address often follows the “@” symbol.
def have_at_sign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

"""3.1.4. Length of URL"""
"""checking length is more than 54"""
# Phishers can use long URL to hide the doubtful part in the address bar.
def get_length(url):
    if len(url) < 54:
        length = 0
    else:
        length = 1
    return length

"""3.1.5. Depth of URL"""
# 5.Gives number of '/' in URL (URL_Depth)
# This feature calculates the number of subpages in the given url based on the '/'.
def get_depth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth

"""3.1.6. Redirection "//" in URL"""
"""1(True) for pos of // at 6 or 7 i.e user being redirected"""
# existence of // is user is being redirected to another website
# checks the presence of // in url. if http then // wil be at 6th pos and https it will be at 7th pos.
# If the "//" is anywhere in the URL apart from after the protocol, thee value assigned to this feature is 1 (phishing)
# or else 0 (legitimate).
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0

"""3.1.7. "http/https" in Domain name"""
"""The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users."""
# The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.
# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def http_domain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0

"""3.1.8. Using URL Shortening Services “TinyURL”"""
""" URL may be made considerably smaller in length and still lead to the required webpage."""
# listing shortening services
# If the URL is using Shortening Services, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tiny_url(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0

"""3.1.9. Prefix or Suffix "-" in Domain"""
# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefix_suffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate

"""3.2. Domain Based Features"""
"""
DNS Record
Website Traffic
Age of Domain
End Period of Domain
"""

"""3.2.1. DNS Record"""
# For phishing websites, either the claimed identity is not recognized by the WHOIS database or no records founded for
# the hostname. If the DNS record is empty or not found then,
# the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

"""3.2.2. Web Traffic"""
# gives popularity of website
# 1.Web traffic (Web_Traffic)
def web_traffic(url):

    try:
        api = "https://similarweb2.p.rapidapi.com/trafficoverview"

        querystring = {"domain": f"{getdomain(url)}"}
        headers = {
            "X-RapidAPI-Key": "6c248f3ed1msh0b5fb92616b6d67p1c7bc5jsna91ad0f8ab7a",
            "X-RapidAPI-Host": "similarweb2.p.rapidapi.com"
        }

        response = requests.get(api, headers=headers, params=querystring)

        print(response.status_code)

        rank = int(response.text)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
        # phishing
    else:
        return 0
    # legitimate



"""3.2.3. Age of Domain"""
# 2. Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domain_age(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if isinstance(creation_date, str or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None) or (creation_date is None):
        return 1
    elif (type(expiration_date) is list) or (type(creation_date) is list):
        return 1
    else:
        ageof_domain = abs((expiration_date - creation_date).days)
        if (ageof_domain / 30) < 6:
            age = 1
            """phishing"""
        else:
            age = 0
            """legitimate"""
    return age

"""3.2.4. End Period of Domain"""
# 3.End time of domain: The difference between termination time and current time (Domain_End)
def domain_end(domain_name):
    expiration_date = domain_name.expiration_date

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list:
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if (end / 30) < 6:
            end = 0
            """legitimate"""
        else:
            end = 1
            """not going to expire soon"""
            """phishing coz we are expecting that owner renewed its domain as it is phishing website """
    return end

"""3.3. HTML and JavaScript based Features"""
# IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can
# make use of the “iframe” tag and make it invisible i.e. without frame borders.

# If the iframe is empty or response is not found then, the value assigned to this feature is 1 (phishing) or
# else 0 (legitimate).
""" 3.3.1. IFrame Redirection (iFrame)"""
"""
IFrame Redirection
Status Bar Customization
Disabling Right Click
Website Forwarding
"""

def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[|]", response.text):
            return 0    # iframe redirection is present
        else:
            return 1    # phishing

"""3.3.2. Status Bar Customization"""
# Phishers may use JavaScript to show a fake URL in the status bar to users
# the response is empty or on mouse over is found then, the value assigned to this feature is
# 1 (phishing) or else 0 (legitimate).
# 2.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseover(response):
    if response == "":
        return 1    # phishing
    else:
        if re.findall("", response.text):
            return 1
        else:
            return 0

"""3.3.3. Disabling Right Click"""
# Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code.
# This feature is treated exactly as “Using onMouseOver to hide the Link”
# If the response is empty or on mouse over is not found then, the value assigned to this
# feature is 1 (phishing) or else 0 (legitimate).
# 17.Checks the status of the right click attribute (Right_Click)
def right_click(response):
    if response == "":
        return 1    # phishing
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

"""3.3.4. Website Forwarding"""
# The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected.
# In our dataset, we find that legitimate websites have been redirected one time max.
# On the other hand, phishing websites containing this feature have been redirected at least 4 times.

# 18.Checks the number of forwarding (Web_Forwards)
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1
