# Skripta e cila nxjerr vetit e faqes nga url i ofruar
# dhe nga permbajtja e faqes e ofruar ne fajllin innerHTML.txt
# 1 = e sigurt
# 0 = e dyshimit
# -1 = phishing
from bs4 import BeautifulSoup
import urllib.request
import bs4
import re
import socket
import whois  # This might be either python-whois or another whois module
from datetime import datetime
import time
from googlesearch import search
import pandas as pd
import requests
from urllib.parse import urlparse
import os

# Check which whois module we have and set up the appropriate function
try:
    # Test if we have python-whois with whois() function
    test_whois = whois.whois("google.com")
    def perform_whois(hostname):
        return whois.whois(hostname)
except AttributeError:
    # If attribute error, we might have the whois module without the whois function
    # Try to use it directly as a callable
    try:
        test_whois = whois("google.com")
        def perform_whois(hostname):
            return whois(hostname)
    except Exception:
        # If that fails too, create a stub function that always returns -1
        print("Warning: No functional whois module found. Domain checks will be limited.")
        def perform_whois(hostname):
            return -1
except Exception as e:
    print(f"Error initializing whois functionality: {e}")
    # Create a stub function that always returns -1
    def perform_whois(hostname):
        return -1

# This import is needed only when you run this file in isolation.
import sys

from patterns import *

# Path - use a relative path that will work in any environment
# We don't need this for the extract_features implementation which doesn't use the file
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
INNERHTML_PATH = os.path.join(CURRENT_DIR, "innerHTML.txt")

# Added function to extract features in dictionary format
def extract_features(url):
    """
    Extract phishing detection features from a URL
    
    Args:
        url: The URL string to analyze
        
    Returns:
        Dictionary containing the extracted features
    """
    features = {}
    
    # URL-based features directly from existing functions
    features['url_length'] = url_length(url)
    features['shortining_service'] = shortening_service(url)
    features['having_at_symbol'] = having_at_symbol(url)
    features['double_slash_redirecting'] = double_slash_redirecting(url)
    
    hostname = get_hostname_from_url(url)
    features['prefix_suffix'] = prefix_suffix(hostname)
    features['having_sub_domain'] = having_sub_domain(url)
    
    # SSL features (new implementation)
    try:
        parsed = urlparse(url)
        if (parsed.scheme == 'https'):
            # Check certificate by making a request
            try:
                response = requests.get(url, timeout=10, verify=True)
                features['sslfinal_state'] = 1  # Legitimate
            except requests.exceptions.SSLError as e:
                print(f"Exception SSL error in extract_feature is: {e}")
                features['sslfinal_state'] = -1  # Phishing (SSL error)
            except (requests.exceptions.RequestException, Exception) as e:
                print(f"Exception request exception in extract_feature is: {e}")
                features['sslfinal_state'] = 0  # Suspicious - request failed
        else:
            features['sslfinal_state'] = -1  # Phishing (no HTTPS)
    except Exception as e:
        print(f"Exception other in extract_feature is: {e}")
        features['sslfinal_state'] = -1  # Default to phishing
    
    # Domain features
    domain = get_domain_from_hostname(hostname)
    features['domain_registration_length'] = -1 if domain == -1 else domain_registration_length(domain)
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # HTML and DOM-based features
        features['favicon'] = favicon(url, soup, hostname)
        features['https_token'] = https_token(url)
        features['request_url'] = request_url(url, soup, hostname)
        features['url_of_anchor'] = url_of_anchor(url, soup, hostname)
        features['links_in_tags'] = links_in_tags(url, soup, hostname)
        features['sfh'] = sfh(url, soup, hostname)
        features['submitting_to_email'] = submitting_to_email(soup)
        
        # Check redirect
        features['redirect'] = -1 if len(response.history) > 1 else (0 if len(response.history) == 1 else 1)
        
        # Check iframe
        features['iframe'] = i_frame(soup)
        
    except Exception as e:
        pass

    # External check features
    features['abnormal_url'] = -1 if domain == -1 else abnormal_url(domain, url)
    features['age_of_domain'] = -1 if domain == -1 else age_of_domain(domain)
    
    # DNS record (defaulting to existing implementation)
    features['dnsrecord'] = -1 if domain == -1 else 1  # 1 means legitimate
    
    # Web traffic and Google index
    features['web_traffic'] = web_traffic(url)
    features['google_index'] = google_index(url)
    
    return features

def predict_url(url, model, feature_columns=None):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        url: The URL to analyze
        model: The trained machine learning model
        feature_columns: Optional list of feature column names expected by the model
                         If None, will use the features as extracted
        
    Returns:
        Dictionary with prediction result and URL
    """
    # Extract features from URL
    features = extract_features(url)
    
    # Convert extracted features to DataFrame
    features_df = pd.DataFrame([features])
    
    if feature_columns is not None:
        # Make sure all expected columns exist (fill missing with 0)
        for col in feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0
                
        # Use only the columns expected by the model
        features_df = features_df[feature_columns]
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == -1 else "Legitimate"
    
    return {
        "url": url,
        "prediction": result,
        "raw_prediction": prediction
    }

def having_ip_address(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1


def url_length(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1


def shortening_service(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1


def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1


def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1


def prefix_suffix(domain):
    match = re.search('-', domain)
    return -1 if match else 1


def having_sub_domain(url):
    if having_ip_address(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1


def domain_registration_length(domain):
    """
    Check domain registration length
    Returns:
      1 if domain registration length > 1 year (legitimate)
     -1 if domain registration length <= 1 year (suspicious/phishing)
    Handles all edge cases without crashing
    """
    try:
        # Get today's date for comparison
        today = datetime.now()
        
        # Handle case where expiration_date is None or N/A
        if not domain.expiration_date:
            return -1
        
        # Handle case where expiration_date is a list
        expiration_date = domain.expiration_date
        if isinstance(expiration_date, list):
            if not expiration_date:  # Empty list
                return -1
            expiration_date = expiration_date[0]
        
        # Handle different string formats or None value
        if isinstance(expiration_date, str):
            try:
                # Try to parse common date formats
                for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y.%m.%d', '%d.%m.%Y', '%Y/%m/%d', '%d/%m/%Y']:
                    try:
                        expiration_date = datetime.strptime(expiration_date, fmt)
                        break
                    except ValueError:
                        continue
                else:  # If no format matched
                    return -1
            except Exception:
                return -1
        
        # If expiration_date is still not a datetime object after all attempts
        if not isinstance(expiration_date, datetime):
            return -1
            
        # Calculate registration length in days
        registration_length = (expiration_date - today).days
        
        # Return appropriate value based on registration length
        return 1 if registration_length > 365 else -1
        
    except Exception as e:
        print(f"Error in domain_registration_length: {e}")
        return -1  # Default to suspicious if any error occurs


def favicon(url, soup, domain):
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            return 1 if url in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else -1
    return 1


def https_token(url):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1


def request_url(wiki, soup, domain):
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i) * 100
    except ZeroDivisionError:
        #print("ZeroDivisionError in request_url")
        return 1
    except Exception:
        print("Exception in request_url")
        return 0  # Default to suspicious for other errors

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1


def url_of_anchor(wiki, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        # javascript per 'JavaScript ::void(0)'
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        
    try:
        percentage = unsafe / float(i) * 100
    except ZeroDivisionError:
        #print("ZeroDivisionError in url_of_anchor")
        return 1  # No anchor tags - likely legitimate
    except Exception:
        print("Exception in url_of_anchor")
        return 0  # Other errors - suspicious
        
    if percentage < 31.0:
        return 1
    elif 31.0 <= percentage < 67.0:
        return 0
    else:
        return -1


def links_in_tags(wiki, soup, domain):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
        
    try:
        percentage = success / float(i) * 100
    except ZeroDivisionError:
        #print("ZeroDivisionError in links_in_tags")
        return 1  # No tags with links - likely legitimate
    except Exception:
        print("Exception in links_in_tags")
        return 0  # Other errors - suspicious

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1


def sfh(wiki, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif wiki not in form['action'] and domain not in form['action']:
            return 0
        else:
            return 1
    return 1


def submitting_to_email(soup):
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    # In case there is no form in the soup, then it is safe to return 1.
    return 1


def abnormal_url(domain, url):
    if isinstance(domain.domain_name, list):
        hostname = domain.domain_name[0]
    else:
        hostname = domain.domain_name
    if hostname is None:
        return -1
    match = re.search(hostname.lower(), url)
    return -1 if match is None else 1


def i_frame(soup):
    """Check for suspicious iframes in the HTML"""
    # First check correctly named iframe elements
    for iframe in soup.find_all('iframe', width=True, height=True, frameBorder=True):
        if iframe['width'] == "0" and iframe['height'] == "0" and iframe['frameBorder'] == "0":
            return -1
        if iframe['width'] == "0" or iframe['height'] == "0" or iframe['frameBorder'] == "0":
            return 0
            
    # Also check for i_frame as in the original code (though this is likely a typo)
    for i_frames in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        if i_frames['width'] == "0" and i_frames['height'] == "0" and i_frames['frameBorder'] == "0":
            return -1
        if i_frames['width'] == "0" or i_frames['height'] == "0" or i_frames['frameBorder'] == "0":
            return 0
    return 1


def age_of_domain(domain):
    """
    Check age of domain
    Returns:
      1 if domain age > 6 months (legitimate)
     -1 if domain age <= 6 months or can't be determined (suspicious/phishing)
    Handles all edge cases without crashing
    """
    try:
        # Handle case where creation_date is None or N/A
        if not domain.creation_date:
            return -1
            
        # Handle case where creation_date is a list
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            if not creation_date:  # Empty list
                return -1
            creation_date = creation_date[0]
            
        # Handle different string formats or None value for creation_date
        if isinstance(creation_date, str):
            try:
                # Try to parse common date formats
                for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y.%m.%d', '%d.%m.%Y', '%Y/%m/%d', '%d/%m/%Y']:
                    try:
                        creation_date = datetime.strptime(creation_date, fmt)
                        break
                    except ValueError:
                        continue
                else:  # If no format matched
                    return -1
            except Exception:
                return -1
                
        # If creation_date is still not a datetime object after all attempts
        if not isinstance(creation_date, datetime):
            return -1
            
        # Handle case where expiration_date is None or N/A
        if not domain.expiration_date:
            # If we have creation date but no expiration, calculate age from now
            today = datetime.now()
            age_days = (today - creation_date).days
            return 1 if age_days > 180 else -1
            
        # Handle case where expiration_date is a list
        expiration_date = domain.expiration_date
        if isinstance(expiration_date, list):
            if not expiration_date:  # Empty list
                # Calculate age from now
                today = datetime.now()
                age_days = (today - creation_date).days
                return 1 if age_days > 180 else -1
            expiration_date = expiration_date[0]
            
        # Handle different string formats for expiration_date
        if isinstance(expiration_date, str):
            try:
                # Try to parse common date formats
                for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y.%m.%d', '%d.%m.%Y', '%Y/%m/%d', '%d/%m/%Y']:
                    try:
                        expiration_date = datetime.strptime(expiration_date, fmt)
                        break
                    except ValueError:
                        continue
                else:  # If no format matched
                    # Calculate age from now
                    today = datetime.now()
                    age_days = (today - creation_date).days
                    return 1 if age_days > 180 else -1
            except Exception:
                # Calculate age from now
                today = datetime.now()
                age_days = (today - creation_date).days
                return 1 if age_days > 180 else -1
                
        # If expiration_date is still not a datetime object
        if not isinstance(expiration_date, datetime):
            # Calculate age from now
            today = datetime.now()
            age_days = (today - creation_date).days
            return 1 if age_days > 180 else -1

        # Calculate domain age based on creation and expiration dates
        try:
            age_days = (expiration_date - creation_date).days / 2  # Rough estimate of age as half of registration period
        except Exception:
            # Fallback to current date if calculation fails
            today = datetime.now()
            age_days = (today - creation_date).days
            
        return 1 if age_days > 180 else -1  # 180 days = ~6 months
        
    except Exception as e:
        print(f"Error in age_of_domain: {e}")
        return -1  # Default to suspicious if any error occurs


def web_traffic(url):
    """
    Analyze web traffic for a given URL
    
    Since Alexa service has been discontinued, this uses alternative methods
    """
    hostname = get_hostname_from_url(url)
    
    # List of known popular domains (simplified heuristic)
    popular_domains = [
        'google', 'facebook', 'youtube', 'twitter', 'instagram', 'linkedin', 
        'github', 'apple', 'microsoft', 'amazon', 'netflix', 'yahoo', 'ebay',
        'paypal', 'spotify', 'adobe', 'dropbox', 'salesforce', 'slack', 'zoom',
        'twitch', 'reddit', 'tiktok', 'snapchat', 'pinterest', 'walmart', 'target',
        'chase', 'bankofamerica', 'wellsfargo', 'citi'
    ]
    
    # Check if hostname contains any of the popular domain names
    for domain in popular_domains:
        if domain in hostname and (
            # Make sure it's not just a substring but a major part of the domain
            domain == hostname or 
            hostname.startswith(domain + '.') or
            hostname.endswith('.' + domain + '.') or
            hostname.endswith('.' + domain) or
            '.' + domain + '.' in hostname
        ):
            return 1  # Legitimate - likely has good traffic
    
    # Check domain length - extremely long domains are suspicious
    if len(hostname) > 30:
        return -1  # Phishing - suspicious domain length
    
    # Default to suspicious if we can't determine
    return 0


def google_index(url):
    site = search(url, 5)
    return 1 if site else -1


def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Socket gaierror in statistical_report: {e}")
        # Hostname couldn't be resolved
        return -1
    except Exception as e:
        print(f"Exception in statistical_report {e}")
        # Any other exception
        return 0
        
    url_match = re.search(suspicious_tlds, url)
    ip_match = re.search(suspicious_ips, ip_address)
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1


def get_hostname_from_url(url):
    hostname = url
    pattern = "https://www.|http://www.|https://|http://|www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname


def get_domain_from_hostname(hostname):
    try:
        domain = perform_whois(hostname)
        return domain
    except Exception as e:
        # Handle any whois exceptions more generically
        print(f"Whois error in get_domain_from_hostname: {e}")
        # Domain doesn't exist or couldn't be processed
        return -1


def main(url):
    with open(INNERHTML_PATH, 'r', encoding='utf8') as file:
        soup_string = file.read()

    soup = BeautifulSoup(soup_string, 'html.parser')

    status = []
    hostname = get_hostname_from_url(url)

    status.append(having_ip_address(url))
    status.append(url_length(url))
    status.append(shortening_service(url))
    status.append(having_at_symbol(url))
    status.append(double_slash_redirecting(url))
    status.append(prefix_suffix(hostname))
    status.append(having_sub_domain(url))

    domain = get_domain_from_hostname(hostname)

    status.append(-1 if domain == -1 else domain_registration_length(domain))

    status.append(favicon(url, soup, hostname))
    status.append(https_token(url))
    status.append(request_url(url, soup, hostname))
    status.append(url_of_anchor(url, soup, hostname))
    status.append(links_in_tags(url, soup, hostname))
    status.append(sfh(url, soup, hostname))
    status.append(submitting_to_email(soup))

    status.append(-1 if domain == -1 else abnormal_url(domain, url))

    status.append(i_frame(soup))

    status.append(-1 if domain == -1 else age_of_domain(domain))

    status.append(-1 if domain == -1 else 1)

    status.append(web_traffic(url))
    status.append(google_index(url))
    status.append(statistical_report(url, hostname))

    # print('\n1. Having IP address\n2. URL Length\n3. URL Shortening service\n4. Having @ symbol\n'
    #     '5. Having double slash\n6. Having dash symbol(Prefix Suffix)\n7. Having multiple subdomains\n'
    #    '8. Domain Registration Length\n9. Favicon\n10. HTTP or HTTPS token in domain name\n'
    #   '11. Request URL\n12. URL of Anchor\n13. Links in tags\n14. SFH\n15. Submitting to email\n16. Abnormal URL\n'
    #  '17. IFrame\n18. Age of Domain\n19. DNS Record\n20. Web Traffic\n21. Google Index\n22. Statistical Reports\n')
    # print(status)
    return status