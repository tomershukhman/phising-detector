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
import sys
from patterns import *
from class_labels_mapping import (PHISING_LABEL, LEGITIMATE_LABEL, AMBIGUOUS_LABEL)


# Added function to extract features in dictionary format
def extract_features(url, features_to_extract=None):
    """
    Extract phishing detection features from a URL
    
    Args:
        url: The URL string to analyze
        features_to_extract: Optional list of specific features to extract
                            If None, all features will be extracted
        
    Returns:
        Dictionary containing the extracted features
    """
    features = {}
    
    # Define extractable features matching EXACTLY with the column names in dataset_sample.csv
    feature_extractors = {
        'having_ip_address': lambda: having_ip_address(url),
        'url_length': lambda: url_length(url),
        'shortining_service': lambda: shortening_service(url),
        'having_at_symbol': lambda: having_at_symbol(url),
        'double_slash_redirecting': lambda: double_slash_redirecting(url),
        'prefix_suffix': lambda: prefix_suffix(get_hostname_from_url(url)),
        'having_sub_domain': lambda: having_sub_domain(url),
        'domain_registration_length': lambda: extract_domain_reg_length(url),
        'favicon': lambda: extract_favicon(url),
        'https_token': lambda: https_token(url),
        'request_url': lambda: extract_request_url(url),
        'url_of_anchor': lambda: extract_url_of_anchor(url),
        'links_in_tags': lambda: extract_links_in_tags(url),
        'sfh': lambda: extract_sfh(url),
        'submitting_to_email': lambda: extract_submitting_to_email(url),
        'abnormal_url': lambda: extract_abnormal_url(url),
        'iframe': lambda: extract_iframe(url),
        'age_of_domain': lambda: extract_age_of_domain(url),
        'dnsrecord': lambda: extract_dns_record(url),
        'web_traffic': lambda: web_traffic(url),
        'google_index': lambda: google_index(url),
        'statistical_report': lambda: extract_statistical_report(url),
    }
    
    # If specific features are requested, only extract those
    if features_to_extract:
        extractors_to_use = {feat: func for feat, func in feature_extractors.items() if feat in features_to_extract}
    else:
        extractors_to_use = feature_extractors
    
    # Extract all requested features
    for feature_name, extractor_func in extractors_to_use.items():
        try:
            features[feature_name] = extractor_func()
        except Exception as e:
            print(f"Error extracting {feature_name}: {e}")
            features[feature_name] = PHISING_LABEL  # Default to suspicious on error
    
    return features

# Helper functions for feature extraction that need additional processing
def extract_ssl_state(url):
    """Extract SSL state feature"""
    try:
        parsed = urlparse(url)
        if (parsed.scheme == 'https'):
            # Check certificate by making a request
            try:
                response = requests.get(url, timeout=10, verify=True)
                return LEGITIMATE_LABEL  # Legitimate
            except requests.exceptions.SSLError as e:
                print(f"Exception SSL error: {e}")
                return PHISING_LABEL  # Phishing (SSL error)
            except (requests.exceptions.RequestException, Exception) as e:
                print(f"Exception request exception: {e}")
                return PHISING_LABEL  # Suspicious - request failed
        else:
            return PHISING_LABEL  # Phishing (no HTTPS)
    except Exception as e:
        print(f"Exception in extract_ssl_state: {e}")
        return PHISING_LABEL  # Default to phishing
        
def extract_domain_reg_length(url):
    """Extract domain registration length feature"""
    hostname = get_hostname_from_url(url)
    domain = get_domain_from_hostname(hostname)
    return PHISING_LABEL if domain == -1 else domain_registration_length(domain)

def extract_favicon(url):
    """Extract favicon feature"""
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url, timeout=2)
        soup = BeautifulSoup(response.text, 'html.parser')
        return favicon(url, soup, hostname)
    except Exception:
        print(f"[FeatureExtraction] favicon: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_request_url(url):
    """Extract request URL feature"""
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return request_url(url, soup, hostname)
    except Exception:
        print(f"[FeatureExtraction] request_url: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_url_of_anchor(url):
    """Extract URL of anchor feature"""
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return url_of_anchor(url, soup, hostname)
    except Exception:
        print(f"[FeatureExtraction] url_of_anchor: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_links_in_tags(url):
    """Extract links in tags feature"""
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return links_in_tags(url, soup, hostname)
    except Exception:
        print(f"[FeatureExtraction] links_in_tags: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_sfh(url):
    """Extract server form handler feature"""
    hostname = get_hostname_from_url(url)
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return sfh(url, soup, hostname)
    except Exception:
        print(f"[FeatureExtraction] sfh: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_submitting_to_email(url):
    """Extract submitting to email feature"""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return submitting_to_email(soup)
    except Exception:
        print(f"[FeatureExtraction] submitting_to_email: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_abnormal_url(url):
    """Extract abnormal URL feature"""
    hostname = get_hostname_from_url(url)
    domain = get_domain_from_hostname(hostname)
    return PHISING_LABEL if domain == -1 else abnormal_url(domain, url)

def extract_redirect(url):
    """Extract redirect feature"""
    try:
        response = requests.get(url, timeout=10)
        return PHISING_LABEL if len(response.history) > 1 else (0 if len(response.history) == 1 else 1)
    except Exception as e:
        print(f"Error extracting redirect: {e}")
        return PHISING_LABEL  # Suspicious on error

def extract_iframe(url):
    """Extract iframe feature"""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return i_frame(soup)
    except Exception:
        print(f"[FeatureExtraction] iframe: Network/content error for URL: {url}")
        return PHISING_LABEL  # Suspicious on error

def extract_age_of_domain(url):
    """Extract age of domain feature"""
    hostname = get_hostname_from_url(url)
    domain = get_domain_from_hostname(hostname)
    return PHISING_LABEL if domain == -1 else age_of_domain(domain)

def extract_dns_record(url):
    """Extract DNS record feature"""
    hostname = get_hostname_from_url(url)
    domain = get_domain_from_hostname(hostname)
    return PHISING_LABEL if domain == -1 else 1  # 1 means legitimate

def extract_statistical_report(url):
    """Extract statistical report feature"""
    hostname = get_hostname_from_url(url)
    try:
        return statistical_report(url, hostname)
    except Exception:
        print(f"[FeatureExtraction] statistical_report: Error for URL: {url}")
        return 0
    
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
    # Extract only the features needed by the model if columns are specified
    features = extract_features(url, features_to_extract=feature_columns)
    
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
    return PHISING_LABEL if match else 1


def url_length(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return PHISING_LABEL


def shortening_service(url):
    match = re.search(shortening_services, url)
    return PHISING_LABEL if match else 1


def having_at_symbol(url):
    match = re.search('@', url)
    return PHISING_LABEL if match else 1


def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return PHISING_LABEL if last_double_slash > 6 else 1


def prefix_suffix(domain):
    match = re.search('-', domain)
    return PHISING_LABEL if match else 1


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
        return LEGITIMATE_LABEL
    elif len(num_dots) == 4:
        return AMBIGUOUS_LABEL
    else:
        return PHISING_LABEL


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
            return PHISING_LABEL
        
        # Handle case where expiration_date is a list
        expiration_date = domain.expiration_date
        if isinstance(expiration_date, list):
            if not expiration_date:  # Empty list
                return PHISING_LABEL
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
                    return PHISING_LABEL
            except Exception:
                return PHISING_LABEL
        
        # If expiration_date is still not a datetime object after all attempts
        if not isinstance(expiration_date, datetime):
            return PHISING_LABEL
            
        # Calculate registration length in days
        registration_length = (expiration_date - today).days
        
        # Return appropriate value based on registration length
        return LEGITIMATE_LABEL if registration_length > 365 else PHISING_LABEL
        
    except Exception as e:
        print(f"Error in domain_registration_length: {e}")
        return PHISING_LABEL  # Default to phishing if any error occurs


def favicon(url, soup, domain):
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            return LEGITIMATE_LABEL if url in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else PHISING_LABEL
    return LEGITIMATE_LABEL


def https_token(url):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return PHISING_LABEL if match else LEGITIMATE_LABEL


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
        return PHISING_LABEL  # Default to suspicious for other errors

    if percentage < 22.0:
        return LEGITIMATE_LABEL
    elif 22.0 <= percentage < 61.0:
        return AMBIGUOUS_LABEL
    else:
        return PHISING_LABEL


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
        return PHISING_LABEL  # Other errors - suspicious
        
    if percentage < 31.0:
        return LEGITIMATE_LABEL
    elif 31.0 <= percentage < 67.0:
        return AMBIGUOUS_LABEL
    else:
        return PHISING_LABEL


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
        return LEGITIMATE_LABEL  # No tags with links - likely legitimate
    except Exception:
        print("Exception in links_in_tags")
        return PHISING_LABEL  # Other errors - suspicious

    if percentage < 17.0:
        return LEGITIMATE_LABEL
    elif 17.0 <= percentage < 81.0:
        return AMBIGUOUS_LABEL
    else:
        return PHISING_LABEL


def sfh(wiki, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return PHISING_LABEL
        elif wiki not in form['action'] and domain not in form['action']:
            return AMBIGUOUS_LABEL
        else:
            return LEGITIMATE_LABEL
    return LEGITIMATE_LABEL


def submitting_to_email(soup):
    for form in soup.find_all('form', action=True):
        return PHISING_LABEL if "mailto:" in form['action'] else LEGITIMATE_LABEL
    # In case there is no form in the soup, then it is safe to return 1.
    return LEGITIMATE_LABEL


def abnormal_url(domain, url):
    if isinstance(domain.domain_name, list):
        hostname = domain.domain_name[0]
    else:
        hostname = domain.domain_name
    if hostname is None:
        return PHISING_LABEL
    match = re.search(hostname.lower(), url)
    return PHISING_LABEL if match is None else LEGITIMATE_LABEL


def i_frame(soup):
    """Check for suspicious iframes in the HTML"""
    # First check correctly named iframe elements
    for iframe in soup.find_all('iframe', width=True, height=True, frameBorder=True):
        if iframe['width'] == "0" and iframe['height'] == "0" and iframe['frameBorder'] == "0":
            return PHISING_LABEL
        if iframe['width'] == "0" or iframe['height'] == "0" or iframe['frameBorder'] == "0":
            return PHISING_LABEL
            
    # Also check for i_frame as in the original code (though this is likely a typo)
    for i_frames in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        if i_frames['width'] == "0" and i_frames['height'] == "0" and i_frames['frameBorder'] == "0":
            return PHISING_LABEL
        if i_frames['width'] == "0" or i_frames['height'] == "0" or i_frames['frameBorder'] == "0":
            return PHISING_LABEL
    return LEGITIMATE_LABEL  # No suspicious iframes found


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
            return PHISING_LABEL
            
        # Handle case where creation_date is a list
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            if not creation_date:  # Empty list
                return PHISING_LABEL
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
                    return PHISING_LABEL
            except Exception:
                return PHISING_LABEL
                
        # If creation_date is still not a datetime object after all attempts
        if not isinstance(creation_date, datetime):
            return PHISING_LABEL
            
        # Handle case where expiration_date is None or N/A
        if not domain.expiration_date:
            # If we have creation date but no expiration, calculate age from now
            today = datetime.now()
            age_days = (today - creation_date).days
            return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL
            
        # Handle case where expiration_date is a list
        expiration_date = domain.expiration_date
        if isinstance(expiration_date, list):
            if not expiration_date:  # Empty list
                # Calculate age from now
                today = datetime.now()
                age_days = (today - creation_date).days
                return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL
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
                    return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL
            except Exception:
                # Calculate age from now
                today = datetime.now()
                age_days = (today - creation_date).days
                return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL
                
        # If expiration_date is still not a datetime object
        if not isinstance(expiration_date, datetime):
            # Calculate age from now
            today = datetime.now()
            age_days = (today - creation_date).days
            return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL

        # Calculate domain age based on creation and expiration dates
        try:
            age_days = (expiration_date - creation_date).days / 2  # Rough estimate of age as half of registration period
        except Exception:
            # Fallback to current date if calculation fails
            today = datetime.now()
            age_days = (today - creation_date).days
            
        return LEGITIMATE_LABEL if age_days > 180 else PHISING_LABEL  # 180 days = ~6 months
        
    except Exception as e:
        print(f"Error in age_of_domain: {e}")
        return PHISING_LABEL  # Default to suspicious if any error occurs


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
            return LEGITIMATE_LABEL  # Legitimate - likely has good traffic
    
    # Check domain length - extremely long domains are suspicious
    if len(hostname) > 30:
        return PHISING_LABEL  # Phishing - suspicious domain length
    
    # Default to suspicious if we can't determine
    return PHISING_LABEL


def google_index(url):
    site = search(url, 5)
    return LEGITIMATE_LABEL if site else PHISING_LABEL


def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Socket gaierror in statistical_report: {e}")
        # Hostname couldn't be resolved
        return PHISING_LABEL
    except Exception as e:
        print(f"Exception in statistical_report {e}")
        # Any other exception
        return 0
        
    url_match = re.search(suspicious_tlds, url)
    ip_match = re.search(suspicious_ips, ip_address)
    if url_match:
        return PHISING_LABEL
    elif ip_match:
        return PHISING_LABEL
    else:
        return LEGITIMATE_LABEL


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
        return whois.whois(hostname)
    except Exception:
        print(f"[FeatureExtraction] whois: Could not resolve domain for hostname: {hostname}")
        return PHISING_LABEL

