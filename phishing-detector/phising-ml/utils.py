import re
import socket
import requests
from urllib.parse import urlparse
import whois
from bs4 import BeautifulSoup
import dns.resolver
import pandas as pd
from datetime import datetime

def extract_features(url):
    """
    Extract only the 22 phishing detection features we need from a URL
    
    Args:
        url: The URL string to analyze
        
    Returns:
        Dictionary containing the extracted features
    """
    features = {}
    
    # URL-based features
    features['url_length'] = check_url_length(url)
    features['shortining_service'] = check_shortening_service(url)
    features['having_at_symbol'] = check_at_symbol(url)
    features['double_slash_redirecting'] = check_double_slash_redirect(url)
    features['prefix_suffix'] = check_prefix_suffix(url)
    features['having_sub_domain'] = check_sub_domain(url)
    features['sslfinal_state'] = check_ssl_final_state(url)
    features['domain_registration_length'] = check_domain_registration_length(url)
    features['favicon'] = check_favicon(url)
    features['https_token'] = check_https_token(url)
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # HTML content-based features
        features['request_url'] = check_request_url(url, soup)
        features['url_of_anchor'] = check_url_anchor(url, soup)
        features['links_in_tags'] = check_links_in_tags(url, soup)
        features['sfh'] = check_sfh(url, soup)
        features['submitting_to_email'] = check_submit_to_email(soup)
        features['redirect'] = check_redirect(response)
        features['iframe'] = check_iframe(soup)
        
    except:
        # If can't fetch the page, set these features to -1 (suspicious)
        features['request_url'] = -1
        features['url_of_anchor'] = -1
        features['links_in_tags'] = -1
        features['sfh'] = -1
        features['submitting_to_email'] = -1
        features['redirect'] = -1
        features['iframe'] = -1

    # External check features
    features['abnormal_url'] = check_abnormal_url(url)
    features['age_of_domain'] = check_age_of_domain(url)
    features['dnsrecord'] = check_dns_record(url)
    features['web_traffic'] = check_web_traffic(url)
    features['google_index'] = check_google_index(url)
    
    return features

def check_url_length(url):
    """
    Check if URL length is suspicious
    
    Returns:
        1 (phishing) if URL is very long
        0 (suspicious) if URL length is moderate
        -1 (legitimate) if URL length is normal
    """
    if len(url) < 54:
        return -1  # Legitimate
    elif len(url) >= 54 and len(url) <= 75:
        return 0  # Suspicious
    else:
        return 1  # Phishing

def check_shortening_service(url):
    """
    Check if URL uses shortening service
    
    Returns:
        1 (phishing) if shortening service is used, -1 (legitimate) otherwise
    """
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'tr.im', 'is.gd',
        'cli.gs', 'ow.ly', 'shortened.it', 'shorte.st', 'go2l.ink',
        'x.co', 'snip.ly', 'tiny.cc', 'cutt.ly', 'shorturl.at'
    ]
    domain = urlparse(url).netloc
    
    if domain in shortening_services:
        return 1  # Phishing
    return -1  # Legitimate

def check_at_symbol(url):
    """
    Check if URL contains @ symbol
    
    Returns:
        1 (phishing) if @ symbol is present, -1 (legitimate) otherwise
    """
    if '@' in url:
        return 1  # Phishing
    return -1  # Legitimate

def check_double_slash_redirect(url):
    """
    Check if URL contains '//' after domain in path
    
    Returns:
        1 (phishing) if // is in path, -1 (legitimate) otherwise
    """
    parsed = urlparse(url)
    if '//' in parsed.path:
        return 1  # Phishing
    return -1  # Legitimate

def check_prefix_suffix(url):
    """
    Check if URL contains dash (-) in domain
    
    Returns:
        1 (phishing) if dash is in domain, -1 (legitimate) otherwise
    """
    domain = urlparse(url).netloc
    if '-' in domain:
        return 1  # Phishing
    return -1  # Legitimate

def check_sub_domain(url):
    """
    Check number of sub-domains in URL
    
    Returns:
        1 (phishing) if many subdomains
        0 (suspicious) if moderate number of subdomains
        -1 (legitimate) if normal number of subdomains
    """
    domain = urlparse(url).netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Count dots in domain (excluding www. prefix)
    dot_count = domain.count('.')
    
    if dot_count == 1:
        return -1  # Legitimate
    elif dot_count == 2:
        return 0  # Suspicious
    else:
        return 1  # Phishing (more than 2 dots = multiple subdomains)

def check_ssl_final_state(url):
    """
    Check SSL certificate and HTTPS protocol
    
    Returns:
        1 (legitimate) if valid HTTPS and SSL
        0 (suspicious) if mixed content
        -1 (phishing) if no HTTPS or invalid SSL
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            # Check certificate by making a request
            try:
                response = requests.get(url, timeout=10, verify=True)
                return 1  # Legitimate
            except requests.exceptions.SSLError:
                return -1  # Phishing (SSL error)
        else:
            return -1  # Phishing (no HTTPS)
    except:
        return -1  # Default to phishing
    
    return -1  # Default to phishing

def check_domain_registration_length(url):
    """
    Check domain registration length
    
    Returns:
        1 (phishing) if domain registration is less than a year
        -1 (legitimate) if longer registration or can't determine
    """
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        
        # Check if expiration date is available
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                expiration_date = w.expiration_date[0]
            else:
                expiration_date = w.expiration_date
            
            # Calculate years between now and expiration
            current_date = datetime.now()
            years_diff = (expiration_date.year - current_date.year)
            
            if years_diff <= 1:
                return 1  # Phishing (short registration)
            return -1  # Legitimate (long registration)
    except:
        return -1  # If error, assume legitimate
    
    return 1  # Default to phishing

def check_favicon(url):
    """
    Check if favicon is loaded from external domain
    
    Returns:
        1 (phishing) if favicon from external domain
        0 (suspicious) if can't determine
        -1 (legitimate) if favicon from same domain or no favicon
    """
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        favicon = soup.find('link', rel=lambda r: r and ('icon' in r.lower() or 'shortcut icon' in r.lower()))
        
        if favicon and favicon.get('href'):
            favicon_url = favicon['href']
            
            # Check if favicon URL is relative
            if not favicon_url.startswith(('http://', 'https://')):
                return -1  # Legitimate (favicon on same domain)
            
            # If favicon URL is absolute, check if domain matches
            favicon_domain = urlparse(favicon_url).netloc
            url_domain = urlparse(url).netloc
            
            if favicon_domain != url_domain:
                return 1  # Phishing
            return -1  # Legitimate
    except:
        return 0  # Suspicious if can't determine
    
    return -1  # Default to legitimate (no favicon found)

def check_https_token(url):
    """
    Check if HTTPS token exists in domain part
    
    Returns:
        1 (phishing) if HTTPS in domain, -1 (legitimate) otherwise
    """
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1  # Phishing
    return -1  # Legitimate

def check_request_url(url, soup):
    """
    Check if external objects are loaded from different domain
    
    Returns:
        1 (phishing) if many external objects
        0 (suspicious) if moderate external objects
        -1 (legitimate) if few or no external objects
    """
    try:
        external_count = 0
        total_count = 0
        
        url_domain = urlparse(url).netloc
        
        # Check images, videos, sounds, etc.
        for img in soup.find_all('img', src=True):
            total_count += 1
            src = img['src']
            if src.startswith('http'):
                if url_domain not in urlparse(src).netloc:
                    external_count += 1
        
        for audio in soup.find_all('audio', src=True):
            total_count += 1
            src = audio['src']
            if src.startswith('http'):
                if url_domain not in urlparse(src).netloc:
                    external_count += 1
        
        for video in soup.find_all('video', src=True):
            total_count += 1
            src = video['src']
            if src.startswith('http'):
                if url_domain not in urlparse(src).netloc:
                    external_count += 1
        
        if total_count > 0:
            percentage = external_count / float(total_count) * 100
            if percentage < 22.0:
                return -1  # Legitimate
            elif percentage >= 22.0 and percentage < 61.0:
                return 0  # Suspicious
            else:
                return 1  # Phishing
    except:
        return 0  # Suspicious if error
    
    return -1  # Default to legitimate

def check_url_anchor(url, soup):
    """
    Check URL in anchor tags
    
    Returns:
        1 (phishing) if many anchors to external domains
        0 (suspicious) if moderate anchors to external domains
        -1 (legitimate) if few or no anchors to external domains
    """
    try:
        url_domain = urlparse(url).netloc
        
        i = 0
        unsafe = 0
        
        for a in soup.find_all('a', href=True):
            i += 1
            href = a['href']
            
            # Skip anchors that are just "#" or javascript
            if href == "#" or href.startswith("javascript"):
                unsafe += 1
                continue
                
            # Check if href is a full URL and domain is different
            if href.startswith('http'):
                href_domain = urlparse(href).netloc
                if href_domain != url_domain and href_domain != '':
                    unsafe += 1
        
        if i == 0:
            return -1  # Legitimate (no anchors)
        
        percentage = unsafe / float(i) * 100
        
        if percentage < 31.0:
            return -1  # Legitimate
        elif percentage >= 31.0 and percentage < 67.0:
            return 0  # Suspicious
        else:
            return 1  # Phishing
    except:
        return -1  # Assume legitimate if error
    
    return -1  # Default to legitimate

def check_links_in_tags(url, soup):
    """
    Check links in <Meta>, <Script> and <Link> tags
    
    Returns:
        1 (phishing) if many external resources
        0 (suspicious) if moderate external resources
        -1 (legitimate) if few or no external resources
    """
    try:
        url_domain = urlparse(url).netloc
        
        i = 0
        external = 0
        
        for meta in soup.find_all('meta', content=True):
            i += 1
            content = meta['content']
            if content.startswith('http'):
                meta_domain = urlparse(content).netloc
                if meta_domain != url_domain and meta_domain != '':
                    external += 1
        
        for script in soup.find_all('script', src=True):
            i += 1
            src = script['src']
            if src.startswith('http'):
                script_domain = urlparse(src).netloc
                if script_domain != url_domain and script_domain != '':
                    external += 1
        
        for link in soup.find_all('link', href=True):
            i += 1
            href = link['href']
            if href.startswith('http'):
                link_domain = urlparse(href).netloc
                if link_domain != url_domain and link_domain != '':
                    external += 1
        
        if i == 0:
            return -1  # Legitimate (no such tags)
        
        percentage = external / float(i) * 100
        
        if percentage < 17.0:
            return -1  # Legitimate
        elif percentage >= 17.0 and percentage < 81.0:
            return 0  # Suspicious
        else:
            return 1  # Phishing
    except:
        return -1  # Assume legitimate if error
    
    return -1  # Default to legitimate

def check_sfh(url, soup):
    """
    Check Server Form Handler (SFH)
    
    Returns:
        1 (phishing) if SFH is about:blank or empty
        0 (suspicious) if SFH to different domain
        -1 (legitimate) otherwise
    """
    try:
        url_domain = urlparse(url).netloc
        
        for form in soup.find_all('form', action=True):
            action = form['action']
            
            # Empty action or about:blank
            if action == "" or action == "about:blank":
                return 1  # Phishing
            
            # Check if action is a URL with different domain
            if action.startswith('http'):
                action_domain = urlparse(action).netloc
                if action_domain != url_domain and action_domain != '':
                    return 0  # Suspicious
        
        return -1  # Legitimate (no suspicious forms)
    except:
        return -1  # Assume legitimate if error
    
    return -1  # Default to legitimate

def check_submit_to_email(soup):
    """
    Check if form submits to email
    
    Returns:
        1 (phishing) if form submits to email, -1 (legitimate) otherwise
    """
    try:
        for form in soup.find_all('form'):
            if form.get('action') and 'mailto:' in form.get('action'):
                return 1  # Phishing
            
        # Look for mail() function in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'mail(' in script.string:
                return 1  # Phishing
        
        return -1  # Legitimate
    except:
        return -1  # Assume legitimate if error
    
    return -1  # Default to legitimate

def check_abnormal_url(url):
    """
    Check if URL is abnormal based on WHOIS data
    
    Returns:
        1 (phishing) if URL doesn't match WHOIS identity
        -1 (legitimate) if URL matches identity or can't determine
    """
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        
        # If domain name is not in the WHOIS database or hostname not found
        if not w.domain_name:
            return 1  # Phishing
        
        # Check if domain name appears in the URL
        domain_name = str(w.domain_name)
        if isinstance(w.domain_name, list):
            domain_name = w.domain_name[0]
        
        # Remove TLD from domain name for comparison
        if '.' in domain_name:
            base_domain = domain_name.split('.')[0]
            if base_domain.lower() not in url.lower():
                return 1  # Phishing
        
        return -1  # Legitimate
    except:
        return 1  # Phishing if error (domain likely doesn't exist)
    
    return -1  # Default to legitimate

def check_redirect(response):
    """
    Check for URL redirection
    
    Returns:
        1 (phishing) if multiple redirections
        0 (suspicious) if one redirection
        -1 (legitimate) if no redirection
    """
    try:
        if len(response.history) == 0:
            return -1  # Legitimate (no redirection)
        elif len(response.history) == 1:
            return 0  # Suspicious (one redirection)
        else:
            return 1  # Phishing (multiple redirections)
    except:
        return 0  # Default to suspicious
    
    return 0  # Default to suspicious

def check_iframe(soup):
    """
    Check for IFrame redirection
    
    Returns:
        1 (phishing) if invisible iframes are present
        0 (suspicious) if any iframes are present
        -1 (legitimate) if no iframes
    """
    try:
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            # Check for invisible iframes (common in phishing)
            if iframe.get('frameborder') == '0' or iframe.get('style') and 'display:none' in iframe.get('style'):
                return 1  # Phishing
        
        if len(iframes) > 0:
            return 0  # Suspicious
        
        return -1  # Legitimate (no iframes)
    except:
        return -1  # Assume legitimate if error
    
    return -1  # Default to legitimate

def check_age_of_domain(url):
    """
    Check age of domain
    
    Returns:
        1 (phishing) if domain is less than 6 months old
        -1 (legitimate) if domain is older or can't determine
    """
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        
        # Check if creation date is available
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            # Calculate domain age in months
            current_date = datetime.now()
            age = (current_date.year - creation_date.year) * 12 + (current_date.month - creation_date.month)
            
            if age >= 6:
                return -1  # Legitimate (older than 6 months)
            return 1  # Phishing (younger than 6 months)
    except:
        return 1  # Phishing if error (domain likely doesn't exist)
    
    return 1  # Default to phishing

def check_dns_record(url):
    """
    Check DNS record
    
    Returns:
        1 (phishing) if no DNS records found
        -1 (legitimate) if DNS records exist
    """
    try:
        domain = urlparse(url).netloc
        dns_query = dns.resolver.resolve(domain, 'A')
        if dns_query:
            return -1  # Legitimate (DNS record exists)
    except:
        return 1  # Phishing (no DNS record or error)
    
    return -1  # Default to legitimate

def check_web_traffic(url):
    """
    Check website traffic based on domain popularity
    
    Returns:
        1 (phishing) if likely low traffic
        0 (suspicious) if moderate traffic
        -1 (legitimate) if likely high traffic
    """
    try:
        domain = urlparse(url).netloc
        
        # Check for popular domains
        popular_domains = [
            'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin', 
            'amazon', 'apple', 'microsoft', 'github', 'stackoverflow', 'reddit',
            'wikipedia', 'yahoo', 'netflix', 'spotify', 'ebay', 'cnn'
        ]
        
        # Extract base domain
        base_domain = domain
        if '.' in domain:
            base_domain = domain.split('.')[0]
            if base_domain.startswith('www'):
                base_domain = domain.split('.')[1] if len(domain.split('.')) > 2 else base_domain
        
        # Check if it's a known popular domain
        for popular in popular_domains:
            if popular in base_domain.lower():
                return -1  # High traffic (legitimate)
        
        # Try to check DNS records - domains with multiple records often have higher traffic
        try:
            dns_records = dns.resolver.resolve(domain, 'A')
            if len(dns_records) > 1:
                return 0  # Moderate traffic
        except:
            pass
            
        # If we can't determine, assume low traffic
        return 1  # Low traffic (suspicious)
    except:
        return 1  # Default to suspicious

def check_google_index(url):
    """
    Check if URL is likely indexed by Google
    
    Returns:
        1 (phishing) if likely not indexed
        -1 (legitimate) if likely indexed
    """
    try:
        domain = urlparse(url).netloc
        
        # Popular domains are almost certainly indexed
        popular_domains = [
            'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin', 
            'amazon', 'apple', 'microsoft', 'github', 'stackoverflow'
        ]
        
        # Check if it's a known domain
        for popular in popular_domains:
            if popular in domain.lower():
                return -1  # Indexed (legitimate)
        
        # Check domain age - if older than 1 year, more likely indexed
        try:
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                # Calculate domain age in months
                current_date = datetime.now()
                age = (current_date.year - creation_date.year) * 12 + (current_date.month - creation_date.month)
                
                if age >= 12:
                    return -1  # Likely indexed (legitimate)
        except:
            pass
            
        # Check for suspicious patterns
        if any(x in url for x in ['login', 'password', 'secure', 'account']):
            if any(x in url for x in ['.tk', '.ml', '.ga', '.cf', '.xyz']):
                return 1  # Not indexed (suspicious)
                
        # If it has proper DNS records, it's more likely to be indexed
        try:
            dns.resolver.resolve(domain, 'A')
            return -1  # Probably indexed (legitimate)
        except:
            return 1  # Not indexed (suspicious)
    except:
        return 1  # Default to suspicious

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
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    return {
        "url": url,
        "prediction": result,
        "raw_prediction": prediction
    }