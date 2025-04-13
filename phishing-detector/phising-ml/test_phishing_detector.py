import unittest
from utils import extract_url_features, extract_html_features, predict_phishing

class TestPhishingDetector(unittest.TestCase):
    def setUp(self):
        # Known legitimate URLs
        self.legitimate_urls = [
            'https://www.google.com',
            'https://github.com',
            'https://www.microsoft.com/en-us',
            'https://stackoverflow.com/questions',
            'https://www.amazon.com/dp/B08F7N9ZF4'
        ]

        # Known phishing patterns
        self.phishing_urls = [
            'http://googgle-secure-signin.com',  # Typosquatting
            'https://paypal-account-secure-login.com',  # Brand + security words
            'http://login-secure-bankofamerica.tk',  # Suspicious TLD
            'https://facebook.login-verify-account.net',  # Brand in subdomain
            'http://192.168.1.1/login.php',  # IP address URL
            'http://bit.ly/3xF9ke',  # URL shortener
            'https://secure-login123.com',  # Numeric domain
            'https://account-verify-signin.com/login',  # Multiple security keywords
            'http://bankofarnerica.com',  # Character replacement
            'https://www.paypal.com.secure-login.net'  # Domain spoofing
        ]

        # Ambiguous URLs (legitimate but with suspicious patterns)
        self.ambiguous_urls = [
            'https://login.microsoftonline.com',  # Legitimate login portal
            'https://accounts.google.com',  # Legitimate account page
            'https://www.bankofamerica.com/login',  # Legitimate bank login
            'https://github.com/login',  # Legitimate login page
            'https://bit.ly/github'  # Legitimate shortened URL
        ]

    def test_legitimate_urls(self):
        """Test detection of legitimate URLs"""
        print("\n=== Testing Legitimate URLs ===")
        for url in self.legitimate_urls:
            result = predict_phishing(url)
            if result:
                print(f"\nURL: {url}")
                print(f"Prediction: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
                print(f"Confidence: {result['confidence']:.2f}")
                self.assertFalse(result['is_phishing'], 
                               f"False positive on legitimate URL: {url}")

    def test_phishing_urls(self):
        """Test detection of phishing URLs"""
        print("\n=== Testing Phishing URLs ===")
        for url in self.phishing_urls:
            result = predict_phishing(url)
            if result:
                print(f"\nURL: {url}")
                print(f"Prediction: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
                print(f"Confidence: {result['confidence']:.2f}")
                self.assertTrue(result['is_phishing'], 
                              f"Failed to detect phishing URL: {url}")

    def test_ambiguous_urls(self):
        """Test handling of ambiguous URLs"""
        print("\n=== Testing Ambiguous URLs ===")
        for url in self.ambiguous_urls:
            result = predict_phishing(url)
            if result:
                print(f"\nURL: {url}")
                print(f"Prediction: {'Phishing' if result['is_phishing'] else 'Legitimate'}")
                print(f"Confidence: {result['confidence']:.2f}")
                # For ambiguous URLs, we mainly want to see the confidence levels
                # rather than assert a specific outcome

    def test_url_feature_extraction(self):
        """Test URL feature extraction"""
        url = "https://www.example-test123.com/login?user=test"
        features = extract_url_features(url)
        
        self.assertEqual(features['URLLength'], len(url))
        self.assertEqual(features['IsHTTPS'], 1)
        self.assertTrue('NumDigitsInURL' in features)
        self.assertTrue('HasSensitiveKeyword' in features)

    def test_edge_cases(self):
        """Test edge cases and malformed URLs"""
        edge_cases = [
            'not_a_url',  # Invalid URL
            'https://',   # Incomplete URL
            'http://localhost',  # Local URL
            'https://test.test', # Non-existent TLD
            'data:text/html,<script>alert("test")</script>'  # Data URL
        ]
        
        print("\n=== Testing Edge Cases ===")
        for url in edge_cases:
            result = predict_phishing(url)
            print(f"\nTesting URL: {url}")
            print(f"Result: {result}")
            # Edge cases should either return None or be classified as suspicious
            if result:
                self.assertTrue(result['is_phishing'] or result['confidence'] < 0.6,
                              f"Edge case {url} incorrectly classified as legitimate with high confidence")

if __name__ == '__main__':
    unittest.main(verbosity=2)