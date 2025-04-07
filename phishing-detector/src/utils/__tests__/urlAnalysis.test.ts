import { UrlAnalyzer } from '../urlAnalysis';

describe('UrlAnalyzer', () => {
  let analyzer: UrlAnalyzer;

  beforeEach(() => {
    analyzer = new UrlAnalyzer();
  });

  describe('Safe URLs', () => {
    it('should identify legitimate URLs as low risk', () => {
      const safeUrls = [
        'https://www.google.com',
        'https://facebook.com',
        'https://amazon.com/products',
        'https://github.com',
        'https://edu.stanford.edu'
      ];

      safeUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.risk).toBeLessThan(0.3);
        expect(analyzer.getRiskLevel(result.risk)).toBe('Low');
        expect(result.flags).toHaveLength(0);
      });
    });
  });

  describe('Brand Impersonation Detection', () => {
    it('should detect typosquatting attempts', () => {
      const suspiciousUrls = [
        'https://googgle.com',
        'https://faceb00k.com',
        'https://paypa1.com',
        'https://arnazon.com'
      ];

      suspiciousUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.flags).toContain('BRAND_IMPERSONATION');
        expect(result.brandMatches).toBe(true);
        expect(result.typosquatting).toBeTruthy();
        expect(analyzer.getRiskLevel(result.risk)).not.toBe('Low');
      });
    });

    it('should detect brand names in subdomains', () => {
      const result = analyzer.analyzeUrl('https://login-paypal.malicious.com');
      expect(result.flags).toContain('BRAND_IMPERSONATION');
      expect(result.brandMatches).toBe(true);
      expect(result.risk).toBeGreaterThan(0.3);
    });
  });

  describe('Technical Indicators', () => {
    it('should detect IP address URLs', () => {
      const result = analyzer.analyzeUrl('http://192.168.1.1/login');
      expect(result.flags).toContain('IP_ADDRESS_URL');
      expect(result.risk).toBeGreaterThan(0.3);
    });

    it('should detect suspicious TLDs', () => {
      const result = analyzer.analyzeUrl('https://login.account.tk');
      expect(result.flags).toContain('UNCOMMON_TLD');
    });

    it('should detect excessive subdomains', () => {
      const result = analyzer.analyzeUrl('https://login.account.security.bank.suspicious.com');
      expect(result.flags).toContain('EXCESSIVE_SUBDOMAINS');
    });

    it('should detect special characters in domain', () => {
      const result = analyzer.analyzeUrl('https://paypal-secure@login.com');
      expect(result.flags).toContain('SPECIAL_CHARS_IN_DOMAIN');
    });
  });

  describe('Content and Pattern Detection', () => {
    it('should detect suspicious keywords', () => {
      const result = analyzer.analyzeUrl('https://secure-login-account-verify.com');
      expect(result.suspiciousPatterns).toContain('login');
      expect(result.suspiciousPatterns).toContain('secure');
      expect(result.suspiciousPatterns).toContain('verify');
    });

    it('should detect suspicious file extensions', () => {
      const result = analyzer.analyzeUrl('https://download.com/update.exe');
      expect(result.flags).toContain('SUSPICIOUS_FILE_EXTENSION');
    });

    it('should detect data URI schemes', () => {
      const result = analyzer.analyzeUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
      expect(result.flags).toContain('DATA_URI_SCHEME');
      expect(result.risk).toBeGreaterThan(0.4);
    });

    it('should detect URL encoding abuse', () => {
      const result = analyzer.analyzeUrl('https://login.com/%70%61%79%70%61%6C.com');
      expect(result.flags).toContain('EXCESSIVE_ENCODING');
    });
  });

  describe('Combined Risk Factors', () => {
    it('should identify high-risk URLs with multiple suspicious features', () => {
      const result = analyzer.analyzeUrl('https://secure-paypal.login.account-verify.tk/signin.php');
      expect(result.risk).toBeGreaterThan(0.6);
      expect(analyzer.getRiskLevel(result.risk)).toBe('High');
      expect(result.flags).toContain('UNCOMMON_TLD');
      expect(result.flags).toContain('BRAND_IMPERSONATION');
      expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle invalid URLs', () => {
      const result = analyzer.analyzeUrl('not-a-valid-url');
      expect(result.flags).toContain('INVALID_URL');
      expect(result.risk).toBe(1);
      expect(analyzer.getRiskLevel(result.risk)).toBe('High');
    });

    it('should handle URLs with no suspicious features', () => {
      const result = analyzer.analyzeUrl('https://example.com');
      expect(result.risk).toBeLessThan(0.3);
      expect(result.flags).toHaveLength(0);
      expect(result.suspiciousPatterns).toHaveLength(0);
    });

    it('should handle URLs with query parameters', () => {
      const result = analyzer.analyzeUrl('https://example.com/path?redirect=https://paypal.com');
      expect(result.flags).toContain('REDIRECT_PRESENT');
    });
  });
});