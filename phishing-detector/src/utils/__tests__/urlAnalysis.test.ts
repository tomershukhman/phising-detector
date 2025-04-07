import { UrlAnalyzer } from '../urlAnalysis.js';
import * as fs from 'fs';
import * as path from 'path';
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { parse } from 'csv-parse/sync';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

function categorizeUrl(url: string): string[] {
  const categories = [];
  try {
    const urlObj = new URL(url);
    
    // Categorize by TLD
    const tld = urlObj.hostname.split('.').pop();
    categories.push(`tld_${tld}`);
    
    // Categorize by protocol
    categories.push(urlObj.protocol.replace(':', ''));
    
    // Categorize by domain structure
    const subdomains = urlObj.hostname.split('.').length;
    categories.push(`subdomain_count_${subdomains}`);
    
    // Categorize by path depth
    const pathDepth = urlObj.pathname.split('/').filter(Boolean).length;
    categories.push(`path_depth_${pathDepth}`);
    
    // Categorize by query parameters
    categories.push(urlObj.search ? 'has_query' : 'no_query');
    
  } catch {
    categories.push('invalid_url');
  }
  return categories;
}

function stratifiedSample(urls: string[], sampleSize: number): string[] {
  const categorized = new Map<string, string[]>();
  
  // Categorize URLs
  urls.forEach(url => {
    const categories = categorizeUrl(url);
    categories.forEach(category => {
      if (!categorized.has(category)) {
        categorized.set(category, []);
      }
      categorized.get(category)?.push(url);
    });
  });

  const result = new Set<string>();
  
  // Sample from each category proportionally
  categorized.forEach((categoryUrls, category) => {
    const categorySize = Math.max(1, Math.floor((categoryUrls.length / urls.length) * sampleSize));
    const shuffled = [...categoryUrls].sort(() => 0.5 - Math.random());
    shuffled.slice(0, categorySize).forEach(url => result.add(url));
  });

  // If we haven't met our sample size, add random URLs
  const remainingSamples = [...urls]
    .sort(() => 0.5 - Math.random())
    .filter(url => !result.has(url));
  
  while (result.size < sampleSize && remainingSamples.length > 0) {
    result.add(remainingSamples.pop()!);
  }

  return [...result];
}

describe('Dataset Testing', () => {
  let analyzer: UrlAnalyzer;

  beforeAll(() => {
    analyzer = new UrlAnalyzer();
  });

  it('should correctly analyze stratified samples from both datasets', () => {
    // Read both datasets
    const phishingUrls = fs.readFileSync(path.join(__dirname, '../../data/phishing.csv'), 'utf-8')
      .split('\n')
      .filter(url => url.trim()); // Remove empty lines
    
    const legitUrls = fs.readFileSync(path.join(__dirname, '../../data/legitimate.csv'), 'utf-8')
      .split('\n')
      .filter(url => url.trim()); // Remove empty lines

    // Take 5% stratified samples
    const phishingSample = stratifiedSample(phishingUrls, Math.ceil(phishingUrls.length * 0.05));
    const legitSample = stratifiedSample(legitUrls, Math.ceil(legitUrls.length * 0.05));

    console.log('\nDataset Coverage:');
    console.log(`Total Phishing URLs: ${phishingUrls.length}, Sampled: ${phishingSample.length}`);
    console.log(`Total Legitimate URLs: ${legitUrls.length}, Sampled: ${legitSample.length}`);

    // Analyze category distribution
    const phishingCategories = new Map();
    const legitCategories = new Map();

    phishingSample.forEach(url => {
      const cats = categorizeUrl(url);
      cats.forEach(cat => phishingCategories.set(cat, (phishingCategories.get(cat) || 0) + 1));
    });

    legitSample.forEach(url => {
      const cats = categorizeUrl(url);
      cats.forEach(cat => legitCategories.set(cat, (legitCategories.get(cat) || 0) + 1));
    });

    console.log('\nPhishing URL Categories:', Object.fromEntries(phishingCategories));
    console.log('Legitimate URL Categories:', Object.fromEntries(legitCategories));

    // Test URLs and track accuracy
    let phishingCorrect = 0, legitCorrect = 0;
    let phishingResults = [], legitResults = [];

    phishingSample.forEach(url => {
      try {
        const result = analyzer.analyzeUrl(url);
        phishingResults.push({ url, risk: result.risk, flags: result.flags });
        if (result.risk > 0.5) phishingCorrect++;
      } catch (error) {
        console.warn('Error analyzing phishing URL:', url);
      }
    });

    legitSample.forEach(url => {
      try {
        const result = analyzer.analyzeUrl(url);
        legitResults.push({ url, risk: result.risk, flags: result.flags });
        if (result.risk < 0.3) legitCorrect++;
      } catch (error) {
        console.warn('Error analyzing legitimate URL:', url);
      }
    });

    // Calculate and log results
    const phishingAccuracy = phishingCorrect / phishingSample.length;
    const legitAccuracy = legitCorrect / legitSample.length;
    const totalAccuracy = (phishingCorrect + legitCorrect) / (phishingSample.length + legitSample.length);

    console.log('\nResults:');
    console.log(`Phishing Detection Rate: ${(phishingAccuracy * 100).toFixed(1)}%`);
    console.log(`Legitimate Detection Rate: ${(legitAccuracy * 100).toFixed(1)}%`);
    console.log(`Overall Accuracy: ${(totalAccuracy * 100).toFixed(1)}%`);

    // Log some misclassified examples for analysis
    console.log('\nSample Misclassifications:');
    phishingResults.filter(r => r.risk <= 0.5).slice(0, 3).forEach(r => 
      console.log(`Missed Phishing: ${r.url} (Risk: ${r.risk.toFixed(2)}, Flags: ${r.flags.join(', ')})`));
    legitResults.filter(r => r.risk >= 0.3).slice(0, 3).forEach(r => 
      console.log(`False Positive: ${r.url} (Risk: ${r.risk.toFixed(2)}, Flags: ${r.flags.join(', ')})`));

    // Assertions
    expect(phishingAccuracy).toBeGreaterThan(0.7);
    expect(legitAccuracy).toBeGreaterThan(0.7);
  });
});