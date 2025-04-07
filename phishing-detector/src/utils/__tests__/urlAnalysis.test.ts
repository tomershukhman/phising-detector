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
        expect(result.brandDetection.hasBrandImpersonation).toBe(true);
        expect(result.brandDetection.impersonationType).toBeTruthy();
        expect(analyzer.getRiskLevel(result.risk)).not.toBe('Low');
      });
    });

    it('should detect brand names in subdomains', () => {
      const result = analyzer.analyzeUrl('https://login-paypal.malicious.com');
      expect(result.flags).toContain('BRAND_IMPERSONATION');
      expect(result.brandDetection.hasBrandImpersonation).toBe(true);
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

// Helper functions for test data management
function loadUrls(isPhishing: boolean): string[] {
  const filename = isPhishing ? 'phishing.csv' : 'legitimate.csv';
  try {
    const fileContent = fs.readFileSync(path.join(__dirname, '../../data', filename), 'utf-8');
    return fileContent
      .split('\n')
      .map(line => line.trim())
      .filter(url => url && url.length > 0 && !url.startsWith('#'));
  } catch (error) {
    console.error(`Error loading ${filename}:`, error);
    return [];
  }
}

function findUrlsWithPattern(urls: string[], pattern: RegExp): string[] {
  return urls.filter(url => pattern.test(url)).slice(0, 5); // Take up to 5 matching URLs
}

function findUrlsWithTLD(urls: string[], tld: string): string[] {
  return urls.filter(url => {
    try {
      return new URL(url).hostname.endsWith(`.${tld}`);
    } catch {
      return false;
    }
  }).slice(0, 5);
}

function countSubdomains(url: string): number {
  try {
    return new URL(url).hostname.split('.').length;
  } catch {
    return 0;
  }
}

describe('Feature Detection with Real Data', () => {
  let analyzer: UrlAnalyzer;
  let phishingUrls: string[];
  let legitUrls: string[];

  beforeAll(() => {
    analyzer = new UrlAnalyzer();
    phishingUrls = loadUrls(true);
    legitUrls = loadUrls(false);
  });

  describe('Technical Indicators', () => {
    it('should detect IP address URLs', () => {
      const ipUrls = findUrlsWithPattern(phishingUrls, /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
      expect(ipUrls.length).toBeGreaterThan(0);
      
      ipUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.flags).toContain('IP_ADDRESS_URL');
        expect(result.risk).toBeGreaterThan(0.3);
      });
    });

    it('should detect suspicious TLDs', () => {
      const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq'];
      const suspiciousUrls = suspiciousTlds.flatMap(tld => findUrlsWithTLD(phishingUrls, tld));
      expect(suspiciousUrls.length).toBeGreaterThan(0);

      suspiciousUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.flags).toContain('UNCOMMON_TLD');
      });
    });

    it('should detect excessive subdomains', () => {
      const excessiveSubdomainUrls = phishingUrls.filter(url => countSubdomains(url) > 3).slice(0, 5);
      expect(excessiveSubdomainUrls.length).toBeGreaterThan(0);

      excessiveSubdomainUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.flags).toContain('EXCESSIVE_SUBDOMAINS');
      });
    });
  });

  describe('Content and Pattern Detection', () => {
    it('should detect suspicious keywords in real phishing URLs', () => {
      const keywordUrls = findUrlsWithPattern(phishingUrls, /(login|secure|verify|account)/i);
      expect(keywordUrls.length).toBeGreaterThan(0);

      keywordUrls.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
        const hasKeyword = result.suspiciousPatterns.some(pattern => 
          ['login', 'secure', 'verify', 'account'].includes(pattern));
        expect(hasKeyword).toBe(true);
      });
    });

    it('should detect suspicious file extensions', () => {
      const suspiciousExtUrls = findUrlsWithPattern(phishingUrls, /\.(exe|zip|rar|pdf|doc|docx)$/i);
      
      if (suspiciousExtUrls.length > 0) {
        suspiciousExtUrls.forEach(url => {
          const result = analyzer.analyzeUrl(url);
          expect(result.flags).toContain('SUSPICIOUS_FILE_EXTENSION');
        });
      } else {
        console.log('No URLs with suspicious extensions found in the dataset');
      }
    });
  });

  describe('Legitimate URL Analysis', () => {
    it('should correctly identify legitimate URLs as low risk', () => {
      const sample = legitUrls.slice(0, 10);
      expect(sample.length).toBeGreaterThan(0);

      sample.forEach(url => {
        const result = analyzer.analyzeUrl(url);
        expect(result.risk).toBeLessThan(0.5);
        if (result.risk >= 0.3) {
          console.log(`Warning: Borderline legitimate URL: ${url} (Risk: ${result.risk})`);
        }
      });
    });
  });
});

describe('Dataset Testing', () => {
  let analyzer: UrlAnalyzer;

  beforeEach(() => {
    analyzer = new UrlAnalyzer();
  });

  it('should show detection results for each URL', () => {
    const phishingUrls = fs.readFileSync(path.join(__dirname, '../../data/phishing.csv'), 'utf-8')
      .split('\n')
      .filter(url => url.trim())
      .slice(0, 100); // Test more URLs
    
    const legitUrls = fs.readFileSync(path.join(__dirname, '../../data/legitimate.csv'), 'utf-8')
      .split('\n')
      .filter(url => url.trim())
      .slice(0, 100);

    const outputPath = path.join(__dirname, '../../../classification_results.html');
    
    // Initialize statistics
    const stats = {
      totalTests: phishingUrls.length + legitUrls.length,
      correctPhishing: 0,
      incorrectPhishing: 0,
      correctLegit: 0,
      incorrectLegit: 0,
      errors: [] as string[]
    };

    // Generate results
    const results = [...phishingUrls, ...legitUrls].map(url => {
      try {
        const trueLabel = phishingUrls.includes(url) ? 'phishing' : 'legit';
        const result = analyzer.analyzeUrl(url);
        const prediction = result.risk > 0.5 ? 'phishing' : 'legit';
        const correct = trueLabel === prediction;
        
        // Update statistics
        if (trueLabel === 'phishing') {
          correct ? stats.correctPhishing++ : stats.incorrectPhishing++;
        } else {
          correct ? stats.correctLegit++ : stats.incorrectLegit++;
        }

        return {
          url,
          trueLabel,
          prediction,
          correct,
          risk: result.risk,
          flags: result.flags,
          patterns: result.suspiciousPatterns
        };
      } catch (error) {
        stats.errors.push(`Error analyzing ${url}: ${error}`);
        return null;
      }
    }).filter(r => r !== null);

    // Calculate accuracy metrics
    const accuracy = ((stats.correctPhishing + stats.correctLegit) / stats.totalTests * 100).toFixed(2);
    const phishingAccuracy = (stats.correctPhishing / phishingUrls.length * 100).toFixed(2);
    const legitAccuracy = (stats.correctLegit / legitUrls.length * 100).toFixed(2);

    // Generate HTML
    const html = `<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .stats { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
        .stat-box { background: white; padding: 10px; border-radius: 3px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
        tr:nth-child(even) { background: #f9f9f9; }
        .correct { color: green; }
        .incorrect { color: red; }
        .errors { color: red; margin-top: 20px; }
        .flag { display: inline-block; background: #e9ecef; padding: 2px 6px; border-radius: 3px; margin: 2px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Phishing Detection Test Results</h1>
        
        <div class="stats">
            <h2>Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <strong>Overall Accuracy:</strong> ${accuracy}%
                </div>
                <div class="stat-box">
                    <strong>Phishing Detection:</strong> ${phishingAccuracy}%
                </div>
                <div class="stat-box">
                    <strong>Legitimate Detection:</strong> ${legitAccuracy}%
                </div>
                <div class="stat-box">
                    <strong>Total URLs Tested:</strong> ${stats.totalTests}
                </div>
            </div>
        </div>

        ${stats.errors.length > 0 ? `
        <div class="errors">
            <h3>Errors (${stats.errors.length})</h3>
            <ul>
                ${stats.errors.map(error => `<li>${error}</li>`).join('')}
            </ul>
        </div>
        ` : ''}

        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>True Label</th>
                    <th>Prediction</th>
                    <th>Risk Score</th>
                    <th>Flags</th>
                    <th>Patterns</th>
                </tr>
            </thead>
            <tbody>
                ${results.map(r => `
                <tr class="${r.correct ? 'correct' : 'incorrect'}">
                    <td>${r.url}</td>
                    <td>${r.trueLabel}</td>
                    <td>${r.prediction} ${r.correct ? '✓' : '✗'}</td>
                    <td>${r.risk.toFixed(2)}</td>
                    <td>${r.flags.map(f => `<span class="flag">${f}</span>`).join(' ')}</td>
                    <td>${r.patterns.join(', ')}</td>
                </tr>
                `).join('')}
            </tbody>
        </table>
    </div>
</body>
</html>`;

    fs.writeFileSync(outputPath, html);
    console.log(`Results written to ${outputPath}`);
  });
});