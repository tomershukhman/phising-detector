import { confusables } from './confusables.js';
import { BrandDetectionResult } from './types.js';

export class BrandDetector {
  private static readonly brandDomains = new Map([
    ['google', 'google.com'],
    ['facebook', 'facebook.com'],
    ['apple', 'apple.com'],
    ['microsoft', 'microsoft.com'],
    ['amazon', 'amazon.com'],
    ['paypal', 'paypal.com'],
    ['netflix', 'netflix.com'],
    ['linkedin', 'linkedin.com'],
    ['twitter', 'twitter.com'],
    ['instagram', 'instagram.com'],
    ['wells', 'wellsfargo.com'],
    ['chase', 'chase.com'],
    ['citi', 'citibank.com'],
    ['americanexpress', 'americanexpress.com'],
    ['amex', 'americanexpress.com'],
    ['dropbox', 'dropbox.com'],
    ['github', 'github.com'],
    ['outlook', 'outlook.com'],
    ['office', 'office.com'],
    ['onedrive', 'onedrive.live.com'],
    ['binance', 'binance.com'],
    ['coinbase', 'coinbase.com'],
    ['metamask', 'metamask.io'],
    ['whatsapp', 'whatsapp.com'],
    ['telegram', 'telegram.org'],
    ['protonmail', 'proton.me'],
    ['okta', 'okta.com']
  ]);

  private static readonly gibberishPatterns = {
    minEntropyThreshold: 4.0,  // Increased from 3.5 to reduce false positives
    maxConsecutiveConsonants: 4,
    maxConsecutiveNumbers: 3,
    maxRepeatedChars: 3,
    suspiciousPatterns: [
      /[bcdfghjklmnpqrstvwxz]{4,}/i,  // Excessive consonants
      /(.)1{2,}/,  // Character repetition
      /[0-9]{4,}/,  // Long number sequences
      /(?:[0-9][a-z]|[a-z][0-9]){3,}/i,  // Alternating letters and numbers
      /[a-z0-9]{10,}/i  // Very long alphanumeric sequences
    ]
  };

  private static readonly brandVariants = new Map([
    ['google', ['google', 'googl', 'g00gle']],
    ['paypal', ['paypal', 'payp', 'ppal']],
    ['microsoft', ['microsoft', 'msft', 'ms']],
    ['amazon', ['amazon', 'amzn']]
  ]);

  private static calculateEntropy(str: string): number {
    const freq: { [key: string]: number } = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    return -Object.values(freq)
      .map(count => count / str.length)
      .reduce((sum, p) => sum + p * Math.log2(p), 0);
  }

  private static readonly commonTLDs = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'io', 'me', 'app',
    'dev', 'ai', 'co', 'us', 'uk', 'eu', 'de', 'fr', 'es', 'it',
    'ca', 'au', 'jp', 'cn', 'ru', 'br', 'in', 'nl', 'pl', 'ch',
    'se', 'no', 'dk', 'fi', 'at', 'be', 'ie', 'nz', 'sg', 'kr',
    'mx', 'ar', 'cl', 'za', 'hu', 'cz', 'pt', 'gr', 'il', 'ae',
    'hk', 'my', 'th', 'ph', 'vn', 'ro', 'ua', 'sa', 'sk', 'info',
    'biz', 'pro', 'int', 'jobs', 'name', 'tel', 'mobi', 'asia',
    'cat', 'travel', 'xxx', 'club', 'blog', 'shop', 'site', 'online',
    'tech', 'live', 'store', 'news', 'cloud', 'life', 'world', 'plus'
  ]);

  private static readonly legitHostingDomains = new Set([
    'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
    'wordpress.com', 'blogspot.com', 'medium.com', 'wixsite.com',
    'squarespace.com', 'shopify.com', 'myshopify.com'
  ]);

  private static readonly cryptoCurrencyTerms = new Set([
    'bitcoin', 'ethereum', 'crypto', 'wallet', 'nft', 'token', 'dao',
    'defi', 'mining', 'btc', 'eth', 'usdt', 'binance', 'metamask',
    'trust', 'ledger', 'dex', 'swap', 'stake', 'yield', 'airdrop',
    'blockchain', 'web3', 'opensea', 'uniswap', 'pancakeswap', 'sushiswap',
    'compound', 'farm', 'pool', 'liquidity', 'presale', 'ico', 'hodl',
    'solana', 'sol', 'bnb', 'bsc', 'polygon', 'matic', 'avalanche', 'avax'
  ]);

  private static readonly scamIndicators = new Set([
    'verify', 'secure', 'authenticate', 'validate', 'confirm',
    'update', 'recover', 'unlock', 'restore', 'limited', 'urgent',
    'suspended', 'unusual', 'required', 'important', 'access',
    'account', 'login', 'signin', 'password', 'credential'
  ]);

  public static analyzeForBrandImpersonation(domain: string, fullDomain: string, tld: string): BrandDetectionResult {
    const result: BrandDetectionResult = {
      hasBrandImpersonation: false,
      hasHomographAttack: false,
      hasCryptoScamIndicators: false,
      detectedBrand: null,
      impersonationType: null,
      confusableCharacters: [],
      cryptoTerms: []
    };

    // Skip analysis for known legitimate hosting domains
    if (this.legitHostingDomains.has(tld) || 
        Array.from(this.legitHostingDomains).some(host => fullDomain.endsWith(host))) {
      return result;
    }

    // Skip analysis for educational institutions
    if (tld === 'edu' || fullDomain.includes('.edu.')) {
      return result;
    }

    // Rest of the analysis with higher thresholds for detection
    const normalizedDomain = this.normalizeString(domain);
    const normalizedFullDomain = this.normalizeString(fullDomain);

    // Check for gibberish patterns with stricter rules
    const entropy = this.calculateEntropy(domain);
    const hasGibberish = entropy > this.gibberishPatterns.minEntropyThreshold &&
      this.gibberishPatterns.suspiciousPatterns.some(pattern => pattern.test(domain));

    if (hasGibberish) {
      result.hasBrandImpersonation = true;
      result.impersonationType = 'gibberish';
    }

    // Brand impersonation checks
    for (const [brand, legitimateDomain] of this.brandDomains) {
      // Skip if it's the legitimate domain or subdomain
      if (fullDomain === legitimateDomain || fullDomain.endsWith('.' + legitimateDomain)) continue;

      // Check for scam indicators first
      const hasScamIndicators = Array.from(this.scamIndicators)
        .filter(indicator => normalizedFullDomain.includes(indicator)).length >= 2; // Require multiple indicators

      const isLegitTLD = this.commonTLDs.has(tld.toLowerCase());

      // Check brand variants
      const variants = this.brandVariants.get(brand) || [brand];
      const hasVariantMatch = variants.some(variant => 
        normalizedDomain === variant || // Exact match only
        (normalizedDomain.includes(variant) && hasScamIndicators) // Must have scam indicators if just a substring
      );

      // More targeted detection
      if (hasVariantMatch && !isLegitTLD && hasScamIndicators) {
        result.hasBrandImpersonation = true;
        result.detectedBrand = brand;
        result.impersonationType = 'substring';
        break;
      }

      // Stricter typosquatting detection
      const distance = this.levenshteinDistance(normalizedDomain, brand);
      const maxAllowedDistance = Math.min(1, Math.floor(brand.length / 8)); // More conservative distance

      if (distance > 0 && distance <= maxAllowedDistance && !isLegitTLD) {
        result.hasBrandImpersonation = true;
        result.detectedBrand = brand;
        result.impersonationType = 'typosquatting';
        break;
      }
    }

    // Check for homograph attacks
    const confusableResults = this.detectConfusables(domain);
    if (confusableResults.hasConfusables) {
      result.hasHomographAttack = true;
      result.confusableCharacters = confusableResults.confusables;
    }

    // Check for crypto scam indicators
    const detectedCryptoTerms = Array.from(this.cryptoCurrencyTerms)
      .filter(term => normalizedFullDomain.includes(term));

    if (detectedCryptoTerms.length > 0) {
      result.hasCryptoScamIndicators = true;
      result.cryptoTerms = detectedCryptoTerms;
    }

    return result;
  }

  /**
   * Detects confusable characters used in homograph attacks
   */
  private static detectConfusables(text: string): { 
    hasConfusables: boolean; 
    confusables: Array<{original: string; lookalike: string}>
  } {
    const found: Array<{original: string; lookalike: string}> = [];
    
    // Check each character against known confusables
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (confusables[char]) {
        found.push({
          original: char,
          lookalike: confusables[char]
        });
      }
    }

    return {
      hasConfusables: found.length > 0,
      confusables: found
    };
  }

  /**
   * Normalizes text for comparison by replacing common substitutions
   */
  private static normalizeString(str: string): string {
    // Remove numeric prefixes for comparison
    const withoutNumericPrefix = str.replace(/^\d+/, '');
    
    return withoutNumericPrefix.toLowerCase()
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/5/g, 's')
      .replace(/\$/g, 's')
      .replace(/@/g, 'a')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/8/g, 'b')
      .replace(/7/g, 't');
  
  }

  /**
   * Calculates Levenshtein distance between two strings
   */
  private static levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = Array(str1.length + 1).fill(null)
      .map(() => Array(str2.length + 1).fill(null));

    for (let i = 0; i <= str1.length; i++) matrix[i][0] = i;
    for (let j = 0; j <= str2.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= str1.length; i++) {
      for (let j = 1; j <= str2.length; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[str1.length][str2.length];
  }
}