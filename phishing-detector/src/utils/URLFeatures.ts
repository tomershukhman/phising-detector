import { FeatureResult } from './types.js';
import { BrandDetector } from './BrandDetector.js';

export class URLFeatures {
  private static readonly commonTLDs = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'biz', 'info',
    'mil', 'int', 'eu', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp'
  ]);

  private static readonly suspiciousFileExtensions = new Set([
    '.exe', '.zip', '.scr', '.js', '.msi', '.bat', '.dll', '.sh', '.ps1',
    '.cmd', '.vbs', '.jar', '.app', '.apk', '.deb', '.dmg', '.bin', '.iso'
  ]);

  private static readonly commonHostingProviders = new Set([
    'godaddysites.com', 'wcomhost.com', 'weebly.com', 'netlify.com',
    'azurewebsites.net', 'herokuapp.com', 'cloudaccess.host', '16mb.com',
    'ngrok.io', 'surge.sh', 'vercel.app', 'github.io', 'web.app', 'firebaseapp.com',
    'pages.dev', 'glitch.me', 'repl.co', 'appspot.com', 'web.core.windows.net'
  ]);

  private static readonly suspiciousKeywords = new Set([
    'secure', 'login', 'signin', 'account', 'verify', 'auth', 'authenticate',
    'password', 'credential', 'wallet', 'recover', 'support', 'help', 'desk',
    'service', 'access', 'form', 'update', 'billing', 'payment', 'confirm',
    'security', 'reset', 'validation', 'identity', 'unlock', 'restore',
    'protect', 'limited', 'urgent', 'suspended', 'unusual', 'suspicious',
    'important', 'required', 'verify-now', 'authenticate-now', 'crypto',
    'blockchain', 'token', 'nft', 'airdrop', 'bonus', 'reward', 'prize'
  ]);

  private static readonly gibberishPatterns = {
    minEntropyThreshold: 3.8,  // Higher values indicate more randomness
    maxConsecutiveConsonants: 4,
    maxConsecutiveNumbers: 3,
    maxRepeatedChars: 3,
    suspiciousPatterns: [
      /[bcdfghjklmnpqrstvwxz]{4,}/i,  // Excessive consonants
      /(.)\1{2,}/,  // Character repetition
      /[0-9]{4,}/,  // Long number sequences
      /(?:[0-9][a-z]|[a-z][0-9]){3,}/i,  // Alternating letters and numbers
      /[a-z0-9]{12,}/i,  // Very long alphanumeric sequences
      /[aeiou]{4,}/i,  // Excessive vowels
      /(?:xn--|--)[a-z0-9-]{4,}/i  // Suspicious punycode or dashed patterns
    ]
  };

  private static calculateEntropy(str: string): number {
    const freq: { [key: string]: number } = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    return -Object.values(freq)
      .map(count => count / str.length)
      .reduce((sum, p) => sum + p * Math.log2(p), 0);
  }

  private static readonly brandKeywords = new Set([
    'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix',
    'bank', 'wells', 'chase', 'citi', 'coinbase', 'binance', 'metamask',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'gmail', 'outlook', 'yahoo',
    'steam', 'discord', 'whatsapp', 'telegram', 'spotify', 'adobe', 'office365',
    'onedrive', 'icloud', 'blockchain', 'opensea', 'uniswap', 'trustwallet',
    'americanexpress', 'mastercard', 'visa', 'discover', 'bankofamerica',
    'wellsfargo', 'capitalone', 'citibank', 'hsbc', 'barclays', 'santander'
  ]);

  private static readonly suspiciousTLDs = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'club', 'work',
    'party', 'date', 'stream', 'racing', 'win', 'bid', 'pro', 'online',
    'ru', 'cn', 'su', 'ws', 'bz', 'me', 'cc', 'to', 'in'
  ]);

  public static extractFeatures(urlString: string): FeatureResult {
    const features: FeatureResult = {
      hasIPAddress: false,
      hasUncommonTLD: false,
      hasSuspiciousTLD: false,
      hasExcessiveSubdomains: false,
      subdomainCount: 0,
      hasSpecialChars: false,
      hasSuspiciousFileExt: false,
      usesSuspiciousHosting: false,
      hasNumericDomain: false,
      domainLength: 0,
      hasDataURI: false,
      hasExcessiveEncoding: false,
      hasRedirectPattern: false,
      hasSuspiciousKeywords: false,
      hasBrandKeywords: false,
      tld: '',
      domain: '',
      subdomains: [],
      fullDomain: '',
      isInvalid: false
    };

    try {
      // Add protocol if missing to prevent URL parse errors
      const urlToAnalyze = urlString.startsWith('http') ? urlString : `http://${urlString}`;
      const urlObj = new URL(urlToAnalyze);

      // Extract domain parts
      const domainParts = urlObj.hostname.split('.');
      features.tld = domainParts[domainParts.length - 1];
      features.domain = domainParts[domainParts.length - 2] || '';
      features.subdomains = domainParts.slice(0, -2);
      features.fullDomain = urlObj.hostname;
      features.domainLength = urlObj.hostname.length;
      features.subdomainCount = Math.max(0, domainParts.length - 2);

      // Check for IP address
      features.hasIPAddress = this.isIPAddress(urlObj.hostname);

      // Check TLD characteristics
      features.hasUncommonTLD = !this.commonTLDs.has(features.tld.toLowerCase());
      features.hasSuspiciousTLD = this.suspiciousTLDs.has(features.tld.toLowerCase());

      // Check for excessive subdomains
      features.hasExcessiveSubdomains = features.subdomainCount > 2;

      // Check for special characters, deceptive punctuation, and homograph patterns
      features.hasSpecialChars = /[<>{}|\^[]@]|[-_.]{2,}/.test(urlObj.hostname) ||
        /[0o1il][0o1il]{2,}/.test(urlObj.hostname) || // Detect character substitution patterns
        /[а-яА-Я]/.test(urlObj.hostname) || // Detect Cyrillic characters
        /[\u0430-\u044F\u0410-\u042F]/.test(urlObj.hostname) || // Unicode ranges for Cyrillic
        /[\u0660-\u0669]/.test(urlObj.hostname) || // Arabic numerals
        /[\u0966-\u096F]/.test(urlObj.hostname) || // Devanagari numerals
        /[\u0250-\u02AF\u0300-\u036F\u1D00-\u1D7F\u1D80-\u1DBF\u1DC0-\u1DFF\u2100-\u214F\u2150-\u218F]/.test(urlObj.hostname) || // Unicode ranges for confusable characters
        /[\u2E80-\u2EFF\u3000-\u303F\u3200-\u32FF\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]/.test(urlObj.hostname); // CJK characters and symbols

      // Check for numeric domain patterns, sequences, and gibberish
      const numericPattern = /^\d+/.test(domainParts[0]) || // Starts with number
        /^[0-9a-f]{2,}(?:[.-][0-9a-f]{2,})*$/.test(domainParts[0]) || // Hex-like patterns
        (domainParts[0].match(/\d/g) || []).length > 3 || // More than 3 digits
        /\d{3,}/.test(domainParts[0]) || // Long number sequences
        /(?:0|1){3,}/.test(domainParts[0]) || // Repeated 0s and 1s
        /\d+(?:[a-z]\d+){1,}/.test(domainParts[0]) || // Alternating numbers and letters
        /^[a-z0-9]{1,3}[.-][a-z0-9]{3,}$/.test(domainParts[0]); // Short prefix with separator
      features.hasNumericDomain = numericPattern;

      // Enhanced gibberish detection
      const entropy = this.calculateEntropy(domainParts[0]);
      const hasGibberish = entropy > this.gibberishPatterns.minEntropyThreshold ||
        this.gibberishPatterns.suspiciousPatterns.some(pattern => pattern.test(domainParts[0])) ||
        /^[a-z0-9]{6,}$/.test(domainParts[0]) || // Long random-looking strings
        /^[a-z0-9]{2,}[.-][a-z0-9]{2,}$/.test(domainParts[0]) || // Separated random strings
        /^(?:[bcdfghjklmnpqrstvwxz]{1,2}\d+|\d+[bcdfghjklmnpqrstvwxz]{1,2})/.test(domainParts[0].toLowerCase()); // Consonant-number combinations
      
      if (hasGibberish) {
        features.hasSpecialChars = true;
        features.hasSuspiciousKeywords = true;
      }

      // Check for data URI scheme
      features.hasDataURI = urlString.startsWith('data:');

      // Check for suspicious file extension
      const pathExt = this.getFileExtension(urlObj.pathname);
      features.hasSuspiciousFileExt = pathExt ? 
        this.suspiciousFileExtensions.has(pathExt.toLowerCase()) : false;

      // Check for excessive URL encoding
      features.hasExcessiveEncoding = this.hasExcessiveEncoding(urlString);

      // Check for suspicious hosting provider
      features.usesSuspiciousHosting = this.commonHostingProviders
        .has(urlObj.hostname.toLowerCase()) || 
        Array.from(this.commonHostingProviders)
          .some(provider => urlObj.hostname.toLowerCase().endsWith(provider));

      // Check for redirect patterns, suspicious query parameters, and path segments
      const suspiciousParams = /redirect|url=|goto=|link=|out=|return=|forward=|target=|destination=|next=|continue=|path=|to=|location=/;
      const suspiciousPathSegments = /(auth|login|signin|account|verify|password|secure|update).*(php|html|aspx|jsp|cgi)/i;
      const hasBase64Params = /[a-zA-Z0-9+/]{20,}={0,2}(?:[?&]|$)/.test(urlString);
      
      features.hasRedirectPattern = suspiciousParams.test(urlString.toLowerCase()) ||
        suspiciousPathSegments.test(urlObj.pathname) ||
        hasBase64Params ||
        urlObj.searchParams.has('data') ||
        urlObj.searchParams.has('token') ||
        /^\/(redirect|forward|go)\//.test(urlObj.pathname);

      // Enhanced brand detection and phishing analysis
      const domainString = urlObj.hostname.toLowerCase();
      const brandAnalysis = BrandDetector.analyzeForBrandImpersonation(
        features.domain,
        features.fullDomain,
        features.tld
      );

      // Update brand and suspicious keyword detection based on brand analysis
      features.hasBrandKeywords = brandAnalysis.hasBrandImpersonation || brandAnalysis.hasHomographAttack;
      features.hasSuspiciousKeywords = Array.from(this.suspiciousKeywords)
        .some(keyword => domainString.includes(keyword));

      // Additional risk factors from brand analysis
      if (brandAnalysis.hasCryptoScamIndicators) {
        features.hasSuspiciousKeywords = true;
      }

      // Strengthen detection with combined signals
      if (features.hasSpecialChars && features.hasBrandKeywords) {
        features.hasSuspiciousKeywords = true;
      }

    } catch (error) {
      // Return features with default values if URL parsing fails
      features.isInvalid = true;
    }

    return features;
  }

  private static isIPAddress(hostname: string): boolean {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      const parts = hostname.split('.');
      return parts.every(part => {
        const num = parseInt(part);
        return num >= 0 && num <= 255;
      });
    }
    return false;
  }

  private static getFileExtension(path: string): string | null {
    const match = path.match(/\.[^.\/]+$/);
    return match ? match[0].toLowerCase() : null;
  }

  private static hasExcessiveEncoding(url: string): boolean {
    const percentCount = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    return percentCount > 3;
  }
}