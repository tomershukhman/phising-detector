import { UrlAnalysisResult } from './types';
import { URLFeatures } from './URLFeatures';
import { BrandDetector } from './BrandDetector';

export class UrlAnalyzer {
  private static readonly RISK_WEIGHTS = {
    NUMERIC_DOMAIN: 0.3,
    SUSPICIOUS_KEYWORDS: 0.4,
    BRAND_MISUSE: 0.5,
    REDIRECT: 0.4
  };

  private static readonly RISK_THRESHOLDS = {
    LOW: 0.3,
    MEDIUM: 0.6,
    HIGH: 0.75
  };

  private readonly riskFactors = {
    // High risk factors
    IP_ADDRESS_URL: 0.8,
    DATA_URI_SCHEME: 0.8,
    HOMOGRAPH_ATTACK: 0.8,
    BRAND_IMPERSONATION: 0.7,
    
    // Medium risk factors
    EXCESSIVE_SUBDOMAINS: 0.3,
    EXCESSIVE_ENCODING: 0.4,
    SUSPICIOUS_FILE_EXTENSION: 0.4,
    SUSPICIOUS_TLD: 0.3,
    SUSPICIOUS_HOSTING: 0.3,
    
    // Lower risk factors - reduced these
    UNCOMMON_TLD: 0.2,  // Was 0.4
    SPECIAL_CHARS_IN_DOMAIN: 0.1,  // Was 0.3
    
    // Cumulative risk factors
    COMBINED_THREATS: 0.3  // Was 0.5
  };

  /**
   * Analyzes a URL for phishing indicators
   */
  analyzeUrl(url: string): UrlAnalysisResult {
    const result: UrlAnalysisResult = {
      risk: 0,
      riskLevel: 'Low',
      flags: [],
      suspiciousPatterns: [],
      features: URLFeatures.extractFeatures(url)
    };

    try {
      // Technical analysis
      this.addTechnicalRiskFactors(result);

      // Brand impersonation analysis
      const brandDetection = BrandDetector.analyzeForBrandImpersonation(
        result.features.domain,
        result.features.fullDomain,
        result.features.tld
      );
      result.brandDetection = brandDetection;
      this.addBrandImpersonationRiskFactors(result);

      // Content pattern analysis
      this.addContentPatternRiskFactors(result);

      // Apply special rules for legitimate domains
      this.applyLegitimateDomainsRules(result);

      // Cap the risk score at 1
      result.risk = Math.min(1, result.risk);
      // Set the risk level based on the final risk score
      result.riskLevel = this.getRiskLevel(result.risk);

    } catch (error) {
      result.flags.push('ANALYSIS_ERROR');
      result.risk = 1;
      result.riskLevel = 'High';
    }

    return result;
  }

  /**
   * Adds risk factors based on technical URL characteristics
   */
  private addTechnicalRiskFactors(result: UrlAnalysisResult): void {
    if (result.features.hasIPAddress) {
      result.flags.push('IP_ADDRESS_URL');
      result.risk += this.riskFactors.IP_ADDRESS_URL;
    }

    if (result.features.hasDataURI) {
      result.flags.push('DATA_URI_SCHEME');
      result.risk += this.riskFactors.DATA_URI_SCHEME;
    }

    // Only flag special chars if they're suspicious combinations
    const suspiciousChars = /[@$!%*#?&\/\\]/;
    if (result.features.domain && suspiciousChars.test(result.features.domain)) {
      result.flags.push('SPECIAL_CHARS_IN_DOMAIN');
      result.risk += this.riskFactors.SPECIAL_CHARS_IN_DOMAIN;
    }

    // More lenient subdomain check
    if (result.features.subdomainCount > 4) {  // Was 3
      result.flags.push('EXCESSIVE_SUBDOMAINS');
      result.risk += this.riskFactors.EXCESSIVE_SUBDOMAINS;
    }

    // Skip TLD checks for known legitimate TLDs
    if (result.features.tld && !this.isLegitimateHosting(result.features.fullDomain)) {
      const commonTLDs = new Set(['com', 'org', 'net', 'edu', 'gov', 'mil', 'int']);
      if (!commonTLDs.has(result.features.tld.toLowerCase())) {
        const suspiciousTLDs = new Set(['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']);
        if (suspiciousTLDs.has(result.features.tld.toLowerCase())) {
          result.flags.push('SUSPICIOUS_TLD');
          result.risk += this.riskFactors.SUSPICIOUS_TLD;
        } else {
          result.flags.push('UNCOMMON_TLD');
          result.risk += this.riskFactors.UNCOMMON_TLD;
        }
      }
    }

    if (result.features.hasNumericDomain) {
      result.flags.push('NUMERIC_PREFIX');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.NUMERIC_DOMAIN;
    }

    if (result.features.usesSuspiciousHosting) {
      result.flags.push('SUSPICIOUS_HOSTING');
      result.risk += this.riskFactors.SUSPICIOUS_HOSTING;
    }

    // Add risk for suspicious keywords in domain
    if (result.features.hasSuspiciousKeywords) {
      result.flags.push('SUSPICIOUS_KEYWORDS');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SUSPICIOUS_KEYWORDS;
      result.suspiciousPatterns.push('suspicious_keywords');
    }

    // Add risk for brand keywords in suspicious domains
    if (result.features.hasBrandKeywords && !this.isLegitimateHosting(result.features.fullDomain)) {
      result.flags.push('BRAND_KEYWORD_MISUSE');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.BRAND_MISUSE;
      result.suspiciousPatterns.push('brand_misuse');
    }

    // Add cumulative risk for combined technical indicators
    const technicalIndicators = [
      result.features.hasIPAddress,
      result.features.hasSuspiciousTLD,
      result.features.hasExcessiveSubdomains,
      result.features.hasSpecialChars,
      result.features.hasNumericDomain
    ].filter(Boolean).length;

    if (technicalIndicators >= 2) {
      result.risk += this.riskFactors.COMBINED_THREATS * technicalIndicators;
    }
  }

  /**
   * Adds risk factors based on brand impersonation detection
   */
  private addBrandImpersonationRiskFactors(result: UrlAnalysisResult): void {
    if (result.brandDetection.hasHomographAttack) {
      result.flags.push('HOMOGRAPH_ATTACK');
      result.risk += this.riskFactors.HOMOGRAPH_ATTACK;
    }

    // Only add brand impersonation risk if there are multiple indicators
    if (result.brandDetection.hasBrandImpersonation) {
      const hasSuspiciousIndicators = 
        result.brandDetection.impersonationType === 'typosquatting' ||
        (result.brandDetection.impersonationType === 'substring' && result.suspiciousPatterns.length > 0);

      if (hasSuspiciousIndicators) {
        result.flags.push('BRAND_IMPERSONATION');
        result.risk += this.riskFactors.BRAND_IMPERSONATION;
      }
    }

    if (result.brandDetection.hasCryptoScamIndicators) {
      result.flags.push('CRYPTO_SCAM_INDICATORS');
      result.risk += this.riskFactors.SUSPICIOUS_HOSTING;
    }
  }

  /**
   * Adds risk factors based on URL content patterns
   */
  private addContentPatternRiskFactors(result: UrlAnalysisResult): void {
    if (result.features.hasSuspiciousFileExt) {
      result.flags.push('SUSPICIOUS_FILE_EXTENSION');
      result.risk += this.riskFactors.SUSPICIOUS_FILE_EXTENSION;
    }

    if (result.features.hasDataURI) {
      result.flags.push('DATA_URI_SCHEME');
      result.risk += this.riskFactors.DATA_URI_SCHEME;
    }

    if (result.features.hasExcessiveEncoding) {
      result.flags.push('EXCESSIVE_ENCODING');
      result.risk += this.riskFactors.EXCESSIVE_ENCODING;
    }

    if (result.features.hasRedirectPattern) {
      result.flags.push('REDIRECT_PRESENT');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.REDIRECT;
      result.suspiciousPatterns.push('redirect');

      // Add extra risk if redirect is combined with other suspicious patterns
      if (result.suspiciousPatterns.length > 1) {
        result.risk += 0.15;
      }
    }

    // Require multiple suspicious patterns for increasing risk
    const patterns = this.detectSuspiciousPatterns(result.features.fullDomain);
    if (patterns.length > 0) {
      result.suspiciousPatterns.push(...patterns);
      // Only increase risk if multiple patterns are found
      if (patterns.length > 1) {
        result.risk += this.riskFactors.COMBINED_THREATS;
      }
    }
  }

  /**
   * Applies special rules for known legitimate domains
   */
  private applyLegitimateDomainsRules(result: UrlAnalysisResult): void {
    // If it's a legitimate brand domain with no other flags, keep risk very low
    if (result.brandDetection?.detectedBrand && result.flags.length === 1 && 
        result.flags[0] === 'BRAND_IMPERSONATION') {
      result.risk = 0.1;
      result.flags = [];
    }

    // Only reduce risk for legitimate brand root domains
    if (result.features?.domain && this.isLegitimateHosting(result.features.fullDomain)) {
      result.risk = Math.max(0.1, result.risk - 0.2);
    }
  }

  /**
   * Checks if a domain belongs to a legitimate hosting provider
   */
  private isLegitimateHosting(hostname: string): boolean {
    // Only consider root domains as legitimate, not their subdomains on cloud platforms
    const legitDomains = [
      'github.com',
      'gitlab.com',
      'bitbucket.org',
      'wordpress.com',
      'medium.com',
      'twitter.com',
      'facebook.com',
      'linkedin.com',
      'youtube.com',
      'amazon.com',
      'microsoft.com',
      'apple.com',
      'google.com'
    ];
    
    // Cloud platforms that require additional scrutiny
    const cloudPlatforms = [
      'github.io',
      'githubusercontent.com',
      'blogspot.com',
      'netlify.com',
      'netlify.app',
      'vercel.app',
      'herokuapp.com',
      'azurewebsites.net',
      'web.app',
      'firebaseapp.com',
      'appspot.com',
      'pages.dev',
      'surge.sh',
      'web.core.windows.net',
      'blob.core.windows.net',
      'godaddysites.com',
      'wixsite.com',
      'weebly.com',
      'squarespace.com'
    ];

    // Check if domain is a cloud platform
    const isCloudPlatform = cloudPlatforms.some(platform => hostname.endsWith(platform));
    if (isCloudPlatform) {
      return false; // Don't automatically trust cloud platforms
    }
    
    return legitDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
  }

  /**
   * Detects suspicious patterns in URLs
   */
  private detectSuspiciousPatterns(domain: string): string[] {
    const patterns = [];
    
    // Check for excessive numbers
    if (/\d{4,}/.test(domain)) {
      patterns.push('excessive_numbers');
    }
    
    // Check for repetitive characters
    if (/(.)\1{3,}/.test(domain)) {
      patterns.push('repetitive_chars');
    }
    
    // Check for mixed number-letter sequences
    if (/(?:\d[a-z]|[a-z]\d){3,}/i.test(domain)) {
      patterns.push('mixed_alphanumeric');
    }
    
    // Check for common scam words
    const scamWords = ['secure', 'login', 'verify', 'account', 'limited', 'confirm'];
    if (scamWords.some(word => domain.toLowerCase().includes(word))) {
      patterns.push('scam_keywords');
    }
    
    return patterns;
  }

  /**
   * Gets the risk level category for a risk score
   */
  getRiskLevel(risk: number): 'Low' | 'Medium' | 'High' {
    if (risk < 0.3) return 'Low';  // Was 0.2
    if (risk < 0.6) return 'Medium';  // Was 0.5
    return 'High';
  }
}