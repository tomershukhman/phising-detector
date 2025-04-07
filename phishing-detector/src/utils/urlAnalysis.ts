import { UrlAnalysisResult } from './types';
import { URLFeatures } from './URLFeatures';
import { BrandDetector } from './BrandDetector';

export class UrlAnalyzer {
  private static readonly RISK_THRESHOLDS = {
    LOW: 0.25,
    MEDIUM: 0.5,
    HIGH: 0.75
  };

  private static readonly RISK_WEIGHTS = {
    // Critical risk factors
    IP_ADDRESS: 0.8,
    DATA_URI: 0.9,
    HOMOGRAPH_ATTACK: 0.9,
    BRAND_IMPERSONATION: 0.9,
    
    // High risk factors
    SUSPICIOUS_TLD: 0.7,
    SUSPICIOUS_KEYWORDS: 0.75,
    BRAND_MISUSE: 0.8,
    CRYPTO_SCAM: 0.8,
    SUSPICIOUS_FILE: 0.7,
    
    // Medium risk factors
    SPECIAL_CHARS: 0.6,
    NUMERIC_DOMAIN: 0.6,
    SUSPICIOUS_HOSTING: 0.65,
    EXCESSIVE_ENCODING: 0.6,
    REDIRECT: 0.6,
    
    // Lower risk factors
    UNCOMMON_TLD: 0.4,
    EXCESSIVE_SUBDOMAINS: 0.4,
    
    // Cumulative risk factors
    COMBINED_THREATS: 0.5
  };

  /**
   * Analyzes a URL for phishing indicators
   */
  analyzeUrl(url: string): UrlAnalysisResult {
    const result: UrlAnalysisResult = {
      risk: 0,
      flags: [],
      brandMatches: false,
      suspiciousPatterns: []
    };

    try {
      // Extract URL features
      const features = URLFeatures.extractFeatures(url);
      result.features = features;

      if (features.isInvalid) {
        result.flags.push('INVALID_URL');
        result.risk = 1;
        return result;
      }

      // Analyze for brand impersonation and homograph attacks
      const brandDetection = BrandDetector.analyzeForBrandImpersonation(
        features.domain,
        features.fullDomain,
        features.tld
      );
      result.brandDetection = brandDetection;

      // Add risk factors based on technical indicators
      this.addTechnicalRiskFactors(result, features);

      // Add risk factors based on brand impersonation
      this.addBrandImpersonationRiskFactors(result, brandDetection);

      // Add risk factors based on content patterns
      this.addContentPatternRiskFactors(result, features);

      // Apply special rules for legitimate domains
      this.applyLegitimateDomainsRules(result);

      // Cap the risk score at 1
      result.risk = Math.min(1, result.risk);

    } catch (error) {
      result.flags.push('ANALYSIS_ERROR');
      result.risk = 1;
    }

    return result;
  }

  /**
   * Adds risk factors based on technical URL characteristics
   */
  private addTechnicalRiskFactors(result: UrlAnalysisResult, features: ReturnType<typeof URLFeatures.extractFeatures>): void {
    if (features.hasIPAddress) {
      result.flags.push('IP_ADDRESS_URL');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.IP_ADDRESS;
    }

    if (features.hasUncommonTLD) {
      result.flags.push('UNCOMMON_TLD');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.UNCOMMON_TLD;
    }

    if (features.hasSuspiciousTLD) {
      result.flags.push('SUSPICIOUS_TLD');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SUSPICIOUS_TLD;
    }

    if (features.hasExcessiveSubdomains) {
      result.flags.push('EXCESSIVE_SUBDOMAINS');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.EXCESSIVE_SUBDOMAINS;
      // Add extra risk for each additional subdomain beyond 2
      if (features.subdomainCount > 2) {
        result.risk += (features.subdomainCount - 2) * 0.1;
      }
    }

    if (features.hasSpecialChars) {
      result.flags.push('SPECIAL_CHARS_IN_DOMAIN');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SPECIAL_CHARS;
    }

    if (features.hasNumericDomain) {
      result.flags.push('NUMERIC_PREFIX');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.NUMERIC_DOMAIN;
    }

    if (features.usesSuspiciousHosting) {
      result.flags.push('SUSPICIOUS_HOSTING');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SUSPICIOUS_HOSTING;
    }

    // Add risk for suspicious keywords in domain
    if (features.hasSuspiciousKeywords) {
      result.flags.push('SUSPICIOUS_KEYWORDS');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SUSPICIOUS_KEYWORDS;
      result.suspiciousPatterns.push('suspicious_keywords');
    }

    // Add risk for brand keywords in suspicious domains
    if (features.hasBrandKeywords && !this.isLegitimateHosting(features.fullDomain)) {
      result.flags.push('BRAND_KEYWORD_MISUSE');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.BRAND_MISUSE;
      result.suspiciousPatterns.push('brand_misuse');
    }

    // Add cumulative risk for combined technical indicators
    const technicalIndicators = [
      features.hasIPAddress,
      features.hasSuspiciousTLD,
      features.hasExcessiveSubdomains,
      features.hasSpecialChars,
      features.hasNumericDomain
    ].filter(Boolean).length;

    if (technicalIndicators >= 2) {
      result.risk += UrlAnalyzer.RISK_WEIGHTS.COMBINED_THREATS * technicalIndicators;
    }
  }

  /**
   * Adds risk factors based on brand impersonation detection
   */
  private addBrandImpersonationRiskFactors(result: UrlAnalysisResult, brandDetection: ReturnType<typeof BrandDetector.analyzeForBrandImpersonation>): void {
    if (brandDetection.hasBrandImpersonation) {
      result.flags.push('BRAND_IMPERSONATION');
      result.brandMatches = true;
      result.detectedBrand = brandDetection.detectedBrand;
      result.risk += UrlAnalyzer.RISK_WEIGHTS.BRAND_IMPERSONATION;

      // Add extra risk for sophisticated impersonation attempts
      if (brandDetection.impersonationType === 'typosquatting') {
        result.risk += 0.1;
      }
    }

    if (brandDetection.hasHomographAttack) {
      result.flags.push('HOMOGRAPH_ATTACK');
      result.confusables = brandDetection.confusableCharacters;
      result.risk += UrlAnalyzer.RISK_WEIGHTS.HOMOGRAPH_ATTACK;

      // Add extra risk based on number of confusable characters
      if (brandDetection.confusableCharacters.length > 1) {
        result.risk += 0.1 * Math.min(brandDetection.confusableCharacters.length, 3);
      }
    }

    if (brandDetection.hasCryptoScamIndicators) {
      result.flags.push('CRYPTO_SCAM_INDICATORS');
      result.cryptoTerms = brandDetection.cryptoTerms;
      result.risk += UrlAnalyzer.RISK_WEIGHTS.CRYPTO_SCAM;

      // Add extra risk for multiple crypto terms
      if (brandDetection.cryptoTerms.length > 1) {
        result.risk += 0.1 * Math.min(brandDetection.cryptoTerms.length, 3);
      }
    }
  }

  /**
   * Adds risk factors based on URL content patterns
   */
  private addContentPatternRiskFactors(result: UrlAnalysisResult, features: ReturnType<typeof URLFeatures.extractFeatures>): void {
    if (features.hasSuspiciousFileExt) {
      result.flags.push('SUSPICIOUS_FILE_EXTENSION');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.SUSPICIOUS_FILE;
    }

    if (features.hasDataURI) {
      result.flags.push('DATA_URI_SCHEME');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.DATA_URI;
    }

    if (features.hasExcessiveEncoding) {
      result.flags.push('EXCESSIVE_ENCODING');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.EXCESSIVE_ENCODING;
    }

    if (features.hasRedirectPattern) {
      result.flags.push('REDIRECT_PRESENT');
      result.risk += UrlAnalyzer.RISK_WEIGHTS.REDIRECT;
      result.suspiciousPatterns.push('redirect');

      // Add extra risk if redirect is combined with other suspicious patterns
      if (result.suspiciousPatterns.length > 1) {
        result.risk += 0.15;
      }
    }

    // Add cumulative risk for multiple content-based indicators
    const contentIndicators = [
      features.hasSuspiciousFileExt,
      features.hasDataURI,
      features.hasExcessiveEncoding,
      features.hasRedirectPattern
    ].filter(Boolean).length;

    if (contentIndicators >= 2) {
      result.risk += UrlAnalyzer.RISK_WEIGHTS.COMBINED_THREATS * contentIndicators;
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
   * Gets the risk level category for a risk score
   */
  getRiskLevel(risk: number): 'Low' | 'Medium' | 'High' {
    if (risk < UrlAnalyzer.RISK_THRESHOLDS.LOW) return 'Low';
    if (risk < UrlAnalyzer.RISK_THRESHOLDS.MEDIUM) return 'Medium';
    return 'High';
  }
}