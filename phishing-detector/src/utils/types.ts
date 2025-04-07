export interface FeatureResult {
  hasIPAddress: boolean;
  hasUncommonTLD: boolean;
  hasSuspiciousTLD: boolean;
  hasExcessiveSubdomains: boolean;
  subdomainCount: number;
  hasSpecialChars: boolean;
  hasSuspiciousFileExt: boolean;
  usesSuspiciousHosting: boolean;
  hasNumericDomain: boolean;
  domainLength: number;
  hasDataURI: boolean;
  hasExcessiveEncoding: boolean;
  hasRedirectPattern: boolean;
  hasSuspiciousKeywords: boolean;
  hasBrandKeywords: boolean;
  tld: string;
  domain: string;
  subdomains: string[];
  fullDomain: string;
  isInvalid?: boolean;
}

export interface BrandDetectionResult {
  hasBrandImpersonation: boolean;
  hasHomographAttack: boolean;
  hasCryptoScamIndicators: boolean;
  detectedBrand: string | null;
  impersonationType: 'substring' | 'typosquatting' | 'gibberish' | null;
  confusableCharacters: Array<{
    original: string;
    lookalike: string;
  }>;
  cryptoTerms: string[];
}

export interface UrlAnalysisResult {
  risk: number;
  flags: string[];
  brandMatches: boolean;
  suspiciousPatterns: string[];
  features?: FeatureResult;
  brandDetection?: BrandDetectionResult;
  detectedBrand?: string;
  typosquatting?: string;
  confusables?: Array<{
    original: string;
    lookalike: string;
  }>;
  cryptoTerms?: string[];
}