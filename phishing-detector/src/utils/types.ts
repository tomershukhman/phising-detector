export interface BrandDetectionResult {
  hasBrandImpersonation: boolean;
  hasHomographAttack: boolean;
  hasCryptoScamIndicators: boolean;
  detectedBrand: string | null;
  impersonationType: string | null;
  confusableCharacters: Array<{original: string; lookalike: string}>;
  cryptoTerms: string[];
}

export interface URLFeatures {
  domain: string;
  fullDomain: string;
  tld: string;
  subdomainCount: number;
  hasIPAddress: boolean;
  hasUncommonTLD: boolean;
  hasSuspiciousTLD: boolean;
  hasExcessiveSubdomains: boolean;
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
  subdomains: string[];
  isInvalid?: boolean;
}

export interface UrlAnalysisResult {
  risk: number;
  riskLevel: 'Low' | 'Medium' | 'High';
  flags: string[];
  suspiciousPatterns: string[];
  features: URLFeatures;
  brandDetection?: BrandDetectionResult;
}

export interface FeatureResult extends URLFeatures {}