interface UrlAnalysisResult {
  risk: number; // 0-1 score
  flags: string[];
  brandMatches: boolean;
  suspiciousPatterns: string[];
  typosquatting?: string; // Original brand name if typosquatting detected
}

export class UrlAnalyzer {
  private suspiciousKeywords = [
    'login', 'signin', 'account', 'secure', 'verify', 'update', 'confirm',
    'banking', 'password', 'credential'
  ];

  private commonBrands = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
    'netflix', 'linkedin', 'twitter', 'instagram', 'bank'
  ];

  private tldList = ['.com', '.org', '.net', '.edu', '.gov'];
  private commonTLDs = new Set(['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.biz', '.info']);
  private suspiciousFileExtensions = new Set(['.exe', '.zip', '.scr', '.js', '.msi', '.bat', '.dll']);

  analyzeUrl(url: string): UrlAnalysisResult {
    const result: UrlAnalysisResult = {
      risk: 0,
      flags: [],
      brandMatches: false,
      suspiciousPatterns: []
    };

    try {
      const urlObj = new URL(url);
      
      // Check for special characters in URL
      if (/@/.test(url) || /[<>{}|\\\^\[\]]/.test(url)) {
        result.flags.push('SPECIAL_CHARS_IN_DOMAIN');
        result.risk += 0.25;
      }

      // Check for IP address in hostname
      if (this.isIpAddress(urlObj.hostname)) {
        result.flags.push('IP_ADDRESS_URL');
        result.risk += 0.3;
      }

      // Enhanced TLD check
      const tld = this.extractTLD(urlObj.hostname);
      if (!this.commonTLDs.has(tld)) {
        result.flags.push('UNCOMMON_TLD');
        result.risk += 0.2;
      }

      // Check for suspicious file extensions
      const pathExt = this.getFileExtension(urlObj.pathname);
      if (pathExt && this.suspiciousFileExtensions.has(pathExt.toLowerCase())) {
        result.flags.push('SUSPICIOUS_FILE_EXTENSION');
        result.risk += 0.25;
      }

      // Enhanced brand impersonation and typosquatting check
      const domainParts = urlObj.hostname.toLowerCase().split('.');
      // Use the second-to-last part for domains like google.com, or the third-to-last for www.google.com
      const mainDomain = domainParts.length > 1 ? 
        (domainParts[0] === 'www' && domainParts.length > 2 ? domainParts[1] : domainParts[domainParts.length - 2]) :
        domainParts[0];

      // Check main domain for brand impersonation
      const brandCheck = this.checkBrandImpersonation(mainDomain);
      if (brandCheck.impersonated) {
        result.flags.push('BRAND_IMPERSONATION');
        result.brandMatches = true;
        result.typosquatting = brandCheck.originalBrand;
        result.risk += 0.4;
      }

      // Check for brand names in subdomains (e.g., login-paypal.malicious.com)
      if (!brandCheck.impersonated) {
        // Check if any subdomain part contains a brand name
        const fullDomainString = urlObj.hostname.toLowerCase();
        for (const brand of this.commonBrands) {
          // Skip if the domain is exactly the brand (legitimate)
          if (mainDomain === brand) continue;
          
          // Check if any part contains the brand name
          if (fullDomainString.includes(brand) && mainDomain !== brand) {
            result.flags.push('BRAND_IMPERSONATION');
            result.brandMatches = true;
            result.typosquatting = brand;
            result.risk += 0.4;
            break;
          }
        }
      }

      // Base risk adjustment for legitimate domains
      if (this.commonBrands.includes(mainDomain)) {
        // If it's a legitimate brand domain with no flags yet, keep risk very low
        if (result.flags.length === 0) {
          result.risk = 0.1;
        } else {
          result.risk = Math.max(0.1, result.risk - 0.3);
        }
      }

      // Check for suspicious keywords in URL
      for (const keyword of this.suspiciousKeywords) {
        if (url.toLowerCase().includes(keyword)) {
          result.suspiciousPatterns.push(keyword);
          result.risk += 0.1;
        }
      }

      // Check for excessive subdomains
      const subdomainCount = urlObj.hostname.split('.').length - 2;
      if (subdomainCount > 2) {
        result.flags.push('EXCESSIVE_SUBDOMAINS');
        result.risk += 0.15;
      }

      // Check for numeric domain
      if (/^\d+$/.test(urlObj.hostname.split('.')[0])) {
        result.flags.push('NUMERIC_DOMAIN');
        result.risk += 0.2;
      }

      // Check for data URI scheme
      if (url.startsWith('data:')) {
        result.flags.push('DATA_URI_SCHEME');
        result.risk += 0.5;
      }

      // Check for URL encoding abuse
      if (this.hasExcessiveEncoding(url)) {
        result.flags.push('EXCESSIVE_ENCODING');
        result.risk += 0.3;
      }

      // Check for redirect in URL
      if (url.includes('redirect') || url.includes('url=') || url.includes('goto=')) {
        result.flags.push('REDIRECT_PRESENT');
        result.risk += 0.15;
      }

      // Cap the risk score at 1
      result.risk = Math.min(result.risk, 1);

    } catch (error) {
      result.flags.push('INVALID_URL');
      result.risk = 1;
    }

    return result;
  }

  private extractTLD(hostname: string): string {
    const parts = hostname.split('.');
    return parts.length > 1 ? '.' + parts[parts.length - 1] : '';
  }

  private getFileExtension(path: string): string | null {
    const match = path.match(/\.[^.\/]+$/);
    return match ? match[0] : null;
  }

  private checkBrandImpersonation(domain: string): { impersonated: boolean; originalBrand?: string } {
    for (const brand of this.commonBrands) {
      // Exact match means it's legitimate
      if (domain === brand) {
        return { impersonated: false };
      }

      // Check for character substitution
      const normalized = this.normalizeString(domain);
      if (normalized === brand && domain !== brand) {
        return { impersonated: true, originalBrand: brand };
      }
      
      // Check for brand name within domain (for example googgle contains google)
      if (domain !== brand && domain.includes(brand)) {
        return { impersonated: true, originalBrand: brand };
      }

      // Check for typosquatting using Levenshtein distance
      const distance = this.levenshteinDistance(domain, brand);
      
      // More lenient distance for typosquatting detection
      // For short brands, allow 1 character difference
      // For longer brands, allow up to 2 character differences
      const maxAllowedDistance = brand.length <= 5 ? 1 : 2;
      
      if (distance > 0 && distance <= maxAllowedDistance) {
        return { impersonated: true, originalBrand: brand };
      }
      
      // Check for keyboard-adjacent typos
      if (domain.length === brand.length && this.areCharactersAdjacent(domain, brand)) {
        return { impersonated: true, originalBrand: brand };
      }

      // Better check for repeated characters (e.g., googgle)
      if (domain !== brand && 
          domain.length > brand.length && 
          domain.replace(/(.)(?=\1)/g, '') === brand.replace(/(.)(?=\1)/g, '')) {
        return { impersonated: true, originalBrand: brand };
      }
    }
    return { impersonated: false };
  }

  private areCharactersAdjacent(str1: string, str2: string): boolean {
    const keyboard = {
      'q': ['w','a'], 'w': ['q','e','s'], 'e': ['w','r','d'], 'r': ['e','t','f'], 't': ['r','y','g'],
      'y': ['t','u','h'], 'u': ['y','i','j'], 'i': ['u','o','k'], 'o': ['i','p','l'], 'p': ['o','['],
      'a': ['q','s','z'], 's': ['w','a','d','x'], 'd': ['e','s','f','c'], 'f': ['r','d','g','v'],
      'g': ['t','f','h','b'], 'h': ['y','g','j','n'], 'j': ['u','h','k','m'], 'k': ['i','j','l'],
      'l': ['o','k',';'], 'z': ['a','x'], 'x': ['s','z','c'], 'c': ['d','x','v'],
      'v': ['f','c','b'], 'b': ['g','v','n'], 'n': ['h','b','m'], 'm': ['j','n']
    };

    if (str1.length !== str2.length) return false;

    for (let i = 0; i < str1.length; i++) {
      if (str1[i] !== str2[i]) {
        const adjacent = keyboard[str2[i]] || [];
        if (!adjacent.includes(str1[i])) {
          return false;
        }
      }
    }
    return true;
  }

  private hasExcessiveEncoding(url: string): boolean {
    const percentCount = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    return percentCount > 3;
  }

  private normalizeString(str: string): string {
    return str
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/5/g, 's')
      .replace(/\$/g, 's')
      .replace(/@/g, 'a');
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str1.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str2.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str1.length; i++) {
      for (let j = 1; j <= str2.length; j++) {
        if (str1[i-1] === str2[j-1]) {
          matrix[i][j] = matrix[i-1][j-1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i-1][j-1] + 1,
            matrix[i][j-1] + 1,
            matrix[i-1][j] + 1
          );
        }
      }
    }

    return matrix[str1.length][str2.length];
  }

  private isIpAddress(hostname: string): boolean {
    // Simple IPv4 check
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

  getRiskLevel(risk: number): 'Low' | 'Medium' | 'High' {
    if (risk < 0.3) return 'Low';
    if (risk < 0.6) return 'Medium';
    return 'High';
  }
}