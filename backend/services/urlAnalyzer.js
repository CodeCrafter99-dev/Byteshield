/**
 * ByteShield URL Analyzer
 * Analyzes URLs for suspicious indicators
 * Indicators are risk factors, NOT definitive proof of fraud
 */

// Known suspicious TLDs (higher risk, but NOT proof of fraud)
const SUSPICIOUS_TLDS = [
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz',
  '.club', '.work', '.click', '.link', '.info', '.icu', '.cam',
  '.rest', '.surf', '.monster'
];

// Known URL shortener domains
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rb.gy',
  'short.link', 'cutt.ly', 'ow.ly', 'tiny.cc', 'shorte.st',
  'adf.ly', 'buff.ly', 'clck.ru', 'v.gd'
];

// Well-known brands commonly targeted for impersonation
const PRIMARY_BRANDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'pnb', 'rbi', 'paypal', 'amazon',
  'flipkart', 'google', 'microsoft', 'apple', 'facebook', 'instagram',
  'whatsapp', 'netflix', 'paytm', 'phonepe', 'gpay', 'razorpay'
];

// Security / banking / account terms often combined with brand names in fake domains
const DOMAIN_SECURITY_KEYWORDS = [
  'login', 'secure', 'verify', 'verification', 'account', 'update',
  'banking', 'kyc', 'support', 'helpdesk', 'service', 'official'
];

// Suspicious URL path keywords
const SUSPICIOUS_PATH_KEYWORDS = [
  'login', 'signin', 'verify', 'update', 'confirm', 'secure',
  'account', 'password', 'credential', 'banking', 'kyc',
  'suspend', 'block', 'unlock', 'restore', 'claim', 'prize',
  'reward', 'winner', 'gift', 'free', 'offer'
];

/**
 * Analyze a URL for suspicious indicators
 * @param {string} urlString - URL to analyze
 * @returns {Object} Analysis result
 */
function analyzeUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return {
      score: 0,
      confidence: 50,
      indicators: [],
      reasons: ['No URL provided for analysis.'],
      recommendation: 'Please provide a URL to analyze.'
    };
  }

  // Normalize URL
  let url;
  try {
    // Add protocol if missing
    let normalizedUrl = urlString.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }
    url = new URL(normalizedUrl);
  } catch (err) {
    return {
      score: 15,
      confidence: 40,
      indicators: [{ description: 'Invalid or malformed URL', severity: 'medium', weight: 5 }],
      reasons: ['The URL appears to be malformed or invalid.'],
      recommendation: 'This URL could not be parsed. Exercise caution with unusually formatted URLs.'
    };
  }

  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();
  const fullUrl = url.href.toLowerCase();
  const matchedIndicators = [];
  const categories = new Set();
  let totalWeight = 0;

  // === Check 1: HTTP vs HTTPS ===
  if (url.protocol === 'http:') {
    matchedIndicators.push({
      description: 'Uses HTTP instead of HTTPS — data is not encrypted in transit',
      severity: 'medium',
      weight: 5,
      category: 'protocol'
    });
    categories.add('protocol');
    totalWeight += 5;
  }

  // === Check 2: Brand Impersonation ===
  const brandMatches = [];
  for (const brand of PRIMARY_BRANDS) {
    if (hostname.includes(brand) && !isOfficialDomain(hostname, brand)) {
      brandMatches.push(brand);
    }
  }

  if (brandMatches.length > 0) {
    matchedIndicators.push({
      description: `Contains brand keyword(s) "${brandMatches.join(', ')}" in an unofficial domain — potential brand impersonation`,
      severity: 'high',
      weight: 10,
      category: 'impersonation'
    });
    categories.add('impersonation');
    totalWeight += 10;
  }

  // === Check 3: Domain Security / Verification Keywords ===
  const domainSecMatches = DOMAIN_SECURITY_KEYWORDS.filter(k => hostname.includes(k));
  if (domainSecMatches.length > 0) {
    // High severity if co-occurring with brand impersonation or multiple keywords
    const isHigh = brandMatches.length > 0 || domainSecMatches.length >= 2;
    matchedIndicators.push({
      description: `Domain contains security/verification keyword(s): "${domainSecMatches.join(', ')}"`,
      severity: isHigh ? 'high' : 'medium',
      weight: isHigh ? 7 : 4,
      category: 'domain_keywords'
    });
    categories.add('domain_keywords');
    totalWeight += isHigh ? 7 : 4;
  }

  // === Check 4: Suspicious TLD ===
  const tld = '.' + hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    // If co-occurring with brand impersonation or domain security terms, elevate severity
    const hasOtherThreats = brandMatches.length > 0 || domainSecMatches.length > 0;
    matchedIndicators.push({
      description: `Uses uncommon TLD "${tld}" — often associated with low-cost domain registration used in phishing`,
      severity: hasOtherThreats ? 'high' : 'medium',
      weight: hasOtherThreats ? 7 : 5,
      category: 'tld',
      aloneIsWeak: !hasOtherThreats
    });
    categories.add('tld');
    totalWeight += hasOtherThreats ? 7 : 5;
  }

  // === Check 5: IP address instead of domain ===
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(hostname)) {
    matchedIndicators.push({
      description: 'Uses an IP address instead of a domain name — legitimate services typically use registered domains',
      severity: 'high',
      weight: 10,
      category: 'domain'
    });
    categories.add('domain');
    totalWeight += 10;
  }

  // === Check 6: URL shortener ===
  if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
    matchedIndicators.push({
      description: 'Uses a URL shortener — hides the actual destination URL',
      severity: 'medium',
      weight: 6,
      category: 'shortener'
    });
    categories.add('shortener');
    totalWeight += 6;
  }

  // === Check 7: Excessive subdomains ===
  const parts = hostname.split('.');
  if (parts.length > 3) {
    matchedIndicators.push({
      description: `Has ${parts.length - 1} subdomains — excessive subdomains can be used to mimic legitimate domains`,
      severity: 'medium',
      weight: 5,
      category: 'structure'
    });
    categories.add('structure');
    totalWeight += 5;
  }

  // === Check 8: Suspicious path keywords ===
  const pathMatches = SUSPICIOUS_PATH_KEYWORDS.filter(k => pathname.includes(k));
  if (pathMatches.length >= 1) {
    const isHighRiskPath = pathMatches.some(k => ['kyc', 'login', 'signin', 'password', 'credential', 'banking'].includes(k));
    const isHigh = (pathMatches.length >= 2 || isHighRiskPath) && brandMatches.length > 0;
    const weight = (pathMatches.length >= 2 || isHighRiskPath) ? 6 : 4;
    matchedIndicators.push({
      description: `URL path contains suspicious security/action keyword(s): "${pathMatches.join(', ')}"`,
      severity: isHigh ? 'high' : 'medium',
      weight,
      category: 'path'
    });
    categories.add('path');
    totalWeight += weight;
  }

  // === Check 9: Suspicious characters in URL ===
  if (fullUrl.includes('@') || fullUrl.includes('%40')) {
    matchedIndicators.push({
      description: 'Contains "@" symbol — can be used to disguise the actual destination',
      severity: 'high',
      weight: 8,
      category: 'obfuscation'
    });
    categories.add('obfuscation');
    totalWeight += 8;
  }

  // === Check 10: Unusually long URL ===
  if (fullUrl.length > 200) {
    matchedIndicators.push({
      description: 'Unusually long URL — may be attempting to hide suspicious elements',
      severity: 'low',
      weight: 3,
      category: 'structure'
    });
    categories.add('structure');
    totalWeight += 3;
  }

  // === Check 11: Encoded characters ===
  const encodedCount = (fullUrl.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (encodedCount > 5) {
    matchedIndicators.push({
      description: 'Contains many encoded characters — may be obfuscating the actual URL content',
      severity: 'medium',
      weight: 5,
      category: 'obfuscation'
    });
    categories.add('obfuscation');
    totalWeight += 5;
  }

  // === Check 12: Hyphenated domain (brand-impersonation style) ===
  const domainWithoutTld = hostname.split('.').slice(0, -1).join('.');
  const hyphenCount = (domainWithoutTld.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    matchedIndicators.push({
      description: `Domain contains ${hyphenCount} hyphens — commonly seen in phishing domains mimicking legitimate services`,
      severity: 'medium',
      weight: 5,
      category: 'structure'
    });
    categories.add('structure');
    totalWeight += 5;
  }

  // === Calculate Score ===
  const weakOnlyIndicators = matchedIndicators.filter(i => i.aloneIsWeak).length;
  const strongIndicators = matchedIndicators.length - weakOnlyIndicators;
  const highSeverityCount = matchedIndicators.filter(i => i.severity === 'high').length;
  let score;

  if (matchedIndicators.length === 0) {
    score = 0;
  } else if (strongIndicators === 0) {
    score = Math.min(totalWeight * 2, 25);
  } else {
    // Base score calculation normalized against max typical single-aspect threat
    score = Math.min(Math.round((totalWeight / 38) * 100), 100);
    const categoryBonus = Math.min((categories.size - 1) * 3, 15);
    score = Math.min(score + categoryBonus, 100);

    // Compounding boost: 2 or more high-severity indicators naturally cross HIGH threshold (70+)
    if (highSeverityCount >= 2) {
      score = Math.max(score, 72);
    }
  }

  // === Calculate Dynamic Confidence ===
  let confidence;
  if (matchedIndicators.length === 0) {
    confidence = 65; // Fairly confident it looks clean
  } else if (strongIndicators === 0) {
    confidence = 35 + matchedIndicators.length * 5;
  } else {
    confidence = 45;
    confidence += Math.min(strongIndicators * 7, 28);
    confidence += Math.min(categories.size * 4, 16);
    confidence += Math.min(highSeverityCount * 4, 12);
    confidence = Math.min(confidence, 95);
  }

  // === Generate reasons ===
  const reasons = matchedIndicators.map(i => i.description);
  if (reasons.length === 0) {
    reasons.push('No suspicious indicators detected for this URL.');
  }

  // === Generate recommendation ===
  const riskLevel = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  let recommendation;

  if (riskLevel === 'HIGH') {
    recommendation = 'This URL shows multiple suspicious indicators. Do not visit this link or enter any personal information. If you believe it claims to be from a legitimate service, access that service directly through its official website or app.';
  } else if (riskLevel === 'MEDIUM') {
    recommendation = 'This URL has some suspicious characteristics. Exercise caution and verify the destination. Consider accessing the service through its official website instead.';
  } else {
    recommendation = 'This URL appears to have low risk indicators. Standard internet safety practices still apply — verify before entering sensitive data on unfamiliar websites.';
  }

  return {
    score: Math.round(score),
    confidence: Math.round(confidence * 10) / 10,
    indicators: matchedIndicators,
    reasons,
    recommendation
  };
}

/**
 * Check if a domain is an official domain for a brand
 */
function isOfficialDomain(hostname, brand) {
  const officialDomains = {
    'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'sbi.co', 'onlinesbi.com'],
    'hdfc': ['hdfcbank.com', 'hdfc.com', 'hdfcbank.co.in'],
    'icici': ['icicibank.com', 'icici.com', 'icicibank.co.in'],
    'google': ['google.com', 'google.co.in', 'googleapis.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
    'amazon': ['amazon.com', 'amazon.in', 'amazonaws.com'],
    'apple': ['apple.com', 'icloud.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'paypal': ['paypal.com'],
    'netflix': ['netflix.com'],
    'flipkart': ['flipkart.com'],
    'paytm': ['paytm.com'],
  };

  const official = officialDomains[brand];
  if (!official) return false;
  return official.some(d => hostname === d || hostname.endsWith('.' + d));
}

module.exports = { analyzeUrl };
