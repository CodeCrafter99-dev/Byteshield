/**
 * ByteShield Rule Engine
 * Local pattern-based analysis for messages
 * Detects scam indicators using regex and keyword patterns
 * Dynamic confidence calculation — NOT hardcoded
 */

/**
 * Indicator categories with patterns and weights
 * Each pattern has:
 *  - regex: the pattern to match
 *  - weight: how much this contributes to risk score (1-15)
 *  - severity: 'low' | 'medium' | 'high'
 *  - description: human-readable explanation
 */
const MESSAGE_PATTERNS = [
  // === Urgency & Time Pressure ===
  {
    regex: /\b(urgent|immediately|right now|right away|act now|hurry|asap|quick(?:ly)?)\b/i,
    weight: 6,
    severity: 'medium',
    category: 'urgency',
    description: 'Creates urgency to pressure quick action'
  },
  {
    regex: /\b(within\s+\d+\s*hours?|within\s+\d+\s*minutes?|expires?\s+(?:soon|today|tonight)|last\s+chance|final\s+warning|limited\s+time)\b/i,
    weight: 8,
    severity: 'high',
    category: 'urgency',
    description: 'Imposes a tight deadline to create panic'
  },

  // === Threats & Fear ===
  {
    regex: /\b(blocked|suspended|deactivated|terminated|closed|frozen|restricted|locked)\b/i,
    weight: 7,
    severity: 'high',
    category: 'threat',
    description: 'Threatens account suspension or restriction'
  },
  {
    regex: /\b(legal\s+action|arrest|police|court|penalty|fine|prosecution)\b/i,
    weight: 9,
    severity: 'high',
    category: 'threat',
    description: 'Threatens legal consequences'
  },
  {
    regex: /\b(your\s+account\s+will\s+be|your\s+account\s+has\s+been|account\s+.*(?:suspend|block|clos|restrict))/i,
    weight: 8,
    severity: 'high',
    category: 'threat',
    description: 'Claims your account is at risk'
  },

  // === Credential & Data Requests ===
  {
    regex: /\b(otp|one[\s-]time[\s-]password|verification\s+code|security\s+code)\b/i,
    weight: 10,
    severity: 'high',
    category: 'credential_request',
    description: 'Requests OTP or verification code'
  },
  {
    regex: /\b(password|pin|cvv|card\s+number|bank\s+details|account\s+number|social\s+security|ssn|aadhaar|pan\s+(?:card|number))\b/i,
    weight: 9,
    severity: 'high',
    category: 'credential_request',
    description: 'Requests sensitive personal or financial information'
  },
  {
    regex: /\b(enter\s+your|provide\s+your|share\s+your|submit\s+your|verify\s+your)\s+\w*(detail|info|credential|password|pin|account)/i,
    weight: 10,
    severity: 'high',
    category: 'credential_request',
    description: 'Directly asks user to enter sensitive information'
  },
  {
    regex: /\b(kyc|know\s+your\s+customer|identity\s+verification|verify\s+(?:your\s+)?(?:identity|account))\b/i,
    weight: 7,
    severity: 'medium',
    category: 'credential_request',
    description: 'References KYC/identity verification (common in phishing)'
  },

  // === Suspicious Links ===
  {
    regex: /https?:\/\/[^\s]+/i,
    weight: 2,
    severity: 'low',
    category: 'link',
    description: 'Contains a URL link',
    aloneIsWeak: true
  },
  {
    regex: /\b(click\s+(?:here|this|the\s+link|below)|tap\s+(?:here|the\s+link)|follow\s+(?:this|the)\s+link|open\s+(?:this|the)\s+link)\b/i,
    weight: 6,
    severity: 'medium',
    category: 'link',
    description: 'Urges clicking on a link'
  },
  {
    regex: /(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy|short\.link|cutt\.ly)/i,
    weight: 5,
    severity: 'medium',
    category: 'link',
    description: 'Contains a URL shortener (hides actual destination)'
  },

  // === Financial / Payment ===
  {
    regex: /\b(transfer|payment|transaction|refund|cashback|reward|prize|lottery|jackpot|won|winner|winning)\b/i,
    weight: 5,
    severity: 'medium',
    category: 'financial',
    description: 'References financial transactions or rewards'
  },
  {
    regex: /\b(free\s+gift|congratulations|you\s+(?:have\s+)?won|claim\s+(?:your|now)|collect\s+(?:your|now))\b/i,
    weight: 8,
    severity: 'high',
    category: 'financial',
    description: 'Unsolicited prize or reward claim'
  },
  {
    regex: /(?:₹|rs\.?|inr|usd|\$|£|€)\s*\d[\d,.]*/i,
    weight: 3,
    severity: 'low',
    category: 'financial',
    description: 'Mentions specific monetary amounts'
  },
  {
    regex: /\b(upi|gpay|phonepe|paytm|google\s*pay|bhim)\b/i,
    weight: 3,
    severity: 'low',
    category: 'financial',
    description: 'References payment platforms',
    aloneIsWeak: true
  },

  // === Impersonation ===
  {
    regex: /\b(sbi|hdfc|icici|axis|pnb|rbi|reserve\s+bank|state\s+bank)\b/i,
    weight: 4,
    severity: 'medium',
    category: 'impersonation',
    description: 'References a known bank (potential impersonation)',
    aloneIsWeak: true
  },
  {
    regex: /\b(customer\s+(?:care|support|service)|helpdesk|help\s+desk|support\s+team|technical\s+support)\b/i,
    weight: 4,
    severity: 'low',
    category: 'impersonation',
    description: 'Claims to be customer support',
    aloneIsWeak: true
  },
  {
    regex: /\b(government|ministry|income\s+tax|irs|fbi|cia|police\s+department)\b/i,
    weight: 5,
    severity: 'medium',
    category: 'impersonation',
    description: 'Claims to be from a government authority'
  },

  // === Social Engineering ===
  {
    regex: /\b(do\s+not\s+share|don'?t\s+share|keep\s+(?:this\s+)?secret|confidential|private\s+message)\b/i,
    weight: 6,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Instructs secrecy (isolation tactic)'
  },
  {
    regex: /\b(dear\s+(?:customer|user|sir|madam|valued\s+member)|your\s+account\s+(?:with|at))\b/i,
    weight: 3,
    severity: 'low',
    category: 'social_engineering',
    description: 'Uses generic greeting (common in mass phishing)'
  },
  {
    regex: /\b(whatsapp|telegram|call\s+(?:us|this|the)\s+number|contact\s+(?:us|this))\b/i,
    weight: 4,
    severity: 'medium',
    category: 'social_engineering',
    description: 'Directs to external communication channel'
  }
];

/**
 * Analyze a message for scam indicators
 * @param {string} text - The message text to analyze
 * @returns {Object} Analysis result with score, confidence, indicators, reasons, recommendation
 */
function analyzeMessage(text) {
  if (!text || typeof text !== 'string') {
    return {
      score: 0,
      confidence: 50,
      indicators: [],
      reasons: ['No text provided for analysis.'],
      recommendation: 'Please provide a message to analyze.'
    };
  }

  const normalizedText = text.trim();
  const matchedIndicators = [];
  const categories = new Set();
  let totalWeight = 0;
  let highSeverityCount = 0;
  let mediumSeverityCount = 0;
  let weakOnlyIndicators = 0;

  // Run all patterns
  for (const pattern of MESSAGE_PATTERNS) {
    if (pattern.regex.test(normalizedText)) {
      matchedIndicators.push({
        description: pattern.description,
        severity: pattern.severity,
        category: pattern.category,
        weight: pattern.weight,
        aloneIsWeak: pattern.aloneIsWeak || false
      });
      categories.add(pattern.category);
      totalWeight += pattern.weight;

      if (pattern.severity === 'high') highSeverityCount++;
      if (pattern.severity === 'medium') mediumSeverityCount++;
      if (pattern.aloneIsWeak) weakOnlyIndicators++;
    }
  }

  // === Calculate Risk Score ===
  // Max possible weight is roughly ~130 (if ALL patterns match), but realistic max is ~80
  // Scale to 0-100
  const strongIndicators = matchedIndicators.length - weakOnlyIndicators;
  let score;

  if (matchedIndicators.length === 0) {
    score = 0;
  } else if (strongIndicators === 0) {
    // Only weak indicators — very low score
    score = Math.min(totalWeight * 2, 25);
  } else {
    // Normalize score: use logarithmic-ish scaling for natural feel
    score = Math.min(Math.round((totalWeight / 60) * 100), 100);

    // Boost for diversity of categories
    const categoryBonus = Math.min((categories.size - 1) * 3, 15);
    score = Math.min(score + categoryBonus, 100);

    // Boost for high severity indicators
    if (highSeverityCount >= 3) {
      score = Math.max(score, 70);
    }
  }

  // === Calculate Dynamic Confidence ===
  let confidence;
  if (matchedIndicators.length === 0) {
    // No indicators — we're fairly confident it's clean, but not 100%
    confidence = 55 + Math.min(normalizedText.length / 20, 15); // 55-70% based on text length
  } else if (strongIndicators === 0) {
    // Only weak indicators — low confidence in risk assessment
    confidence = 35 + matchedIndicators.length * 5;
  } else {
    // Start from base confidence
    confidence = 40;

    // More indicators = more confidence
    confidence += Math.min(strongIndicators * 6, 30);

    // More categories = more confidence
    confidence += Math.min(categories.size * 4, 16);

    // High severity boosts confidence
    confidence += Math.min(highSeverityCount * 3, 12);

    // Cap at 95 (never 100% certain from rules alone)
    confidence = Math.min(confidence, 95);
  }

  // === Generate Reasons ===
  const reasons = matchedIndicators.map(ind => ind.description);
  if (reasons.length === 0) {
    reasons.push('No suspicious indicators detected in this message.');
  }

  // === Generate Recommendation ===
  let recommendation;
  const riskLevel = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';

  if (riskLevel === 'HIGH') {
    recommendation = 'This message shows multiple strong scam indicators. Do not click any links, share personal information, or respond. If this claims to be from a bank or service, contact them directly through their official app or website.';
  } else if (riskLevel === 'MEDIUM') {
    recommendation = 'This message contains some suspicious indicators. Exercise caution. Verify the sender through official channels before taking any action. Do not share sensitive information.';
  } else {
    recommendation = 'This message appears to have low risk indicators. However, always verify unexpected requests through official channels and never share sensitive information via messages.';
  }

  return {
    score: Math.round(score),
    confidence: Math.round(confidence * 10) / 10,
    indicators: matchedIndicators,
    reasons,
    recommendation
  };
}

module.exports = { analyzeMessage };
