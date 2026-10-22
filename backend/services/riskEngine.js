/**
 * ByteShield Risk Engine
 * Combines AI and rule-based analysis results
 * Weighted scoring: AI 60% + Rules 40% (when both available)
 */

/**
 * Risk level thresholds
 * LOW: 0-39
 * MEDIUM: 40-69
 * HIGH: 70-100
 */
function getRiskLevel(score) {
  if (score >= 70) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

/**
 * Generate recommendation based on risk level and scan type
 */
function getRecommendation(riskLevel, scanType) {
  const recommendations = {
    HIGH: {
      message: 'This message shows multiple strong scam indicators. Do not click any links, share personal information, or respond. If it claims to be from a known organization, contact them directly through their official app or website.',
      url: 'This URL shows multiple suspicious indicators. Do not visit this link or enter any personal information. If you believe it is from a legitimate service, access that service directly through its official website or app.',
      screenshot: 'This screenshot shows strong indicators of a potential scam. Do not follow any instructions shown in the image. Verify through official channels before taking any action.',
      qr: 'This QR code leads to suspicious content. Do not proceed with any transactions or provide personal information. Verify the source through official channels.'
    },
    MEDIUM: {
      message: 'This message contains some suspicious indicators. Exercise caution and verify the sender through official channels before taking any action.',
      url: 'This URL has some suspicious characteristics. Exercise caution and verify the destination. Consider accessing the service through its official website instead.',
      screenshot: 'This screenshot contains some potentially suspicious elements. Verify the information through official channels before acting on it.',
      qr: 'This QR code has some concerning aspects. Verify the source and destination before proceeding with any actions.'
    },
    LOW: {
      message: 'This message appears to have low risk. However, always verify unexpected requests through official channels and never share sensitive information via messages.',
      url: 'This URL appears to have low risk indicators. Standard internet safety practices still apply — verify before entering sensitive data.',
      screenshot: 'This screenshot appears to have low risk indicators. Standard caution is still recommended for any financial or personal information.',
      qr: 'This QR code appears to have low risk. Standard caution is recommended when scanning QR codes from unknown sources.'
    }
  };

  return (recommendations[riskLevel] && recommendations[riskLevel][scanType])
    || recommendations[riskLevel]?.message
    || 'Exercise standard caution and verify through official channels.';
}

/**
 * Combine AI and rule-based analysis results
 * @param {Object|null} aiResult - Gemini AI result (null if unavailable)
 * @param {Object} ruleResult - Rule engine result
 * @param {string} scanType - Type of scan ('message', 'url', 'screenshot', 'qr')
 * @returns {Object} Combined analysis result
 */
function combineResults(aiResult, ruleResult, scanType = 'message') {
  let finalScore;
  let finalConfidence;
  let allReasons = [];
  let analysisSource;

  if (aiResult && ruleResult) {
    // === Both AI and Rules available ===
    // Weighted average: AI 60% + Rules 40%
    finalScore = Math.round(aiResult.score * 0.6 + ruleResult.score * 0.4);

    // Confidence considers agreement between sources
    const scoreDifference = Math.abs(aiResult.score - ruleResult.score);

    if (scoreDifference <= 15) {
      // Strong agreement — boost confidence
      finalConfidence = Math.min(
        (aiResult.confidence * 0.6 + ruleResult.confidence * 0.4) + 8,
        98
      );
    } else if (scoreDifference <= 30) {
      // Moderate agreement
      finalConfidence = aiResult.confidence * 0.6 + ruleResult.confidence * 0.4;
    } else {
      // Significant disagreement — reduce confidence
      finalConfidence = Math.max(
        (aiResult.confidence * 0.6 + ruleResult.confidence * 0.4) - 12,
        30
      );
    }

    // Combine reasons (deduplicate)
    const reasonSet = new Set();
    if (aiResult.indicators) {
      aiResult.indicators.forEach(r => reasonSet.add(r));
    }
    if (ruleResult.reasons) {
      ruleResult.reasons.forEach(r => reasonSet.add(r));
    }
    allReasons = [...reasonSet];

    analysisSource = 'AI + Rule Engine';
  } else if (aiResult) {
    // === Only AI available ===
    finalScore = aiResult.score;
    finalConfidence = Math.min(aiResult.confidence, 90); // Cap without rule confirmation
    allReasons = aiResult.indicators || [];
    analysisSource = 'AI Only';
  } else if (ruleResult) {
    // === Only Rules available ===
    finalScore = ruleResult.score;
    finalConfidence = ruleResult.confidence;
    allReasons = ruleResult.reasons || [];
    analysisSource = 'Rule Engine Only';
  } else {
    // === Nothing available ===
    return {
      riskLevel: 'LOW',
      riskScore: 0,
      confidence: 0,
      reasons: ['Unable to perform analysis.'],
      recommendation: 'Analysis could not be completed. Please try again.',
      analysisSource: 'None'
    };
  }

  // Ensure score is in bounds
  finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));
  finalConfidence = Math.max(0, Math.min(98, Math.round(finalConfidence * 10) / 10));

  const riskLevel = getRiskLevel(finalScore);

  // Use the best recommendation available
  let recommendation;
  if (aiResult && aiResult.recommendation && aiResult.recommendation.length > 20) {
    recommendation = aiResult.recommendation;
  } else if (ruleResult && ruleResult.recommendation) {
    recommendation = ruleResult.recommendation;
  } else {
    recommendation = getRecommendation(riskLevel, scanType);
  }

  // Filter out "no indicators" messages if we have real reasons
  if (allReasons.length > 1) {
    allReasons = allReasons.filter(r =>
      !r.toLowerCase().includes('no suspicious indicators') &&
      !r.toLowerCase().includes('no specific indicators')
    );
  }

  return {
    riskLevel,
    riskScore: finalScore,
    confidence: finalConfidence,
    reasons: allReasons.length > 0 ? allReasons : ['No specific indicators detected.'],
    recommendation,
    analysisSource
  };
}

module.exports = { combineResults, getRiskLevel, getRecommendation };
