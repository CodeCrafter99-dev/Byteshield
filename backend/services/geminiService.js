/**
 * ByteShield Gemini AI Service
 * Integrates Google Gemini API for intelligent scam analysis
 * Uses @google/genai SDK
 */

const path = require('path');
const dotenv = require('dotenv');

// Ensure dotenv is loaded from project root if not already loaded
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const { GoogleGenAI } = require('@google/genai');

// Initialize Gemini client (only if API key is available)
let genai = null;
const apiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : '';
const modelName = process.env.GEMINI_MODEL ? process.env.GEMINI_MODEL.trim() : 'gemini-3.6-flash';

if (apiKey) {
  try {
    genai = new GoogleGenAI({ apiKey });
    console.log(`[Gemini] Initialized successfully with model: ${modelName}`);
  } catch (err) {
    console.warn('[Gemini] Failed to initialize:', err.message);
    genai = null;
  }
} else {
  console.warn('[Gemini] GEMINI_API_KEY is not set in .env. AI features will use rule engine fallback.');
}

/**
 * Extract text safely from Gemini API response
 * Handles undefined text, thought parts, and candidate structures
 */
function extractResponseText(response) {
  if (!response) return null;

  // 1. First try response.text getter
  try {
    if (typeof response.text === 'string' && response.text.trim()) {
      return response.text.trim();
    }
  } catch (e) {
    // Getter threw an error or undefined access
  }

  // 2. Fallback to candidate parts extraction
  try {
    const candidate = response.candidates?.[0];
    const parts = candidate?.content?.parts;
    if (Array.isArray(parts) && parts.length > 0) {
      const textParts = parts
        .filter(p => typeof p.text === 'string' && !p.thought)
        .map(p => p.text);
      if (textParts.length > 0) {
        const joined = textParts.join('').trim();
        if (joined) return joined;
      }
    }
  } catch (e) {
    // Ignore candidate extraction error
  }

  return null;
}

/**
 * Format error for logging without exposing sensitive data (keys/credentials)
 */
function formatErrorDetails(err, operation) {
  let status = err?.status || err?.code || 'N/A';
  let message = err?.message || 'Unknown error';

  // Sanitize message to never leak API key
  if (apiKey) {
    message = message.split(apiKey).join('[REDACTED_API_KEY]');
  }

  // Extract nested status code if available
  if (err?.error?.code) {
    status = err.error.code;
  }
  if (err?.error?.message) {
    let subMsg = err.error.message;
    if (apiKey) subMsg = subMsg.split(apiKey).join('[REDACTED_API_KEY]');
    message = `${message} (Detail: ${subMsg})`;
  }

  return `[Gemini] ${operation} failed | HTTP/Status: ${status} | Error: ${message}`;
}

/**
 * Check if an error is transient (e.g. 503, 429, 500, network timeouts)
 */
function isTransientError(err) {
  const status = Number(err?.status || err?.error?.code || err?.code);
  if ([503, 502, 504, 500, 429].includes(status)) {
    return true;
  }
  const msg = (err?.message || '').toLowerCase();
  if (
    msg.includes('high demand') ||
    msg.includes('temporary') ||
    msg.includes('unavailable') ||
    msg.includes('overloaded') ||
    msg.includes('rate limit') ||
    msg.includes('timeout') ||
    msg.includes('econnreset')
  ) {
    return true;
  }
  return false;
}

// Primary model from .env; fallback models verified via list() if primary has a 503 outage or 429 quota exhaustion
const FALLBACK_MODELS = ['gemini-3.5-flash-lite', 'gemini-3.5-flash'];

/**
 * Execute generateContent with single retry and fallback model on transient errors
 */
async function callGeminiWithRetry(params, operationName) {
  try {
    return await genai.models.generateContent(params);
  } catch (err) {
    console.error(formatErrorDetails(err, operationName));

    if (isTransientError(err)) {
      console.warn(`[Gemini] Transient error on ${params.model || modelName} during ${operationName}. Retrying once with backoff...`);
      await new Promise(res => setTimeout(res, 1200));

      try {
        return await genai.models.generateContent(params);
      } catch (retryErr) {
        console.error(formatErrorDetails(retryErr, `${operationName} (Retry primary)`));

        // If primary model still fails with 503/429, try verified fallback models in order
        for (const fbModel of FALLBACK_MODELS) {
          if (params.model !== fbModel) {
            console.warn(`[Gemini] Primary model unavailable. Attempting verified fallback model: ${fbModel}...`);
            try {
              const fallbackParams = { ...params, model: fbModel };
              return await genai.models.generateContent(fallbackParams);
            } catch (fallbackErr) {
              console.error(formatErrorDetails(fallbackErr, `${operationName} (Fallback ${fbModel})`));
            }
          }
        }
        throw retryErr;
      }
    } else {
      // Permanent error (e.g. 400 Invalid Argument, 403 Forbidden, 401 Unauthorized) -> do not retry
      throw err;
    }
  }
}

/**
 * Check if Gemini is available
 */
function isAvailable() {
  return genai !== null;
}

/**
 * Analyze a text message for scam indicators
 * @param {string} text - Message text to analyze
 * @returns {Object|null} Analysis result or null if unavailable
 */
async function analyzeMessage(text) {
  if (!genai) return null;

  try {
    const prompt = `You are a cybersecurity expert analyzing a message for potential scam or phishing indicators.

Analyze the following message and provide your assessment.

IMPORTANT RULES:
- Be balanced and fair in your assessment
- Individual indicators alone are not proof of fraud
- Consider the overall context and combination of indicators
- Do not claim something is definitely a scam unless there is strong evidence
- A legitimate bank name appearing does not automatically make it a scam

Message to analyze:
"""
${text}
"""

Respond ONLY with valid JSON in this exact format (no markdown, no code blocks):
{
  "score": <number 0-100>,
  "confidence": <number 0-100>,
  "indicators": [<list of detected indicator strings>],
  "recommendation": "<one paragraph recommendation>"
}`;

    const response = await callGeminiWithRetry({
      model: modelName,
      contents: prompt,
      config: {
        temperature: 0.1,
        responseMimeType: 'application/json'
      }
    }, 'analyzeMessage');

    const responseText = extractResponseText(response);
    if (!responseText) {
      console.warn('[Gemini] analyzeMessage: No text content in Gemini response');
      return null;
    }

    return parseGeminiResponse(responseText);
  } catch (err) {
    // Already logged in callGeminiWithRetry
    return null;
  }
}

/**
 * Analyze a URL for suspicious indicators
 * @param {string} url - URL to analyze
 * @returns {Object|null} Analysis result or null if unavailable
 */
async function analyzeUrl(url) {
  if (!genai) return null;

  try {
    const prompt = `You are a cybersecurity expert analyzing a URL for potential phishing or scam indicators.

Analyze the following URL and provide your assessment.

IMPORTANT RULES:
- Individual indicators are risk factors, NOT definitive proof of fraud
- A suspicious TLD (.xyz, .tk, etc.) alone does not make a URL malicious
- Missing HTTPS alone is a minor concern, not proof of scam
- Consider the overall combination of indicators
- Be fair and balanced — many legitimate websites use uncommon TLDs
- Brand names in domains are suspicious but not conclusive

URL to analyze:
${url}

Respond ONLY with valid JSON in this exact format (no markdown, no code blocks):
{
  "score": <number 0-100>,
  "confidence": <number 0-100>,
  "indicators": [<list of detected indicator strings>],
  "recommendation": "<one paragraph recommendation>"
}`;

    const response = await callGeminiWithRetry({
      model: modelName,
      contents: prompt,
      config: {
        temperature: 0.1,
        responseMimeType: 'application/json'
      }
    }, 'analyzeUrl');

    const responseText = extractResponseText(response);
    if (!responseText) {
      console.warn('[Gemini] analyzeUrl: No text content in Gemini response');
      return null;
    }

    return parseGeminiResponse(responseText);
  } catch (err) {
    // Already logged in callGeminiWithRetry
    return null;
  }
}

/**
 * Analyze a screenshot image for scam indicators
 * @param {Buffer} imageBuffer - Image data as buffer
 * @param {string} mimeType - Image MIME type
 * @returns {Object|null} Analysis result or null if unavailable
 */
async function analyzeImage(imageBuffer, mimeType) {
  if (!genai) return null;

  try {
    const base64Image = imageBuffer.toString('base64');
    const now = new Date();
    const currentDateStr = now.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    const currentYear = now.getFullYear();

    const prompt = `You are an expert digital forensics and cybersecurity analyst specializing in mobile UI verification, UPI payment workflows, and scam detection.

CURRENT SYSTEM CONTEXT:
- Today's Date: ${currentDateStr} (${currentYear}).
- Dates in ${currentYear} (e.g., October ${currentYear}) are current/recent valid dates, NOT future dates.

TASK:
Analyze the provided screenshot and classify it into one of these categories:
1. Genuine/normal payment receipt: Standard mobile payment UI (Google Pay, PhonePe, Paytm, BHIM) with consistent fonts, standard layout, and no visible tampering.
2. Fabricated or visibly altered payment screenshot: Concrete evidence of tampering (e.g., mismatched font, text pasted over amount, digital artifacts, broken UI geometry).
3. Inconclusive / low-quality / cropped screenshot: Blurry, heavily compressed, or tightly cropped such that visual authenticity cannot be reliably judged.
4. Active scam lure or phishing: Prompts to enter UPI PIN to receive money, fake prize/lottery alerts, phishing links, or spoofed bank alert messages.
5. Non-payment screenshot: Benign app screenshot, logo, or interface unrelated to payments.

CRITICAL GUIDELINES FOR INDIAN UPI / GOOGLE PAY SCREENSHOTS:
- Standard authentic elements in Google Pay / UPI receipts include:
  * Recipient and sender names and masked phone numbers (e.g., +91 .....1917)
  * Green 'Completed' or 'Paid' status checkmarks, Rupee amounts (e.g., ₹1,000)
  * Bank names (State Bank of India, HDFC Bank, ICICI Bank, Axis Bank, etc.) with bank logos
  * 12-digit numeric UPI transaction IDs
  * Google transaction IDs (alphanumeric strings like CICAgPi-otibUA)
  * VPA handles ending in @okicici, @okhdfcbank, @oksbi, @okaxis, @paytm, @ybl
  * Action buttons like 'Having issues?' and 'Share'
  * Android/iOS status bars (battery, Wi-Fi, time, network icons) and gesture navigation bar
- WHAT IS NOT FRAUD:
  * Do NOT flag standard UPI fields, bank names, transaction IDs, Rupee symbols, or Google Pay branding as suspicious. They are normal, legitimate components.
  * Do NOT invent suspicious indicators or assume tampering without concrete visual evidence.
- LIMITATIONS OF SCREENSHOT ANALYSIS:
  * A screenshot alone cannot prove that money actually settled into the recipient's bank account. However, absence of bank settlement proof is NOT evidence of image tampering. A standard, untampered receipt layout should be classified as LOW risk, with advice to verify in the bank account.

SCORING & CALIBRATION RUBRIC:
- LOW RISK (0 - 35):
  * Standard, consistent layout with no visible signs of tampering, font inconsistencies, or editing artifacts. (Score: 5 - 20, indicators: []).
  * Non-payment benign screenshots (app home screens, logos, settings). (Score: 0 - 15, indicators: []).
  * Recommendation: State that visual layout shows no tampering, and provide standard advice to confirm fund credit in the official bank app or Google Pay app.
- MEDIUM RISK (36 - 65):
  * Inconclusive: Image is heavily cropped, blurry, low resolution, or partially obscured, preventing reliable forensic inspection.
  * Mild visual discrepancies where tampering cannot be confirmed nor ruled out.
  * Recommendation: Note that image quality is too low or cropped to confirm visual integrity; advise checking bank statement directly.
- HIGH RISK (66 - 100):
  * Observable proof of editing (e.g., obvious font/weight mismatch on the amount, cut-and-paste artifacts, duplicated text layers, altered digits).
  * Obvious fake payment app templates (e.g. spoof apps with caricature logos, wrong currency symbols, broken UI geometry).
  * Direct scam indicators (asking for UPI PIN/OTP to receive money, fake lottery winnings, phishing links).

Respond ONLY with valid JSON in this exact format:
{
  "score": <number 0-100>,
  "confidence": <number 0-100>,
  "indicators": [<list of concrete observed indicators, or empty [] if none>],
  "recommendation": "<concise recommendation, including standard guidance to verify funds in official bank app if payment receipt>"
}`;

    const response = await callGeminiWithRetry({
      model: modelName,
      contents: [
        {
          role: 'user',
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType: mimeType || 'image/jpeg',
                data: base64Image
              }
            }
          ]
        }
      ],
      config: {
        temperature: 0.1,
        responseMimeType: 'application/json'
      }
    }, 'analyzeImage');

    const responseText = extractResponseText(response);
    if (!responseText) {
      console.warn('[Gemini] analyzeImage: No text content in Gemini response');
      return null;
    }

    return parseGeminiResponse(responseText);
  } catch (err) {
    // Already logged in callGeminiWithRetry
    return null;
  }
}

/**
 * Parse Gemini response text into structured object
 * Handles potential markdown code blocks and JSON extraction
 */
function parseGeminiResponse(text) {
  try {
    let cleaned = (text || '').trim();
    if (cleaned.startsWith('```json')) {
      cleaned = cleaned.replace(/^```json\s*/, '').replace(/\s*```$/, '');
    } else if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```\s*/, '').replace(/\s*```$/, '');
    }

    // Isolate JSON if surrounded by extraneous commentary
    const firstBrace = cleaned.indexOf('{');
    const lastBrace = cleaned.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      cleaned = cleaned.substring(firstBrace, lastBrace + 1);
    }

    const parsed = JSON.parse(cleaned);

    // Validate required fields
    return {
      score: Math.max(0, Math.min(100, Math.round(Number(parsed.score) || 0))),
      confidence: Math.max(0, Math.min(100, Math.round(Number(parsed.confidence) || 50))),
      indicators: Array.isArray(parsed.indicators)
        ? parsed.indicators.filter(i => typeof i === 'string' && i.trim().length > 0)
        : [],
      recommendation: parsed.recommendation || 'No specific recommendation provided.'
    };
  } catch (err) {
    console.error('[Gemini] Failed to parse response:', err.message);
    console.error('[Gemini] Raw response:', text ? text.substring(0, 200) : 'null');
    return null;
  }
}

module.exports = { isAvailable, analyzeMessage, analyzeUrl, analyzeImage };
