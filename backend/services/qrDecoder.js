/**
 * ByteShield QR Code Decoder
 * Decodes QR codes from images using jsQR and Jimp
 * Analyzes decoded content for potential threats
 */

const jsQR = require('jsqr');
const Jimp = require('jimp');

/**
 * Decode a QR code from an image buffer
 * @param {Buffer} imageBuffer - Image file buffer
 * @returns {Object} Decoded content and metadata
 */
async function decodeQR(imageBuffer) {
  try {
    // Read image using Jimp
    const image = await Jimp.Jimp.read(imageBuffer);
    const width = image.width;
    const height = image.height;

    // Get raw RGBA pixel data
    const bitmap = image.bitmap;
    const imageData = new Uint8ClampedArray(bitmap.data);

    // Decode QR code
    const code = jsQR(imageData, width, height);

    if (!code) {
      return {
        success: false,
        error: 'No QR code found in the image. Please upload a clear image containing a QR code.',
        content: null,
        contentType: null
      };
    }

    const content = code.data;

    // Determine content type
    const contentType = classifyContent(content);

    return {
      success: true,
      content,
      contentType,
      error: null
    };
  } catch (err) {
    console.error('[QR] Decode error:', err.message);
    return {
      success: false,
      error: 'Failed to process the image. Please ensure it is a valid image file.',
      content: null,
      contentType: null
    };
  }
}

/**
 * Classify decoded QR content
 * @param {string} content - Decoded QR string
 * @returns {string} Content type
 */
function classifyContent(content) {
  if (!content) return 'unknown';

  // URL
  if (/^https?:\/\//i.test(content) || /^www\./i.test(content)) {
    return 'url';
  }

  // UPI payment (Indian payment system)
  if (/^upi:\/\//i.test(content)) {
    return 'upi';
  }

  // Email
  if (/^mailto:/i.test(content)) {
    return 'email';
  }

  // Phone
  if (/^tel:/i.test(content)) {
    return 'phone';
  }

  // SMS
  if (/^sms:/i.test(content) || /^smsto:/i.test(content)) {
    return 'sms';
  }

  // WiFi
  if (/^WIFI:/i.test(content)) {
    return 'wifi';
  }

  // vCard
  if (/^BEGIN:VCARD/i.test(content)) {
    return 'vcard';
  }

  // Plain text with URL-like content
  if (/[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}/.test(content)) {
    return 'possible_url';
  }

  return 'text';
}

/**
 * Analyze decoded QR content for suspicious indicators
 * @param {string} content - Decoded content
 * @param {string} contentType - Type of content
 * @returns {Object} Analysis result
 */
function analyzeQRContent(content, contentType) {
  const indicators = [];
  let score = 0;
  let confidence = 50;
  const reasons = [];

  switch (contentType) {
    case 'url':
    case 'possible_url':
      // URL analysis will be handled by urlAnalyzer in the route
      reasons.push(`QR code contains a URL: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`);
      break;

    case 'upi':
      // Parse UPI details
      const upiDetails = parseUPI(content);
      reasons.push(`QR code contains UPI payment information`);
      if (upiDetails.pa) reasons.push(`Payment address: ${upiDetails.pa}`);
      if (upiDetails.pn) reasons.push(`Payee name: ${upiDetails.pn}`);
      if (upiDetails.am) reasons.push(`Amount: ₹${upiDetails.am}`);
      if (upiDetails.tn) reasons.push(`Transaction note: ${upiDetails.tn}`);

      // Check for suspicious UPI patterns
      if (upiDetails.am && parseFloat(upiDetails.am) > 10000) {
        score += 15;
        reasons.push('Large transaction amount detected — verify before proceeding');
      }
      confidence = 55;
      break;

    case 'email':
      reasons.push(`QR code contains an email link: ${content.substring(0, 100)}`);
      confidence = 45;
      break;

    case 'phone':
      reasons.push(`QR code contains a phone number: ${content.replace('tel:', '')}`);
      confidence = 45;
      break;

    case 'sms':
      reasons.push(`QR code triggers an SMS message`);
      score += 10;
      confidence = 50;
      break;

    case 'wifi':
      reasons.push('QR code contains WiFi network configuration');
      confidence = 45;
      break;

    case 'vcard':
      reasons.push('QR code contains a contact card (vCard)');
      confidence = 45;
      break;

    default:
      reasons.push(`QR code contains text: "${content.substring(0, 200)}${content.length > 200 ? '...' : ''}"`);
      confidence = 40;
  }

  return {
    score,
    confidence,
    indicators,
    reasons,
    recommendation: 'QR code decoded successfully. Review the content before taking any action.',
    contentType,
    decodedContent: content
  };
}

/**
 * Parse UPI URI parameters
 */
function parseUPI(upiString) {
  const params = {};
  try {
    const url = new URL(upiString);
    url.searchParams.forEach((value, key) => {
      params[key] = value;
    });
    // Also try to get the payee address from pathname
    if (!params.pa && url.pathname) {
      params.pa = url.pathname.replace(/^\/\//, '');
    }
  } catch (e) {
    // Fallback: manual parsing
    const parts = upiString.replace(/^upi:\/\//i, '').split('&');
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      if (key) params[key] = valueParts.join('=');
    }
  }
  return params;
}

module.exports = { decodeQR, analyzeQRContent, classifyContent };
