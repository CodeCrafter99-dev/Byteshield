/**
 * ByteShield Frontend — Scanner Module
 * Handles scan requests and result display
 * (Scan API calls will be added in Phase 5+)
 */

const Scanner = (() => {
  /**
   * Initialize scanner tabs
   */
  function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        // Remove active from all
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));

        // Activate clicked tab
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-tab') + 'Tab';
        document.getElementById(tabId).classList.add('active');

        // Hide results when switching tabs
        hideResults();
      });
    });
  }

  /**
   * Initialize file upload areas (drag & drop + click)
   */
  function initFileUploads() {
    // Screenshot upload
    setupFileUpload('screenshotUploadArea', 'screenshotInput', 'screenshotPreview', 'screenshotPreviewImg', 'removeScreenshot');
    // QR upload
    setupFileUpload('qrUploadArea', 'qrInput', 'qrPreview', 'qrPreviewImg', 'removeQr');
  }

  function setupFileUpload(areaId, inputId, previewId, previewImgId, removeBtnId) {
    const area = document.getElementById(areaId);
    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);
    const previewImg = document.getElementById(previewImgId);
    const removeBtn = document.getElementById(removeBtnId);

    if (!area || !input) return;

    // Click to upload
    area.addEventListener('click', () => input.click());

    // Drag & drop
    area.addEventListener('dragover', (e) => {
      e.preventDefault();
      area.classList.add('drag-over');
    });

    area.addEventListener('dragleave', () => {
      area.classList.remove('drag-over');
    });

    area.addEventListener('drop', (e) => {
      e.preventDefault();
      area.classList.remove('drag-over');
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showFilePreview(input, area, preview, previewImg);
      }
    });

    // File selected
    input.addEventListener('change', () => {
      showFilePreview(input, area, preview, previewImg);
    });

    // Remove file
    if (removeBtn) {
      removeBtn.addEventListener('click', () => {
        input.value = '';
        preview.classList.add('hidden');
        area.classList.remove('hidden');
      });
    }
  }

  function showFilePreview(input, area, preview, previewImg) {
    if (input.files && input.files[0]) {
      const reader = new FileReader();
      reader.onload = (e) => {
        previewImg.src = e.target.result;
        preview.classList.remove('hidden');
        area.classList.add('hidden');
      };
      reader.readAsDataURL(input.files[0]);
    }
  }

  /**
   * Display scan results
   */
  function showResults(result) {
    const resultsArea = document.getElementById('resultsArea');
    const riskBadge = document.getElementById('riskBadge');
    const riskScore = document.getElementById('riskScore');
    const confidence = document.getElementById('confidence');
    const analysisSource = document.getElementById('analysisSource');
    const reasonsList = document.getElementById('reasonsList');
    const recommendation = document.getElementById('recommendation');
    const resultCard = document.getElementById('resultCard');

    // Set risk badge
    riskBadge.textContent = (result.riskLevel || '—') + ' RISK';
    riskBadge.className = 'risk-badge risk-' + (result.riskLevel || 'unknown').toLowerCase();

    // Set metrics
    riskScore.textContent = result.riskScore !== undefined ? result.riskScore + '/100' : '—';
    confidence.textContent = result.confidence !== undefined ? Math.round(result.confidence) + '%' : '—';

    // Highlight if analysis ran via AI or fell back
    const isFallback = (result.analysisSource || '').toLowerCase().includes('fallback');
    if (isFallback) {
      analysisSource.innerHTML = `<span style="color: #f59e0b; font-weight: 700;">⚠️ ${escapeHtml(result.analysisSource)}</span>`;
    } else {
      analysisSource.textContent = result.analysisSource || '—';
    }

    // Update risk meter bar
    const riskMeterFill = document.getElementById('riskMeterFill');
    if (riskMeterFill) {
      const score = Math.max(0, Math.min(100, result.riskScore || 0));
      riskMeterFill.style.width = score + '%';
      const levelClass = (result.riskLevel || 'low').toLowerCase();
      riskMeterFill.className = 'risk-meter-fill fill-' + levelClass;
    }

    // Set reasons
    reasonsList.innerHTML = '';
    const reasons = result.reasons || [];
    if (reasons.length === 0) {
      reasonsList.innerHTML = '<li class="reason-item clean"><span class="item-icon">✅</span> <span>No specific threat indicators detected.</span></li>';
    } else {
      reasons.forEach(reason => {
        const li = document.createElement('li');
        li.className = 'reason-item';
        const isHigh = (result.riskLevel === 'HIGH');
        const icon = isHigh ? '🚨' : (result.riskLevel === 'MEDIUM' ? '⚠️' : '🔍');
        li.innerHTML = `<span class="item-icon">${icon}</span> <span>${escapeHtml(reason)}</span>`;
        reasonsList.appendChild(li);
      });
    }

    // Set recommendation
    recommendation.textContent = result.recommendation || 'No specific recommendation.';

    // Set risk-level class on card
    resultCard.className = 'result-card risk-card-' + (result.riskLevel || 'unknown').toLowerCase();

    // Show results
    resultsArea.classList.remove('hidden');
    resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Hide results area
   */
  function hideResults() {
    const resultsArea = document.getElementById('resultsArea');
    if (resultsArea) resultsArea.classList.add('hidden');
  }

  /**
   * Set button loading state
   */
  function setButtonLoading(btn, loading) {
    const text = btn.querySelector('.btn-text');
    const loadingEl = btn.querySelector('.btn-loading');
    if (loading) {
      btn.disabled = true;
      if (text) text.classList.add('hidden');
      if (loadingEl) loadingEl.classList.remove('hidden');
    } else {
      btn.disabled = false;
      if (text) text.classList.remove('hidden');
      if (loadingEl) loadingEl.classList.add('hidden');
    }
  }

  /**
   * Scan message
   */
  async function scanMessage() {
    const input = document.getElementById('messageInput');
    const btn = document.getElementById('scanMessageBtn');
    const message = input.value.trim();

    if (!message) {
      alert('Please enter a message to analyze.');
      return;
    }

    setButtonLoading(btn, true);
    try {
      const res = await fetch('/api/scan/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed.');
      showResults(data);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  /**
   * Scan URL
   */
  async function scanUrl() {
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('scanUrlBtn');
    const url = input.value.trim();

    if (!url) {
      alert('Please enter a URL to analyze.');
      return;
    }

    setButtonLoading(btn, true);
    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed.');
      showResults(data);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  /**
   * Scan screenshot
   */
  async function scanScreenshot() {
    const input = document.getElementById('screenshotInput');
    const btn = document.getElementById('scanScreenshotBtn');

    if (!input.files || !input.files[0]) {
      alert('Please upload a screenshot to analyze.');
      return;
    }

    const formData = new FormData();
    formData.append('screenshot', input.files[0]);

    setButtonLoading(btn, true);
    try {
      const res = await fetch('/api/scan/screenshot', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed.');
      showResults(data);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  /**
   * Scan QR Code
   */
  async function scanQr() {
    const input = document.getElementById('qrInput');
    const btn = document.getElementById('scanQrBtn');

    if (!input.files || !input.files[0]) {
      alert('Please upload a QR code image to analyze.');
      return;
    }

    const formData = new FormData();
    formData.append('qrcode', input.files[0]);

    setButtonLoading(btn, true);
    try {
      const res = await fetch('/api/scan/qr', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed.');
      showResults(data);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  /**
   * Initialize scan button listeners
   */
  function initScanButtons() {
    document.getElementById('scanMessageBtn')?.addEventListener('click', scanMessage);
    document.getElementById('scanUrlBtn')?.addEventListener('click', scanUrl);
    document.getElementById('scanScreenshotBtn')?.addEventListener('click', scanScreenshot);
    document.getElementById('scanQrBtn')?.addEventListener('click', scanQr);
  }

  return { initTabs, initFileUploads, initScanButtons, showResults, hideResults };
})();
