/**
 * ByteShield Frontend — History & Dashboard Module
 * Loads and displays scan history and dashboard statistics
 */

const History = (() => {
  /**
   * Load dashboard statistics
   */
  async function loadDashboard() {
    try {
      const res = await fetch('/api/dashboard');
      if (!res.ok) {
        if (res.status === 401) {
          window.location.href = '/';
          return;
        }
        throw new Error('Failed to load dashboard.');
      }
      const data = await res.json();

      // Update stats
      document.getElementById('totalScans').textContent = data.stats.totalScans;
      document.getElementById('highRisk').textContent = data.stats.highRisk;
      document.getElementById('mediumRisk').textContent = data.stats.mediumRisk;
      document.getElementById('lowRisk').textContent = data.stats.lowRisk;

      // Update distribution
      document.getElementById('distMessage').textContent = data.distribution.message;
      document.getElementById('distUrl').textContent = data.distribution.url;
      document.getElementById('distScreenshot').textContent = data.distribution.screenshot;
      document.getElementById('distQr').textContent = data.distribution.qr;

      // Render recent scans
      renderRecentScans(data.recentScans);
    } catch (err) {
      console.error('Dashboard load error:', err);
    }
  }

  /**
   * Load full scan history
   */
  async function loadHistory() {
    try {
      const res = await fetch('/api/history');
      if (!res.ok) {
        if (res.status === 401) {
          window.location.href = '/';
          return;
        }
        throw new Error('Failed to load history.');
      }
      const data = await res.json();
      renderHistory(data.scans);
    } catch (err) {
      console.error('History load error:', err);
    }
  }

  /**
   * Render recent scans table
   */
  function renderRecentScans(scans) {
    const container = document.getElementById('recentScansContent');
    if (!scans || scans.length === 0) {
      container.innerHTML = '<p class="history-empty">No scans yet. Start scanning to see results here.</p>';
      return;
    }

    const table = createScansTable(scans);
    container.innerHTML = '';
    container.appendChild(table);
  }

  /**
   * Render full history
   */
  function renderHistory(scans) {
    const container = document.getElementById('historyContent');
    if (!scans || scans.length === 0) {
      container.innerHTML = '<p class="history-empty">No scan history found.</p>';
      return;
    }

    const table = createScansTable(scans);
    container.innerHTML = '';
    container.appendChild(table);
  }

  /**
   * Create a scans table element
   */
  function createScansTable(scans) {
    const table = document.createElement('table');
    table.className = 'history-table';

    table.innerHTML = `
      <thead>
        <tr>
          <th>Type</th>
          <th>Input</th>
          <th>Risk</th>
          <th>Score</th>
          <th>Confidence</th>
          <th>Date</th>
        </tr>
      </thead>
    `;

    const tbody = document.createElement('tbody');

    scans.forEach(scan => {
      const tr = document.createElement('tr');

      const typeIcons = { message: '💬', url: '🔗', screenshot: '📸', qr: '📱' };
      const typeIcon = typeIcons[scan.scan_type] || '📋';

      const riskClass = (scan.risk_level || '').toLowerCase();

      // Format input summary
      let inputSummary = scan.input_summary || '—';
      if (inputSummary.length > 60) {
        inputSummary = inputSummary.substring(0, 60) + '...';
      }

      // Format date
      const date = scan.created_at ? formatDate(scan.created_at) : '—';

      tr.innerHTML = `
        <td>${typeIcon} ${capitalize(scan.scan_type)}</td>
        <td title="${escapeHtml(scan.input_summary || '')}">${escapeHtml(inputSummary)}</td>
        <td><span class="risk-badge risk-${riskClass}">${scan.risk_level || '—'}</span></td>
        <td>${scan.risk_score !== null ? scan.risk_score + '/100' : '—'}</td>
        <td>${scan.confidence !== null ? Math.round(scan.confidence) + '%' : '—'}</td>
        <td>${date}</td>
      `;

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    return table;
  }

  /**
   * Format ISO date string
   */
  function formatDate(dateStr) {
    try {
      const d = new Date(dateStr + 'Z'); // Assume UTC from SQLite
      return d.toLocaleDateString('en-IN', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return dateStr;
    }
  }

  /**
   * Capitalize first letter
   */
  function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /**
   * Escape HTML to prevent XSS
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  return { loadDashboard, loadHistory };
})();
