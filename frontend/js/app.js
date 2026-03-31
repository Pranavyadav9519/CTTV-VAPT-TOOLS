/* ===================================
  CCTV VAPT TOOL - Frontend JavaScript
  Modern Interactive UI (formatted)
  =================================== */

// DOM references
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
const optionsToggle = document.querySelector('.options-toggle');
const optionsContent = document.querySelector('.options-content');
const targetInput = document.getElementById('target-input');
const scanButton = document.querySelector('.btn-scan');
const formSection = document.querySelector('.form-section');
const navItems = document.querySelectorAll('.nav-item');
const parsePanel = document.getElementById('parse-panel');
const detectedTypeEl = document.getElementById('detected-type');
const normalizedTargetEl = document.getElementById('normalized-target');
const hostCountEl = document.getElementById('host-count');
const estimatedScopeEl = document.getElementById('estimated-scan-scope');
const estimatedDurationEl = document.getElementById('estimated-duration');
const recommendedModeEl = document.getElementById('recommended-scan-mode');
const safetyWarningEl = document.getElementById('safety-warning');
const allowManualCheckbox = document.getElementById('allow-manual-target');
const manualTargetContainer = document.getElementById('manual-target-container');
const discoveryResults = document.getElementById('discovery-results');
const resultsContainer = document.getElementById('results-container');
const resultsEmpty = document.getElementById('results-empty');
const resultsError = document.getElementById('results-error');
// Socket.IO client (receives live discovery events from backend)
let socket = null;
const discoveredIps = new Set();
if (window.io) {
  try {
    socket = io();
  } catch (e) {
    console.warn('Socket.IO client failed to initialize', e);
    socket = null;
  }

  if (socket) {
    socket.on('scan_progress', (data) => {
      try {
        if (data && data.phase === 'discovery') {
          const host = data.host || {};
          const ip = host.ip_address || host.ip || '';
          if (!ip) return; // nothing to show
          if (discoveredIps.has(ip)) return; // dedupe
          discoveredIps.add(ip);

          // Render only fields provided by backend — do not fabricate any values
          if (resultsContainer) {
            const item = document.createElement('div');
            item.className = 'info-box';
            const ipEl = document.createElement('div');
            ipEl.textContent = ip;
            ipEl.style.fontFamily = 'JetBrains Mono, monospace';
            ipEl.style.fontWeight = '700';
            item.appendChild(ipEl);

            if (host.services && Array.isArray(host.services) && host.services.length) {
              const svc = document.createElement('div');
              svc.textContent = `Open services: ${host.services.join(', ')}`;
              item.appendChild(svc);
            }

            if (host.fingerprint) {
              const fp = document.createElement('div');
              fp.textContent = `Fingerprint: ${host.fingerprint}`;
              item.appendChild(fp);
            }

            resultsContainer.appendChild(item);
            if (discoveryResults) discoveryResults.style.display = 'block';
          }
        }
      } catch (err) {
        console.error('Error handling scan_progress event:', err);
      }
    });

    socket.on('scan_complete', async (payload) => {
      try {
        showNotification('Discovery complete.', 'success');
        const scanId = payload && (payload.scan_id || payload.scanId || payload.data && payload.data.scan_id);
        if (!scanId) return;

        // Request devices for this scan and render them exactly as returned
        try {
          const resp = await fetch(`/api/scan/${scanId}/devices`);
          if (!resp.ok) {
            showDiscoveryError('Failed to fetch discovered devices.');
            return;
          }

          const body = await resp.json();
          const devices = (body && body.data && body.data.devices) || [];

          if (!devices.length) {
            showEmptyResults();
            return;
          }

          // Render devices (honest values only)
          clearResults();
          devices.forEach((d) => {
            const item = document.createElement('div');
            item.className = 'info-box';
            const ipEl = document.createElement('div');
            ipEl.textContent = d.ip_address || d.ip || '';
            ipEl.style.fontFamily = 'JetBrains Mono, monospace';
            ipEl.style.fontWeight = '700';
            item.appendChild(ipEl);

            if (Array.isArray(d.ports) && d.ports.length) {
              const svc = document.createElement('div');
              svc.textContent = 'Open services: ' + d.ports.map((p) => p.service_name || p.port_number).join(', ');
              item.appendChild(svc);
            }

            if (d.is_cctv) {
              const badge = document.createElement('div');
              badge.textContent = 'CCTV: yes';
              item.appendChild(badge);
            }

            resultsContainer.appendChild(item);
          });
          if (discoveryResults) discoveryResults.style.display = 'block';
        } catch (err) {
          console.error('Failed to get devices for scan:', err);
          showDiscoveryError('Failed to retrieve discovered devices.');
        }
      } catch (err) {
        console.error('Error handling scan_complete', err);
      }
    });

    socket.on('scan_error', (payload) => {
      const msg = (payload && payload.error) || 'Scan failed';
      showDiscoveryError(msg);
    });
  }
}

// TAB switching
tabBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    const tabName = btn.getAttribute('data-tab');

    // Reset active states
    tabBtns.forEach((b) => b.classList.remove('active'));
    tabPanes.forEach((p) => p.classList.remove('active'));

    // Activate clicked tab
    btn.classList.add('active');
    const pane = document.querySelector(`.tab-pane[data-tab="${tabName}"]`);
    if (pane) pane.classList.add('active');

    // Update description text
    updateScanInfo(tabName);
  });
});

function updateScanInfo(tabName) {
  const scanInfoText = document.querySelector('.scan-info-text');
  const infoTexts = {
    passive:
      '<strong>Passive Scan</strong> will analyze your network without sending disruptive traffic. Safe for production environments.',
    active:
      '<strong>Active Scan</strong> will perform detailed probing. May generate noticeable network traffic. Not recommended for critical production systems.',
    advanced:
      '<strong>Advanced / Authorized Scan</strong> performs penetration testing with authentication checks. Requires explicit written authorization.',
  };

  if (scanInfoText && infoTexts[tabName]) {
    scanInfoText.innerHTML = infoTexts[tabName];
  }
}

// Advanced options toggle
if (optionsToggle) {
  optionsToggle.addEventListener('click', () => {
    optionsToggle.classList.toggle('open');

    const icon = optionsToggle.querySelector('i');
    if (optionsContent.style.display === 'none') {
      optionsContent.style.display = 'block';
      if (icon) icon.style.transform = 'rotate(180deg)';
    } else {
      optionsContent.style.display = 'none';
      if (icon) icon.style.transform = 'rotate(0deg)';
    }
  });
}

// Scan button handler
scanButton?.addEventListener('click', (e) => {
  e.preventDefault();

  const activeTab = document.querySelector('.tab-btn.active');
  const scanType = activeTab?.getAttribute('data-tab') || 'passive';

  // Manual target path
  if (allowManualCheckbox?.checked) {
    const targetIP = targetInput?.value.trim();
    if (!targetIP) {
      showNotification('Please enter a target IP, range, or subnet', 'error');
      targetInput?.focus();
      return;
    }

    if (!isValidTarget(targetIP)) {
      showNotification('Invalid IP format. Please use: single IP, range, or subnet', 'error');
      return;
    }

    if (scanType !== 'passive') {
      const authorized = confirm(
        `You are about to start a ${scanType.toUpperCase()} scan on ${targetIP}.\n\nEnsure you have proper authorization before proceeding.\n\nDo you want to continue?`
      );
      if (!authorized) return;
    }

    triggerScan(targetIP, scanType);
    return;
  }

  // Discovery-only path (no fake/demo results)
  startDiscovery(scanType);
});

// Demo Mode button handler
const demoButton = document.getElementById('btn-demo-scan');
demoButton?.addEventListener('click', async (e) => {
  e.preventDefault();
  const originalText = demoButton.innerHTML;
  demoButton.disabled = true;
  demoButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Starting Demo...</span>';

  try {
    const response = await fetch('/api/scan/demo', { method: 'POST' });
    if (!response.ok) {
      showNotification('Failed to start demo scan. Please try again.', 'error');
      return;
    }
    const data = await response.json();
    showNotification('Demo scan started - simulating CCTV network discovery...', 'info');

    const scanId = data.data && data.data.scan_id;
    if (scanId && socket) {
      socket.once('scan_complete', () => {
        showNotification('Demo scan complete! Check Scan History for results.', 'success');
        // Auto-navigate to scan history
        const navItemsAll = document.querySelectorAll('.nav-item');
        navItemsAll.forEach((i) => i.classList.remove('active'));
        if (navItemsAll[1]) navItemsAll[1].classList.add('active');
        showView('scan_history');
        loadScans();
      });
    }
  } catch (err) {
    console.error('Demo scan error:', err);
    showNotification('Failed to start demo scan. Please try again.', 'error');
  } finally {
    demoButton.disabled = false;
    demoButton.innerHTML = originalText;
  }
});

// Trigger targeted scan (calls backend API)
async function triggerScan(targetIP, scanType) {
  const originalText = scanButton.innerHTML;
  scanButton.disabled = true;
  scanButton.innerHTML = '<i class="fas fa-spinner"></i> Starting Scan...';

  try {
    const response = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        network_range: targetIP, 
        scan_type: scanType,
        operator_name: 'web_user'
      }),
    });

    if (!response.ok) {
      showNotification(`Failed to start scan: ${response.status} ${response.statusText}`, 'error');
      return;
    }

    const data = await response.json();
    showNotification(`Scan started successfully. Scan ID: ${data.data?.scan_id}`, 'success');
    targetInput.value = '';
  } catch (error) {
    console.error('Scan error:', error);
    showNotification('Failed to start scan. Please try again.', 'error');
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = originalText;
  }
}

// Start discovery-only scan and render exact backend results or honest errors
async function startDiscovery(scanType) {
  const originalText = scanButton.innerHTML;
  scanButton.disabled = true;
  scanButton.innerHTML = '<i class="fas fa-spinner"></i> Discovering...';
  clearResults();

  try {
    const response = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        discovery: true, 
        scan_type: scanType,
        operator_name: 'web_user'
      }),
    });

    if (!response.ok) {
      showDiscoveryError('Local network discovery is not available in this environment.');
      return;
    }

    // Backend accepted the discovery request and started a scan.
    // Discovery results are emitted via server events while the scan runs.
    showNotification('Network discovery started. Results will appear when available.', 'success');
    return;
  } catch (err) {
    console.error('Discovery error:', err);
    showDiscoveryError('Local network discovery is not available in this environment.');
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = originalText;
  }
}

function clearResults() {
  if (resultsContainer) resultsContainer.innerHTML = '';
  if (resultsEmpty) resultsEmpty.style.display = 'none';
  if (resultsError) resultsError.style.display = 'none';
  if (discoveryResults) discoveryResults.style.display = 'none';
}

function showEmptyResults() {
  if (discoveryResults) discoveryResults.style.display = 'block';
  if (resultsEmpty) resultsEmpty.style.display = 'block';
}

function showDiscoveryError(message) {
  if (discoveryResults) discoveryResults.style.display = 'block';
  if (resultsError) {
    resultsError.style.display = 'block';
    resultsError.textContent = message;
  }
}

function renderResults(devices) {
  if (!discoveryResults || !resultsContainer) return;
  discoveryResults.style.display = 'block';
  resultsContainer.innerHTML = '';

  devices.forEach((d) => {
    // Only render fields returned by the backend. Do not fabricate.
    const item = document.createElement('div');
    item.className = 'info-box';
    const ip = document.createElement('div');
    ip.textContent = d.ip || '';
    ip.style.fontFamily = 'JetBrains Mono, monospace';
    ip.style.fontWeight = '700';
    item.appendChild(ip);

    if (d.services && Array.isArray(d.services) && d.services.length) {
      const svc = document.createElement('div');
      svc.textContent = `Open services: ${d.services.join(', ')}`;
      item.appendChild(svc);
    }

    if (d.fingerprint) {
      const fp = document.createElement('div');
      fp.textContent = `Fingerprint: ${d.fingerprint}`;
      item.appendChild(fp);
    }

    resultsContainer.appendChild(item);
  });
}

// Validation helpers
function isValidTarget(target) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?(-\d{1,3})?$/;
  if (ipRegex.test(target)) {
    const parts = target.split('/')[0].split('-')[0].split('.');
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }
  return false;
}

// Notifications
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.innerHTML =
    '<div class="notification-content">' +
    `<i class="fas fa-${getIconForType(type)}"></i>` +
    `<span>${message}</span>` +
    '</div>' +
    '<button class="notification-close" aria-label="Close">' +
    '<i class="fas fa-times"></i>' +
    '</button>';

  let container = document.querySelector('.notifications-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'notifications-container';
    document.body.appendChild(container);
    addNotificationStyles();
  }

  container.appendChild(notification);

  const closeBtn = notification.querySelector('.notification-close');
  closeBtn?.addEventListener('click', () => notification.remove());

  setTimeout(() => {
    if (notification.parentElement) notification.remove();
  }, 5000);
}

function getIconForType(type) {
  const icons = {
    success: 'check-circle',
    error: 'exclamation-circle',
    info: 'info-circle',
    warning: 'alert-triangle',
  };
  return icons[type] || 'info-circle';
}

function addNotificationStyles() {
  const style = document.createElement('style');
  style.innerHTML =
    '.notifications-container{position:fixed;top:90px;right:20px;z-index:1001;max-width:400px} ' +
    '.notification{background:var(--surface-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;box-shadow:var(--shadow-lg);animation:slideInRight 0.3s ease-out} ' +
    '.notification-content{display:flex;align-items:center;gap:12px;color:var(--text-primary);flex:1} ' +
    '.notification-close{background:transparent;border:none;color:var(--text-secondary);cursor:pointer;padding:4px;display:flex;align-items:center;justify-content:center;transition:all .15s;margin-left:12px} ' +
    '@keyframes slideInRight{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}';

  document.head.appendChild(style);
}

// Input formatting
targetInput?.addEventListener('input', (e) => {
  // Only parse when manual input is explicitly enabled
  if (!allowManualCheckbox?.checked) return;

  let value = e.target.value;
  // allow digits, dots, slash and dash only
  value = value.replace(/[^\d.\/\-]/g, '');
  e.target.value = value;

  // parse the input live and update panel
  const parsed = parseTarget(value.trim());
  if (parsed) {
    updateParsePanel(parsed);
  } else {
    hideParsePanel();
  }
});

// Toggle manual input visibility
if (allowManualCheckbox) {
  allowManualCheckbox.addEventListener('change', (e) => {
    const enabled = e.target.checked;
    if (manualTargetContainer) {
      manualTargetContainer.style.display = enabled ? 'block' : 'none';
      const input = manualTargetContainer.querySelector('#target-input');
      if (input) input.setAttribute('aria-hidden', enabled ? 'false' : 'true');
    }

    if (!enabled) {
      // Clear and hide parse panel when manual input disabled
      if (targetInput) targetInput.value = '';
      hideParsePanel();
    } else {
      targetInput?.focus();
    }
  });
}

// Show/hide parse panel helpers
function hideParsePanel() {
  if (parsePanel) {
    parsePanel.style.display = 'none';
    parsePanel.setAttribute('aria-hidden', 'true');
  }
}

function updateParsePanel(parsed) {
  if (!parsePanel) return;
  detectedTypeEl.textContent = parsed.type || '';
  normalizedTargetEl.textContent = parsed.normalized || '';
  hostCountEl.textContent = parsed.hostCount != null ? String(parsed.hostCount) : '';
  estimatedScopeEl.textContent = parsed.scope || '';
  estimatedDurationEl.textContent = parsed.duration || '';
  recommendedModeEl.textContent = parsed.recommended || '';

  if (parsed.safety && parsed.safety.length) {
    safetyWarningEl.style.display = 'block';
    safetyWarningEl.textContent = parsed.safety;
  } else {
    safetyWarningEl.style.display = 'none';
    safetyWarningEl.textContent = '';
  }

  parsePanel.style.display = 'block';
  parsePanel.setAttribute('aria-hidden', 'false');
}

// Parsing logic: returns null when invalid, otherwise an object with computed fields
function parseTarget(input) {
  if (!input) return null;

  // helpers
  function isIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every((p) => {
      if (!/^[0-9]+$/.test(p)) return false;
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }

  function ipToInt(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
  }

  function intToIp(int) {
    return [24, 16, 8, 0].map((shift) => (int >>> shift) & 0xff).join('.');
  }

  // CIDR
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(input)) {
    const [ip, prefixStr] = input.split('/');
    if (!isIPv4(ip)) return null;
    const prefix = Number(prefixStr);
    if (prefix < 0 || prefix > 32) return null;

    const ipInt = ipToInt(ip);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const networkInt = ipInt & mask;
    const hostBits = 32 - prefix;
    const hostCount = hostBits === 0 ? 1 : Math.max(1, 2 ** hostBits - (prefix <= 30 ? 2 : 0));

    const scope = computeScope(hostCount);
    const duration = formatDuration(estimateSeconds(hostCount));
    const recommended = recommendMode(hostCount);
    const safety = hostCount > 1024 ? `Large scan scope: ${hostCount} hosts — ensure authorization` : '';

    return {
      type: 'CIDR',
      normalized: `${intToIp(networkInt)}/${prefix}`,
      hostCount,
      scope,
      duration,
      recommended,
      safety,
    };
  }

  // Range forms: full start-end or shorthand last-octet range
  if (input.includes('-')) {
    const parts = input.split('-').map((s) => s.trim());
    if (parts.length !== 2) return null;
    const [a, b] = parts;

    // shorthand like 192.168.1.0-254
    if (a.split('.').length === 4 && /^[0-9]{1,3}$/.test(b)) {
      if (!isIPv4(a)) return null;
      const startInt = ipToInt(a);
      const baseParts = a.split('.');
      const startLast = Number(baseParts[3]);
      const endLast = Number(b);
      if (endLast < 0 || endLast > 255) return null;
      const endInt = (startInt & 0xffffff00) | endLast;
      if (endInt < startInt) return null;
      const hostCount = endInt - startInt + 1;
      const scope = computeScope(hostCount);
      const duration = formatDuration(estimateSeconds(hostCount));
      const recommended = recommendMode(hostCount);
      const safety = hostCount > 1024 ? `Large scan scope: ${hostCount} hosts — ensure authorization` : '';

      return {
        type: 'Range',
        normalized: `${intToIp(startInt)}-${intToIp(endInt)}`,
        hostCount,
        scope,
        duration,
        recommended,
        safety,
      };
    }

    // full range start-end
    if (a.split('.').length === 4 && b.split('.').length === 4) {
      if (!isIPv4(a) || !isIPv4(b)) return null;
      const startInt = ipToInt(a);
      const endInt = ipToInt(b);
      if (endInt < startInt) return null;
      const hostCount = endInt - startInt + 1;
      const scope = computeScope(hostCount);
      const duration = formatDuration(estimateSeconds(hostCount));
      const recommended = recommendMode(hostCount);
      const safety = hostCount > 1024 ? `Large scan scope: ${hostCount} hosts — ensure authorization` : '';

      return {
        type: 'Range',
        normalized: `${intToIp(startInt)}-${intToIp(endInt)}`,
        hostCount,
        scope,
        duration,
        recommended,
        safety,
      };
    }

    return null;
  }

  // Single IP
  if (isIPv4(input)) {
    return {
      type: 'Single IP',
      normalized: input,
      hostCount: 1,
      scope: computeScope(1),
      duration: formatDuration(estimateSeconds(1)),
      recommended: recommendMode(1),
      safety: '',
    };
  }

  return null;
}

function computeScope(hostCount) {
  if (hostCount <= 10) return 'Low';
  if (hostCount <= 256) return 'Medium';
  return 'High';
}

function estimateSeconds(hostCount) {
  // base seconds per host for default intensity
  const base = 2; // seconds per host
  return hostCount * base;
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  const mins = Math.round(seconds / 60);
  if (mins < 60) return `${mins} minutes`;
  const hours = (mins / 60).toFixed(1);
  return `${hours} hours`;
}

function recommendMode(hostCount) {
  if (hostCount <= 5) return 'Thorough';
  if (hostCount <= 100) return 'Normal';
  return 'Light';
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  if (e.altKey && e.key === 's') {
    e.preventDefault();
    if (!scanButton.disabled) scanButton.click();
  }

  if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
    const activeTabs = document.querySelectorAll('.tab-btn.active');
    if (activeTabs.length > 0 && e.target.closest?.('.scan-tabs')) {
      const direction = e.key === 'ArrowRight' ? 1 : -1;
      const currentIndex = Array.from(tabBtns).indexOf(activeTabs[0]);
      const nextIndex = (currentIndex + direction + tabBtns.length) % tabBtns.length;
      tabBtns[nextIndex].click();
    }
  }
});

// Recent scans interactions
document.querySelectorAll('.view-report-btn').forEach((btn) => {
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    const scanCard = btn.closest('.recent-scan-card');
    const ip = scanCard.querySelector('h3').textContent;
    showNotification(`Report will be generated for ${ip}`, 'info');
  });
});

// Navigation items
navItems.forEach((item, index) => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    navItems.forEach((i) => i.classList.remove('active'));
    item.classList.add('active');
    
    // Get the view to show based on nav item position
    const views = ['new_scan', 'scan_history', 'reports', 'analytics', 'settings'];
    if (index < views.length) {
      showView(views[index]);
      
      // Load data when switching views
      if (views[index] === 'scan_history') {
        loadScans();
      } else if (views[index] === 'reports') {
        loadReports();
      } else if (views[index] === 'analytics') {
        loadAnalytics();
      } else if (views[index] === 'settings') {
        loadSettings();
      }
    }
  });
});

// Show/Hide Views
function showView(viewName) {
  const viewPages = document.querySelectorAll('.view-page');
  viewPages.forEach(page => page.classList.remove('active'));
  
  const targetView = document.getElementById(`view-${viewName.replace(/_/g, '-')}`);
  if (targetView) {
    targetView.classList.add('active');
  }
  
  // Reset New Scan tab when showing new_scan view
  if (viewName === 'new_scan') {
    resetNewScanTab();
  }
}

// Reset New Scan tab to default state
function resetNewScanTab() {
  // Reset tab buttons
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => btn.classList.remove('active'));
  const passiveBtn = document.querySelector('.tab-btn[data-tab="passive"]');
  if (passiveBtn) passiveBtn.classList.add('active');
  
  // Reset tab panes
  const tabPanes = document.querySelectorAll('.tab-pane');
  tabPanes.forEach(pane => pane.classList.remove('active'));
  const passivePane = document.querySelector('.tab-pane[data-tab="passive"]');
  if (passivePane) passivePane.classList.add('active');
  
  // Reset scan info text
  const scanInfoText = document.querySelector('.scan-info-text');
  if (scanInfoText) {
    scanInfoText.innerHTML = '<strong>Passive Scan</strong> will analyze your network without sending disruptive traffic. Safe for production environments.';
  }
  
  // Reset manual target checkbox
  const allowManualCheckbox = document.getElementById('allow-manual-target');
  if (allowManualCheckbox) {
    allowManualCheckbox.checked = false;
  }
  
  // Hide manual target container
  const manualTargetContainer = document.getElementById('manual-target-container');
  if (manualTargetContainer) {
    manualTargetContainer.style.display = 'none';
  }
  
  // Clear target input
  const targetInput = document.getElementById('target-input');
  if (targetInput) {
    targetInput.value = '';
  }
  
  // Hide parse panel
  const parsePanel = document.getElementById('parse-panel');
  if (parsePanel) {
    parsePanel.style.display = 'none';
  }
  
  // Hide discovery results
  const discoveryResults = document.getElementById('discovery-results');
  if (discoveryResults) {
    discoveryResults.style.display = 'none';
  }
  
  // Reset advanced options
  const optionsContent = document.querySelector('.options-content');
  if (optionsContent) {
    optionsContent.style.display = 'none';
  }
  const optionsToggle = document.querySelector('.options-toggle');
  if (optionsToggle) {
    optionsToggle.classList.remove('open');
    const icon = optionsToggle.querySelector('i');
    if (icon) icon.style.transform = 'rotate(0deg)';
  }
}

// Load Scans from Backend
async function loadScans() {
  try {
    const response = await fetch('/api/scans');
    if (!response.ok) {
      showScansError('Failed to load scans');
      return;
    }
    
    const data = await response.json();
    const scans = (data.data && data.data.scans) || [];
    
    if (!scans.length) {
      showEmptyScans();
      return;
    }
    
    renderScansTable(scans);
  } catch (err) {
    console.error('Failed to load scans:', err);
    showScansError('Failed to load scan history');
  }
}

function renderScansTable(scans) {
  const container = document.getElementById('scans-table-container');
  if (!container) return;
  
  let html = `
    <table class="scans-table">
      <thead>
        <tr>
          <th>Scan ID</th>
          <th>Operator</th>
          <th>Network Range</th>
          <th>Status</th>
          <th>Hosts Found</th>
          <th>Vulnerabilities</th>
          <th>Started</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>
  `;
  
  scans.forEach(scan => {
    const status = scan.status || 'unknown';
    const statusClass = `status-${status}`;
    const startDate = new Date(scan.started_at).toLocaleDateString('en-US', { 
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
    
    let duration = 'N/A';
    if (scan.started_at && scan.completed_at) {
      const start = new Date(scan.started_at);
      const end = new Date(scan.completed_at);
      const seconds = Math.round((end - start) / 1000);
      duration = seconds < 60 ? `${seconds}s` : `${Math.round(seconds / 60)}m`;
    }
    
    html += `
      <tr>
        <td><strong>${scan.scan_id || 'N/A'}</strong></td>
        <td>${scan.operator_name || 'Unknown'}</td>
        <td>${scan.network_range || '-'}</td>
        <td><span class="status-badge ${statusClass}">${status}</span></td>
        <td>${scan.total_hosts_found || 0}</td>
        <td>${scan.vulnerabilities_found || 0}</td>
        <td>${startDate}</td>
        <td>${duration}</td>
      </tr>
    `;
  });
  
  html += `
      </tbody>
    </table>
  `;
  
  container.innerHTML = html;
}

function showEmptyScans() {
  const container = document.getElementById('scans-table-container');
  if (container) {
    container.innerHTML = '<div class="info-box"><p>No recent scans recorded.</p><p>Run a scan to populate recent scan results.</p></div>';
  }
}

function showScansError(message) {
  const container = document.getElementById('scans-table-container');
  if (container) {
    container.innerHTML = `<div class="alert alert-error"><p>${message}</p></div>`;
  }
}

// Load Reports from Backend
async function loadReports() {
  try {
    const response = await fetch('/api/reports');
    if (!response.ok) {
      showReportsError('Failed to load reports');
      return;
    }
    
    const data = await response.json();
    const reports = data.reports || data.data || [];
    
    if (!reports.length) {
      showEmptyReports();
      return;
    }
    
    renderReportsTable(reports);
  } catch (err) {
    console.error('Failed to load reports:', err);
    showReportsError('Failed to load reports');
  }
}

function renderReportsTable(reports) {
  const container = document.getElementById('reports-table-container');
  if (!container) return;
  
  let html = `
    <table class="scans-table">
      <thead>
        <tr>
          <th>Report ID</th>
          <th>Scan ID</th>
          <th>Report Type</th>
          <th>Generated</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
  `;
  
  reports.forEach(report => {
    const generatedDate = new Date(report.generated_at).toLocaleDateString('en-US', { 
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
    const reportType = report.type || 'General';
    
    html += `
      <tr>
        <td><strong>#${report.id}</strong></td>
        <td>${report.scan_id || '-'}</td>
        <td><span class="report-type-badge">${reportType}</span></td>
        <td>${generatedDate}</td>
        <td>
          <div class="download-options">
            <button class="btn-small" onclick="downloadReport(${report.id}, 'json')" title="Download as JSON">
              <i class="fas fa-file-code"></i> JSON
            </button>
            <button class="btn-small" onclick="downloadReport(${report.id}, 'html')" title="Download as HTML">
              <i class="fas fa-file-html5"></i> HTML
            </button>
          </div>
        </td>
      </tr>
    `;
  });
  
  html += `
      </tbody>
    </table>
  `;
  
  container.innerHTML = html;
}

function showEmptyReports() {
  const container = document.getElementById('reports-table-container');
  if (container) {
    container.innerHTML = '<div class="info-box"><p>No reports generated yet.</p><p>Complete a scan to generate reports.</p></div>';
  }
}

function showReportsError(message) {
  const container = document.getElementById('reports-table-container');
  if (container) {
    container.innerHTML = `<div class="alert alert-error"><p>${message}</p></div>`;
  }
}

function downloadReport(reportId, format = 'pdf') {
  try {
    // Create download link
    const downloadUrl = `/api/report/${reportId}/download?format=${format}`;
    
    // Create temporary anchor element
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `report_${reportId}.${format === 'json' ? 'json' : 'html'}`;
    
    // Trigger download
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showNotification(`Report #${reportId} downloading...`, 'success');
  } catch (err) {
    console.error('Download error:', err);
    showNotification('Failed to download report', 'error');
  }
}

// Load Analytics from Backend
async function loadAnalytics() {
  try {
    const response = await fetch('/api/analytics/summary');
    if (!response.ok) {
      showAnalyticsError('Failed to load analytics');
      return;
    }
    
    const data = await response.json();
    const analytics = data.data || data || {};
    
    renderAnalytics(analytics);
  } catch (err) {
    console.error('Failed to load analytics:', err);
    showAnalyticsError('Failed to load analytics');
  }
}

function renderAnalytics(analytics) {
  const stats = {
    'stat-total-scans': analytics.total_scans || 0,
    'stat-completed-scans': analytics.completed_scans || 0,
    'stat-cctv-devices': analytics.total_cctv_devices || 0,
    'stat-total-vulns': analytics.total_vulnerabilities || 0,
    'stat-critical-vulns': analytics.critical_vulnerabilities || 0,
    'stat-high-vulns': analytics.high_vulnerabilities || 0
  };
  
  Object.entries(stats).forEach(([elementId, value]) => {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = value;
    }
  });
}

function showAnalyticsError(message) {
  const container = document.getElementById('analytics-container');
  if (container) {
    container.innerHTML = `<div class="alert alert-error"><p>${message}</p></div>`;
  }
}

// Load and display Settings
async function loadSettings() {
  // Settings are mostly client-side preferences
  // Display last system check time
  const lastCheckElement = document.getElementById('last-system-check');
  if (lastCheckElement) {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    lastCheckElement.textContent = `${timeString}`;
  }
}

// Smooth scrolling for anchors
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// Page load animations placeholder (no functional change)

// End of file
