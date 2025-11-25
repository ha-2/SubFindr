/**
 * SubFindr - Open Source Subdomain Enumeration Tool
 * Author: ha-2
 * GitHub: https://github.com/ha-2
 * License: CC BY-NC 4.0
 */

// At the top of app.js
let lastScanResult = null; // will hold the JSON returned from /scan
let scanInProgress = false;

function setScanStatus(message, percent = null) {
  const statusEl = document.getElementById('scanStatus');
  const barContainer = document.getElementById('progressContainer');
  const bar = document.getElementById('progressBar');

  if (!statusEl || !barContainer || !bar) return;

  if (message) {
    statusEl.textContent = message;
    statusEl.classList.remove('hidden');
    barContainer.classList.remove('hidden');
  } else {
    statusEl.classList.add('hidden');
    barContainer.classList.add('hidden');
  }

  if (percent !== null) {
    const clamped = Math.max(0, Math.min(100, percent));
    bar.style.width = clamped + '%';
  }
}

// Helper function to format datetime
function formatDateTime(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  return d.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
}

// Helper function to get selected scan mode
function getSelectedMode() {
  const radios = document.getElementsByName('scanMode');
  for (const r of radios) {
    if (r.checked) return r.value;
  }
  return 'basic';
}

// Helper function to update the summary counts
function updateSummary(data) {
  const summaryDiv = document.getElementById('summary');
  const totalSpan = document.getElementById('totalCount');
  const aliveSpan = document.getElementById('aliveCount');
  const deadSpan = document.getElementById('deadCount');

  if (!summaryDiv || !totalSpan || !aliveSpan || !deadSpan) return;

  let total = data.total_subdomains;
  let alive = data.alive_count;
  let dead = data.dead_count;

  // Fallback: compute manually if backend fields are missing
  if ((!Number.isInteger(total) || !Number.isInteger(alive) || !Number.isInteger(dead)) &&
      Array.isArray(data.subdomains)) {
    total = data.subdomains.length;
    alive = data.subdomains.filter(s => s.is_alive).length;
    dead = total - alive;
  }

  totalSpan.textContent = `Total: ${total}`;
  aliveSpan.textContent = `Alive: ${alive}`;
  deadSpan.textContent = `Not alive: ${dead}`;

  summaryDiv.classList.remove('hidden');
}

async function scanDomain() {
    const domainInput = document.getElementById('domain');
    const domain = domainInput.value.trim();
    
    if (!domain) {
        showError('Please enter a domain');
        return;
    }
    
    // Get selected mode
    const mode = getSelectedMode();
    
    // Show loading indicator
    scanInProgress = true;
    setScanStatus('Starting scan...', 10);
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
    
    setScanStatus('Contacting server and enumerating sources...', 35);
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ domain: domain, mode: mode })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        setScanStatus('Processing results and checking alive status...', 75);
        
        // Hide loading indicator
        document.getElementById('loading').classList.add('hidden');
        
        // Display results
        displayResults(data.subdomains);
        
        // Save the scan result for PDF generation
        lastScanResult = data; // save the results for PDF generation
        
        // Update summary counts
        updateSummary(data);
        
        // Enable the Download button
        const downloadBtn = document.getElementById('downloadBtn');
        if (downloadBtn) {
          downloadBtn.disabled = false;
          downloadBtn.classList.remove('cursor-not-allowed', 'opacity-60');
        }
        
        scanInProgress = false;
        setScanStatus('Scan complete.', 100);
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('loading').classList.add('hidden');
        scanInProgress = false;
        setScanStatus('Scan failed. Please try again.', 0);
        showError('Unable to scan. Please try again.');
    }
}

function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
}

function displayResults(subdomains) {
    const resultsDiv = document.getElementById('results');
    const tableBody = document.getElementById('resultsTable');
    
    // Clear previous results
    tableBody.innerHTML = '';
    
    if (subdomains.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" class="py-3 px-6 text-center">No subdomains found</td></tr>';
        resultsDiv.classList.remove('hidden');
        return;
    }
    
    // Sort subdomains: alive first, then alphabetical
    subdomains.sort((a, b) => {
        // If one is alive and the other isn't, alive comes first
        if (a.is_alive && !b.is_alive) return -1;
        if (!a.is_alive && b.is_alive) return 1;
        
        // If both are alive or both are not alive, sort alphabetically
        return a.host.localeCompare(b.host);
    });
    
    // Add rows to table
    subdomains.forEach(subdomain => {
        const row = document.createElement('tr');
        row.className = 'border-b border-gray-200 hover:bg-gray-100';
        
        const hostCell = document.createElement('td');
        hostCell.className = 'py-3 px-6 text-left whitespace-nowrap';
        hostCell.textContent = subdomain.host;
        
        const ipCell = document.createElement('td');
        ipCell.className = 'py-3 px-6 text-left';
        ipCell.textContent = subdomain.ip || 'N/A';
        
        const aliveCell = document.createElement('td');
        aliveCell.className = 'py-3 px-6 text-left';
        aliveCell.textContent = subdomain.is_alive ? 'Yes' : 'No';
        aliveCell.className += subdomain.is_alive ? ' text-green-600' : ' text-red-600';
        
        const statusCell = document.createElement('td');
        statusCell.className = 'py-3 px-6 text-left';
        statusCell.textContent = subdomain.http_status || 'N/A';
        
        const sourcesCell = document.createElement('td');
        sourcesCell.className = 'py-3 px-6 text-left';
        sourcesCell.textContent = subdomain.sources.join(', ');
        
        row.appendChild(hostCell);
        row.appendChild(ipCell);
        row.appendChild(aliveCell);
        row.appendChild(statusCell);
        row.appendChild(sourcesCell);
        
        tableBody.appendChild(row);
    });
    
    // Show results
    resultsDiv.classList.remove('hidden');
}

async function downloadReport() {
  console.log('Download PDF button clicked');

  if (!lastScanResult) {
    alert('Run a scan first before downloading a report.');
    return;
  }

  const subs = Array.isArray(lastScanResult.subdomains)
    ? lastScanResult.subdomains
    : [];

  if (!subs.length) {
    alert('No subdomains available.');
    return;
  }

  // Check if jsPDF is loaded correctly from CDN
  if (typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined') {
    console.error('jsPDF library not loaded correctly:', window.jspdf);
    alert('PDF library not loaded. Please refresh the page and try again.');
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const domain = lastScanResult.domain || 'unknown domain';
  const startedAt = lastScanResult.started_at ? formatDateTime(lastScanResult.started_at) : "";
  const finishedAt = lastScanResult.finished_at ? formatDateTime(lastScanResult.finished_at) : "";

  let total = Number.isInteger(lastScanResult.total_subdomains)
    ? lastScanResult.total_subdomains
    : subs.length;

  let alive = Number.isInteger(lastScanResult.alive_count)
    ? lastScanResult.alive_count
    : subs.filter(s => s && s.is_alive).length;

  let dead = Number.isInteger(lastScanResult.dead_count)
    ? lastScanResult.dead_count
    : (total - alive);

  // Watermark
  doc.saveGraphicsState();
  doc.setFontSize(50);
  doc.setTextColor(230, 230, 230);
  doc.text('SubFindr', 105, 150, { angle: -45, align: 'center' });
  doc.restoreGraphicsState();

  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('SubFindr – Subdomain Scan Report', 14, 20);

  doc.setFontSize(11);
  doc.text(`Domain: ${domain}`, 14, 30);
  if (startedAt) doc.text(`Started: ${startedAt}`, 14, 36);
  if (finishedAt) doc.text(`Finished: ${finishedAt}`, 14, 42);
  doc.text(`Total subdomains: ${total}`, 14, 48);
  doc.text(`Alive: ${alive}   Not alive: ${dead}`, 14, 54);

  const body = subs.map((s) => ([
    s.host || '',
    s.ip || 'N/A',
    s.is_alive ? 'Yes' : 'No',
    (s.http_status !== null && s.http_status !== undefined) ? String(s.http_status) : 'N/A',
    Array.isArray(s.sources) ? s.sources.join(', ') : ''
  ]));

  // Check if autoTable is available
  if (typeof doc.autoTable === 'undefined') {
    console.error('jsPDF AutoTable plugin not loaded correctly');
    alert('PDF table plugin not loaded. Please refresh the page and try again.');
    return;
  }

  doc.autoTable({
    head: [['Subdomain', 'IP', 'Alive', 'Status', 'Sources']],
    body,
    startY: 62,
    styles: { fontSize: 9 },
    headStyles: { fillColor: [0, 0, 0] },
    columnStyles: {
      0: { cellWidth: 60 },
      1: { cellWidth: 35 },
      2: { cellWidth: 15 },
      3: { cellWidth: 20 },
      4: { cellWidth: 60 }
    }
  });

  const pageHeight = doc.internal.pageSize.getHeight();
  doc.setFontSize(8);
  doc.text('Generated by SubFindr', 14, pageHeight - 10);
  doc.text('Creator: https://github.com/ha-2', 14, pageHeight - 5);

  doc.save(`SubFindr-${domain}.pdf`);
}

document.addEventListener('DOMContentLoaded', () => {
  const downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) {
    // disabled by default: actual attribute set in HTML
    downloadBtn.addEventListener('click', downloadReport);
  }
  
  // Set initial status
  setScanStatus('Ready.', 0);

  // If you already attach events for the Scan button here,
  // keep that code and do not remove it.
});