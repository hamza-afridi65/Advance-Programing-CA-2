let lastScanId = null;      // track latest scan
let allAlerts = [];         // all alerts for current view (latest scan or filters)
let currentPage = 1;        // current page index (1-based)
let rowsPerPage = 50;       // default rows per page

function showOverlay() {
  const overlay = document.getElementById("scan-overlay");
  if (overlay) overlay.classList.remove("hidden");
}

function hideOverlay() {
  const overlay = document.getElementById("scan-overlay");
  if (overlay) overlay.classList.add("hidden");
}

function setLastUpdated() {
  const el = document.getElementById("last-updated");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleString();
}

/**
 * Reset dashboard to the "no scans run yet" state.
 */
function resetDashboardInitial() {
  allAlerts = [];
  currentPage = 1;

  // Reset counters to 0
  const totalEl = document.getElementById("total-alerts");
  const highEl = document.getElementById("high-alerts");
  const medEl = document.getElementById("medium-alerts");
  const lowEl = document.getElementById("low-alerts");
  const countEl = document.getElementById("alert-count");

  if (totalEl) totalEl.textContent = "0";
  if (highEl) highEl.textContent = "0";
  if (medEl) medEl.textContent = "0";
  if (lowEl) lowEl.textContent = "0";
  if (countEl) countEl.textContent = "0";

  // Table placeholder
  const tableBody = document.querySelector("#alerts-table tbody");
  if (tableBody) {
    tableBody.innerHTML = "";
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.textContent = "No scans run yet. Click 'Scan Local Logs' or 'Scan AWS S3 Logs' to start.";
    row.appendChild(cell);
    tableBody.appendChild(row);
  }

  // Pagination info
  const infoEl = document.getElementById("pagination-info");
  if (infoEl) {
    infoEl.textContent = "No alerts – run a scan to see results.";
  }
}

async function callScan(endpoint) {
  const resultEl = document.getElementById("scan-result");
  resultEl.textContent = "Scanning logs...";
  showOverlay();
  try {
    const response = await fetch(endpoint, {
      method: "POST"
    });
    const data = await response.json();

    // remember which scan this was
    lastScanId = data.scanId || null;

    resultEl.textContent = `Scan complete. Alerts detected: ${data.alerts_detected}`;
    await loadAlerts();
  } catch (error) {
    console.error(error);
    resultEl.textContent = "Error while scanning logs.";
  } finally {
    hideOverlay();
  }
}

function buildAlertsUrl() {
  const severity = document.getElementById("severity-filter").value;
  const hours = document.getElementById("hours-filter").value;

  const params = new URLSearchParams();
  if (severity) params.append("severity", severity);
  if (hours) params.append("hours_back", hours);

  // restrict to last scan if we have an ID
  if (lastScanId) params.append("scan_id", lastScanId);

  const query = params.toString();
  return query ? "/api/alerts?" + query : "/api/alerts";
}

function animateCount(element, value) {
  const duration = 500;
  const startTime = performance.now();
  const startValue = 0;

  function frame(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const current = Math.round(startValue + (value - startValue) * progress);
    element.textContent = current;
    if (progress < 1) {
      requestAnimationFrame(frame);
    }
  }

  requestAnimationFrame(frame);
}

function updateSummaryCards(alerts) {
  const totalEl = document.getElementById("total-alerts");
  const highEl = document.getElementById("high-alerts");
  const medEl = document.getElementById("medium-alerts");
  const lowEl = document.getElementById("low-alerts");
  const countEl = document.getElementById("alert-count");

  let high = 0, medium = 0, low = 0;

  alerts.forEach(a => {
    if (a.severity === "Critical" || a.severity === "High") {
      high++;
    } else if (a.severity === "Medium") {
      medium++;
    } else if (a.severity === "Low") {
      low++;
    }
  });

  if (totalEl) animateCount(totalEl, alerts.length);
  if (highEl) animateCount(highEl, high);
  if (medEl) animateCount(medEl, medium);
  if (lowEl) animateCount(lowEl, low);

  if (countEl) countEl.textContent = alerts.length;
}

function showDetailsModal(alert) {
  const modal = document.getElementById("details-modal");
  const pre = document.getElementById("modal-json");
  const playbookEl = document.getElementById("modal-playbook");

  const pretty = JSON.stringify(alert.rawEvent || alert, null, 2);
  pre.textContent = pretty;

  // Playbook rendering (if present)
  if (playbookEl) {
    const pb = alert.playbook;
    if (pb) {
      const actions = (pb.actions || []).map((a, idx) => `${idx + 1}. ${a}`).join("\n");
      playbookEl.textContent = `${pb.title}\nRisk: ${pb.risk}\n\nRecommended Actions:\n${actions}`;
      playbookEl.classList.remove("hidden");
    } else {
      playbookEl.textContent = "";
      playbookEl.classList.add("hidden");
    }
  }

  modal.classList.remove("hidden");
}


function createSeverityBadgeCell(severity) {
  const cell = document.createElement("td");
  const badge = document.createElement("span");
  const s = (severity || "").toLowerCase();

  badge.textContent = severity || "";
  badge.classList.add("severity-badge");

  if (s === "critical") {
    badge.classList.add("severity-critical");
  } else if (s === "high") {
    badge.classList.add("severity-high");
  } else if (s === "medium") {
    badge.classList.add("severity-medium");
  } else if (s === "low") {
    badge.classList.add("severity-low");
  }

  cell.appendChild(badge);
  return cell;
}

/**
 * Render the current page of alerts into the table.
 */
function renderAlertsTable() {
  const tableBody = document.querySelector("#alerts-table tbody");
  tableBody.innerHTML = "";

  const total = allAlerts.length;

  if (!total) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.textContent = "No alerts found.";
    row.appendChild(cell);
    tableBody.appendChild(row);

    updatePaginationControls();
    return;
  }

  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));
  if (currentPage > totalPages) currentPage = totalPages;

  const startIndex = (currentPage - 1) * rowsPerPage;
  const endIndex = Math.min(startIndex + rowsPerPage, total);
  const pageAlerts = allAlerts.slice(startIndex, endIndex);

  pageAlerts.forEach(alert => {
    const row = document.createElement("tr");

    // Rule
    const ruleCell = document.createElement("td");
    ruleCell.textContent = alert.rule || "";
    row.appendChild(ruleCell);

    // Severity
    const severityCell = createSeverityBadgeCell(alert.severity);
    row.appendChild(severityCell);

    // User
    const userCell = document.createElement("td");
    userCell.textContent = alert.user || "";
    row.appendChild(userCell);

    // Source IP (styled like a link for SOC feel)
    const ipCell = document.createElement("td");
    const ipSpan = document.createElement("span");
    ipSpan.textContent = alert.sourceIP || "";
    ipSpan.className = "clickable-text";
    ipCell.appendChild(ipSpan);
    row.appendChild(ipCell);

    // Event
    const eventCell = document.createElement("td");
    eventCell.textContent = alert.eventName || "";
    row.appendChild(eventCell);

    // Region
    const regionCell = document.createElement("td");
    regionCell.textContent = alert.awsRegion || "";
    row.appendChild(regionCell);

    // Time
    const timeCell = document.createElement("td");
    timeCell.textContent = alert.eventTime || "";
    row.appendChild(timeCell);

    // Details button
    const detailsCell = document.createElement("td");
    const btn = document.createElement("button");
    btn.textContent = "Details";
    btn.className = "details-btn";
    btn.addEventListener("click", () => showDetailsModal(alert));
    detailsCell.appendChild(btn);
    row.appendChild(detailsCell);

    tableBody.appendChild(row);
  });

  updatePaginationControls(startIndex, endIndex, total, totalPages);
}

/**
 * Update pagination controls UI.
 */
function updatePaginationControls(startIndex = 0, endIndex = 0, total = 0, totalPages = 1) {
  const prevBtn = document.getElementById("page-prev");
  const nextBtn = document.getElementById("page-next");
  const pagesContainer = document.getElementById("pagination-pages");
  const infoEl = document.getElementById("pagination-info");

  if (!prevBtn || !nextBtn || !pagesContainer || !infoEl) return;

  const hasData = total > 0;
  prevBtn.disabled = !hasData || currentPage <= 1;
  nextBtn.disabled = !hasData || currentPage >= totalPages;

  pagesContainer.innerHTML = "";

  if (hasData) {
    // Simple page numbers: show up to 7 pages centered around current
    const maxVisible = 7;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    let endPage = startPage + maxVisible - 1;
    if (endPage > totalPages) {
      endPage = totalPages;
      startPage = Math.max(1, endPage - maxVisible + 1);
    }

    for (let p = startPage; p <= endPage; p++) {
      const btn = document.createElement("button");
      btn.textContent = p;
      btn.className = "page-number";
      if (p === currentPage) {
        btn.classList.add("active");
      }
      btn.addEventListener("click", () => {
        currentPage = p;
        renderAlertsTable();
      });
      pagesContainer.appendChild(btn);
    }

    const from = startIndex + 1;
    const to = endIndex;
    infoEl.textContent = `Showing ${from}–${to} of ${total}`;
  } else {
    infoEl.textContent = "No alerts to display.";
  }
}

/**
 * Fetch alerts from backend, then update summary + render table.
 * If no scan has run yet, we do nothing (keep the "no scan" state).
 */
async function loadAlerts() {
  // If no scan has been run in this browser session, do not fetch historic data
  if (!lastScanId) {
    resetDashboardInitial();
    return;
  }

  try {
    const url = buildAlertsUrl();
    const response = await fetch(url);
    const alerts = await response.json();

    allAlerts = alerts;
    currentPage = 1;

    updateSummaryCards(allAlerts);
    setLastUpdated();
    renderAlertsTable();
  } catch (error) {
    console.error(error);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("scan-local-btn").addEventListener("click", () => {
    callScan("/api/scan");
  });

  document.getElementById("scan-s3-btn").addEventListener("click", () => {
    callScan("/api/scan_s3");
  });

  document.getElementById("apply-filters-btn").addEventListener("click", loadAlerts);

  const resetBtn = document.getElementById("reset-filters-btn");
  resetBtn.addEventListener("click", () => {
    document.getElementById("severity-filter").value = "";
    document.getElementById("hours-filter").value = "";
    loadAlerts();
  });

  const modal = document.getElementById("details-modal");
  const closeBtn = document.getElementById("modal-close");
  closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      modal.classList.add("hidden");
    }
  });

  // Pagination controls
  const rowsSelect = document.getElementById("rows-per-page");
  const prevBtn = document.getElementById("page-prev");
  const nextBtn = document.getElementById("page-next");

  if (rowsSelect) {
    rowsSelect.addEventListener("change", (e) => {
      const value = parseInt(e.target.value, 10);
      rowsPerPage = isNaN(value) ? 50 : value;
      currentPage = 1;
      renderAlertsTable();
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        renderAlertsTable();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      const total = allAlerts.length;
      const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));
      if (currentPage < totalPages) {
        currentPage++;
        renderAlertsTable();
      }
    });
  }

  // Initial state: no scans run yet -> everything zero, nice message
  resetDashboardInitial();
  // Important: DO NOT call loadAlerts() here, to avoid loading historic DB data
});
