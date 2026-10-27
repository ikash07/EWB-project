/**
 * Phishing URL Awareness Checker - Client Logic
 * Mirrors the Python phishing_checker.py inspection logic exactly.
 * Operates purely offline via local string analysis.
 */

// Constants matching Python script
const INFO_PREFIXES = [
  "No URL entered",
  "Could not identify",
  "No listed warning",
  "This text is not a valid"
];

// DOM Elements
const urlInput = document.getElementById("urlInput");
const inspectBtn = document.getElementById("inspectBtn");
const btnText = document.getElementById("btnText");
const btnIcon = document.getElementById("btnIcon");
const btnSpinner = document.getElementById("btnSpinner");
const laserBeam = document.getElementById("laserBeam");
const clearBtn = document.getElementById("clearBtn");
const presetButtons = document.querySelectorAll(".preset-btn");

const resultSection = document.getElementById("resultSection");
const statusBanner = document.getElementById("statusBanner");
const bannerIcon = document.getElementById("bannerIcon");
const bannerTitle = document.getElementById("bannerTitle");
const bannerMessage = document.getElementById("bannerMessage");
const warningBadge = document.getElementById("warningBadge");

const partScheme = document.getElementById("partScheme");
const partHost = document.getElementById("partHost");
const partSubdomains = document.getElementById("partSubdomains");
const partPath = document.getElementById("partPath");
const partLength = document.getElementById("partLength");

const findingsList = document.getElementById("findingsList");
const termOutput = document.getElementById("termOutput");
const termActiveInput = document.getElementById("termActiveInput");
const terminalBody = document.getElementById("terminalBody");

// Checks DOM nodes
const checkAt = document.getElementById("check-at");
const checkLength = document.getElementById("check-length");
const checkIp = document.getElementById("check-ip");
const checkSubdomains = document.getElementById("check-subdomains");
const checkPunycode = document.getElementById("check-punycode");
const checkHttp = document.getElementById("check-http");

/**
 * Core URL Inspection Logic (Equivalent to inspect_url in Python)
 */
function inspectUrl(rawUrl) {
  const url = (rawUrl || "").trim();
  const findings = [];
  const checkResults = {
    hasAt: false,
    isLong: false,
    isIp: false,
    manySegments: false,
    isPunycode: false,
    isHttp: false,
    malformed: false
  };

  if (!url) {
    return {
      findings: ["No URL entered."],
      anatomy: null,
      checkResults,
      hasWarnings: false,
      isEmpty: true
    };
  }

  const candidate = url.includes("://") ? url : "http://" + url;
  let parsed;

  try {
    parsed = new URL(candidate);
  } catch (err) {
    checkResults.malformed = true;
    return {
      findings: ["This text is not a valid URL format."],
      anatomy: null,
      checkResults,
      hasWarnings: false,
      isMalformed: true
    };
  }

  const host = (parsed.hostname || "").toLowerCase();

  if (!host) {
    return {
      findings: ["Could not identify a hostname."],
      anatomy: null,
      checkResults,
      hasWarnings: false
    };
  }

  // Anatomy
  const labels = host.split(".").filter(Boolean);
  const anatomy = {
    scheme: parsed.protocol.replace(":", ""),
    host: host,
    subdomainCount: labels.length,
    path: parsed.pathname + parsed.search + parsed.hash || "/",
    length: url.length
  };

  // Check 1: @ symbol
  if (candidate.includes("@")) {
    findings.push("Contains an @ symbol; inspect carefully.");
    checkResults.hasAt = true;
  }

  // Check 2: Unusually long URL (> 100 chars)
  if (url.length > 100) {
    findings.push("Unusually long URL (over 100 characters).");
    checkResults.isLong = true;
  }

  // Check 3: IP address as hostname
  const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  if (ipRegex.test(host)) {
    findings.push("Uses an IP address instead of a familiar domain.");
    checkResults.isIp = true;
  }

  // Check 4: Hostname segments (>= 5)
  if (labels.length >= 5) {
    findings.push("Contains many hostname segments/subdomains.");
    checkResults.manySegments = true;
  }

  // Check 5: Punycode marker (xn--)
  if (host.includes("xn--")) {
    findings.push("Contains a punycode-style hostname.");
    checkResults.isPunycode = true;
  }

  // Check 6: Plain HTTP scheme
  if (anatomy.scheme === "http") {
    findings.push("Uses HTTP. HTTPS alone does not prove trust.");
    checkResults.isHttp = true;
  }

  // Default clean finding
  const hasWarnings = findings.length > 0;
  if (!hasWarnings) {
    findings.push("No listed warning signs found. This does NOT prove safety.");
  }

  return {
    findings,
    anatomy,
    checkResults,
    hasWarnings
  };
}

/**
 * Update the UI with inspection results
 */
function displayResults(rawUrl, analysis) {
  resultSection.style.display = "flex";

  // Re-trigger card pop-in animation
  [checkAt, checkLength, checkIp, checkSubdomains, checkPunycode, checkHttp].forEach(card => {
    card.classList.remove("pop-in");
    void card.offsetWidth; // Force reflow
    card.classList.add("pop-in");
  });

  // Reset check cards
  const updateCard = (cardEl, isFlagged) => {
    const statusEl = cardEl.querySelector(".check-status");
    if (isFlagged) {
      statusEl.className = "check-status status-flagged";
      statusEl.textContent = "Flagged";
    } else {
      statusEl.className = "check-status status-pass";
      statusEl.textContent = "Pass";
    }
  };

  updateCard(checkAt, analysis.checkResults.hasAt);
  updateCard(checkLength, analysis.checkResults.isLong);
  updateCard(checkIp, analysis.checkResults.isIp);
  updateCard(checkSubdomains, analysis.checkResults.manySegments);
  updateCard(checkPunycode, analysis.checkResults.isPunycode);
  updateCard(checkHttp, analysis.checkResults.isHttp);

  // Update Anatomy
  if (analysis.anatomy) {
    partScheme.textContent = analysis.anatomy.scheme.toUpperCase();
    partHost.textContent = analysis.anatomy.host;
    partSubdomains.textContent = `${analysis.anatomy.subdomainCount} segments`;
    partPath.textContent = analysis.anatomy.path;
    partLength.textContent = `${analysis.anatomy.length} characters`;
  } else {
    partScheme.textContent = "-";
    partHost.textContent = "-";
    partSubdomains.textContent = "-";
    partPath.textContent = "-";
    partLength.textContent = `${(rawUrl || "").length} characters`;
  }

  // Update Status Banner
  statusBanner.className = "status-banner";
  if (analysis.hasWarnings) {
    statusBanner.classList.add("status-warning");
    bannerIcon.textContent = "⚠️";
    bannerTitle.textContent = "Review Carefully: Warning Signs Detected";
    bannerMessage.textContent = "This URL exhibits patterns commonly leveraged by deceptive phishing lures.";
    warningBadge.className = "warning-badge badge-warning";
    warningBadge.textContent = `${analysis.findings.length} Warning(s)`;
  } else if (analysis.isEmpty || analysis.isMalformed) {
    statusBanner.classList.add("status-neutral");
    bannerIcon.textContent = "ℹ️";
    bannerTitle.textContent = analysis.isMalformed ? "Invalid URL Format" : "Input Required";
    bannerMessage.textContent = analysis.findings[0];
    warningBadge.className = "warning-badge badge-neutral";
    warningBadge.textContent = "Notice";
  } else {
    statusBanner.classList.add("status-clean");
    bannerIcon.textContent = "🛡️";
    bannerTitle.textContent = "No Listed Warning Signs Found";
    bannerMessage.textContent = "Heuristics passed. Remember: absence of red flags does NOT guarantee safety!";
    warningBadge.className = "warning-badge badge-clean";
    warningBadge.textContent = "No Warnings";
  }

  // Detailed findings list
  findingsList.innerHTML = "";
  analysis.findings.forEach(item => {
    const li = document.createElement("li");
    const isWarn = analysis.hasWarnings;
    li.className = `finding-item ${isWarn ? "flagged" : "info"}`;
    li.textContent = `- ${item}`;
    findingsList.appendChild(li);
  });

  // Log into Terminal session
  appendTerminalRun(rawUrl, analysis);
}

/**
 * Appends simulated Python CLI output to the in-browser Terminal
 */
function appendTerminalRun(rawUrl, analysis) {
  const runBlock = document.createElement("div");
  runBlock.className = "term-run-entry";

  let linesHtml = `
    <div class="term-line term-prompt">Enter a sample URL (or type q to quit): <span class="term-active-input">${escapeHtml(rawUrl)}</span></div>
    <div class="term-line">&nbsp;</div>
    <div class="term-line">Result:</div>
  `;

  analysis.findings.forEach(item => {
    const colorClass = analysis.hasWarnings ? "term-red" : "term-green";
    linesHtml += `<div class="term-line ${colorClass}">- ${escapeHtml(item)}</div>`;
  });

  if (analysis.hasWarnings) {
    linesHtml += `
      <div class="term-line">&nbsp;</div>
      <div class="term-line term-red"><strong>REVIEW CAREFULLY: ${analysis.findings.length} warning sign(s) found.</strong></div>
    `;
  }

  linesHtml += `
    <div class="term-line term-yellow">Never enter passwords from unexpected links.</div>
    <div class="term-line">&nbsp;</div>
  `;

  runBlock.innerHTML = linesHtml;
  termOutput.appendChild(runBlock);

  // Auto scroll terminal
  terminalBody.scrollTop = terminalBody.scrollHeight;
}

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let isAnalyzing = false;

function runAnalysis(onComplete) {
  if (isAnalyzing) return;
  isAnalyzing = true;

  const rawUrl = urlInput.value;

  // Trigger button scanning state
  inspectBtn.classList.add("scanning");
  if (btnText) btnText.textContent = "Scanning...";

  // Trigger laser beam sweep
  if (laserBeam) {
    laserBeam.classList.remove("scanning");
    void laserBeam.offsetWidth; // Force reflow
    laserBeam.classList.add("scanning");
  }

  // Micro-animation scanning delay
  setTimeout(() => {
    const analysis = inspectUrl(rawUrl);
    displayResults(rawUrl, analysis);

    // Reset button
    inspectBtn.classList.remove("scanning");
    if (btnText) btnText.textContent = "Inspect URL";
    isAnalyzing = false;

    if (onComplete) onComplete();
  }, 350);
}

// Event Listeners
inspectBtn.addEventListener("click", () => runAnalysis());

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    runAnalysis();
  }
});

urlInput.addEventListener("input", () => {
  clearBtn.style.display = urlInput.value ? "block" : "none";
  termActiveInput.textContent = urlInput.value;
});

clearBtn.addEventListener("click", () => {
  urlInput.value = "";
  clearBtn.style.display = "none";
  termActiveInput.textContent = "";
  urlInput.focus();
});

// Preset Buttons
presetButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    const url = btn.getAttribute("data-url");
    urlInput.value = url;
    clearBtn.style.display = "block";
    termActiveInput.textContent = url;
    runAnalysis(() => {
      resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
});

// Auto-run initial sample on page load
window.addEventListener("DOMContentLoaded", () => {
  urlInput.value = "http://192.0.2.10/account";
  clearBtn.style.display = "block";
  termActiveInput.textContent = urlInput.value;
  runAnalysis();
});

// Continuously remove any Netlify drawer/badge injection
const removeNetlifyBadge = () => {
  const elements = document.querySelectorAll(
    'iframe[src*="netlify"], [data-netlify-drawer], #netlify-drawer, div[class*="feedback"], a[href*="netlify.com"][style*="fixed"], a[href*="netlify.com"][class*="badge"], div:has(> a[href*="netlify.com"])'
  );
  elements.forEach(el => el.remove());
};

window.addEventListener("DOMContentLoaded", removeNetlifyBadge);
setInterval(removeNetlifyBadge, 400);
