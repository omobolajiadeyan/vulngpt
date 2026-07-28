const byId = (id) => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element: ${id}`);
  return element;
};

function renderReport(report) {
  byId("cve-id").textContent = report.cve.id;
  byId("severity").innerHTML = `<span class="badge ${report.cve.severity}">${report.cve.severity} ${report.cve.score}</span>`;
  byId("priority").textContent = report.analysis.triage_priority;
  byId("confidence").textContent = report.analysis.confidence;
  byId("report-title").textContent = `${report.cve.id} triage summary`;
  byId("summary-text").textContent = report.analysis.summary;
  byId("likelihood").innerHTML = `<span class="badge ${report.analysis.exploitation_likelihood}">${report.analysis.exploitation_likelihood}</span>`;
  byId("likelihood-why").textContent = report.analysis.likelihood_justification;

  byId("technical").innerHTML = `
    <dt>Affected</dt><dd>${report.analysis.technical.affected_component}</dd>
    <dt>Capability</dt><dd>${report.analysis.technical.attacker_capability}</dd>
    <dt>Conditions</dt><dd>${report.analysis.technical.exploitation_conditions}</dd>
    <dt>CWEs</dt><dd>${report.cve.cwes.join(", ")}</dd>
    <dt>Vector</dt><dd>${report.cve.vector}</dd>
  `;

  byId("remediation").innerHTML = report.analysis.remediation.map((item) => `<li>${item}</li>`).join("");
  byId("detection").textContent = report.analysis.detection_guidance;
  byId("limitations").innerHTML = report.analysis.limitations.map((item) => `<li>${item}</li>`).join("");
  byId("references").innerHTML = report.cve.references
    .map((url) => `<li><a href="${url}" target="_blank" rel="noopener">${url}</a></li>`)
    .join("");
}

async function loadSample() {
  const response = await fetch("sample-report.json");
  renderReport(await response.json());
}

async function loadFile(file) {
  renderReport(JSON.parse(await file.text()));
}

byId("load-sample").addEventListener("click", () => void loadSample());
byId("report-file").addEventListener("change", (event) => {
  const input = event.currentTarget;
  if (input.files?.[0]) void loadFile(input.files[0]);
});

void loadSample();
