type VulnCve = {
  id: string;
  description: string;
  score: number;
  severity: string;
  vector: string;
  cwes: string[];
  published: string;
  modified: string;
  references: string[];
  affected_products: string[];
};

type VulnAnalysis = {
  summary: string;
  technical: {
    affected_component: string;
    attacker_capability: string;
    exploitation_conditions: string;
  };
  exploitation_likelihood: string;
  likelihood_justification: string;
  triage_priority: string;
  confidence: string;
  remediation: string[];
  detection_guidance: string;
  limitations: string[];
};

type VulnReport = {
  cve: VulnCve;
  analysis: VulnAnalysis;
};

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element: ${id}`);
  return element as T;
};

const renderList = (items: string[], ordered = false): string => {
  const tag = ordered ? "ol" : "ul";
  return `<${tag}>${items.map((item) => `<li>${item}</li>`).join("")}</${tag}>`;
};

function renderReport(report: VulnReport): void {
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

async function loadSample(): Promise<void> {
  const response = await fetch("sample-report.json");
  renderReport(await response.json() as VulnReport);
}

async function loadFile(file: File): Promise<void> {
  renderReport(JSON.parse(await file.text()) as VulnReport);
}

byId<HTMLButtonElement>("load-sample").addEventListener("click", () => void loadSample());
byId<HTMLInputElement>("report-file").addEventListener("change", (event) => {
  const input = event.currentTarget;
  if (input.files?.[0]) void loadFile(input.files[0]);
});

void loadSample();
