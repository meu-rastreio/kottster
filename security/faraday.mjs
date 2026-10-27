#!/usr/bin/env node
import { readFileSync } from "node:fs";

const [findingsPath, ...flags] = process.argv.slice(2);
const dryRun = flags.includes("--dry-run");
const {
  FARADAY_URL,
  FARADAY_USERNAME,
  FARADAY_PASSWORD,
  FARADAY_CF_KEY,
  FARADAY_WORKSPACE = "meu-rastreio",
  GITHUB_SERVER_URL,
  GITHUB_REPOSITORY,
  GITHUB_RUN_ID,
} = process.env;

if (!findingsPath) {
  console.error("uso: node security/faraday.mjs <findings.json> [--dry-run]");
  process.exit(1);
}
if (!dryRun && !(FARADAY_URL && FARADAY_USERNAME && FARADAY_PASSWORD)) {
  console.log("Faraday: FARADAY_URL, FARADAY_USERNAME ou FARADAY_PASSWORD ausente, envio ignorado.");
  process.exit(0);
}

const report = JSON.parse(readFileSync(findingsPath, "utf8"));
if (report.dirty) {
  console.error("Faraday: relatório com alterações não commitadas não é enviado.");
  process.exit(1);
}

const SEVERITY = { critical: "critical", high: "high", medium: "medium", low: "low", info: "informational" };
const STATUS = {
  novo: "open",
  confirmado: "open",
  suspeita: "open",
  "risco-aceito": "risk-accepted",
  "falso-positivo": "closed",
  corrigido: "closed",
};
const DECISION_LABEL = { "risco-aceito": "Risco aceito", "falso-positivo": "Falso positivo", corrigido: "Corrigido" };
const resolution = (d) =>
  d
    ? [
        `${DECISION_LABEL[d.status] ?? d.status}: ${d.justificativa ?? "-"}`,
        `Responsável: ${d.responsavel ?? "-"} · Data: ${d.data ?? "-"}`,
      ].join("\n")
    : "";
// Only a Resolution in the format above is cleared when the decision is removed; notes typed in Faraday stay.
const isDecisionResolution = (text) => /\nResponsável: .* · Data: .*$/.test(text ?? "");
const host = report.project;
const runUrl = GITHUB_RUN_ID ? `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}` : null;

const vulnerability = (f) => {
  const where = f.package ? `${f.package.name}@${f.package.version} (${f.file ?? "?"})` : f.file ?? "?";
  const locations = f.occurrences
    .map((o) => `${o.file ?? "?"}${o.line_start ? `:${o.line_start}${o.line_end && o.line_end !== o.line_start ? `-${o.line_end}` : ""}` : ""}`)
    .join("\n");
  return {
    type: "Vulnerability",
    name: `${f.title} [${f.id}]`,
    desc: [f.message, "", `Ferramenta: ${f.tool}`, `Regra: ${f.rule}`, `Local: ${where}`].join("\n"),
    severity: SEVERITY[f.severity] ?? "informational",
    status: STATUS[f.status] ?? "open",
    resolution: resolution(f.decision),
    external_id: f.id,
    tool: f.tool,
    data: [
      `Commit: ${report.commit}`,
      ...(runUrl ? [`Execução: ${runUrl}`] : []),
      `Licença da regra: ${f.rule_license ?? "-"}`,
      `Confiança: ${f.confidence ?? "-"}`,
      "",
      "Locais:",
      locations,
      ...(f.snippet ? ["", "Trecho (sanitizado):", f.snippet] : []),
      ...(f.decision ? ["", `Decisão: ${JSON.stringify(f.decision)}`] : []),
    ].join("\n"),
    refs: [...new Set(f.references ?? [])].map((name) => ({ name, type: "other" })),
    cwe: (f.cwe ?? []).map((c) => String(c).match(/CWE-\d+/)?.[0]).filter(Boolean),
    cve: (f.aliases ?? []).filter((a) => /^CVE-\d+-\d+$/.test(a)),
    policyviolations: [],
  };
};

const hostData = { ip: host, description: `Repositório ${GITHUB_REPOSITORY ?? host}`, hostnames: [] };
const vulns = report.findings.map(vulnerability);

if (dryRun) {
  console.log(JSON.stringify({ host: hostData, vulnerabilities: vulns }, null, 2));
  process.exit(0);
}

const base = `${FARADAY_URL.replace(/\/+$/, "")}/_api/v3`;
const headers = {
  Authorization: `Basic ${Buffer.from(`${FARADAY_USERNAME}:${FARADAY_PASSWORD}`).toString("base64")}`,
  "Content-Type": "application/json",
  Accept: "application/json",
  ...(FARADAY_CF_KEY ? { "X-CI-Key": FARADAY_CF_KEY } : {}),
};
const ws = encodeURIComponent(FARADAY_WORKSPACE);

function failure(method, path, response, text) {
  const ray = response.headers.get("cf-ray");
  if (ray) {
    const kind = text.includes("you have been blocked")
      ? "bloqueado por regra do Cloudflare"
      : text.includes("Just a moment") || text.includes("challenge")
        ? "desafio do Cloudflare"
        : "resposta do Cloudflare";
    if (/<html/i.test(text)) {
      return new Error(`${method} ${path} -> ${response.status}: ${kind} (Ray ID ${ray}; procure em Security → Events)`);
    }
  }
  return new Error(`${method} ${path} -> ${response.status}: ${text.slice(0, 300)}`);
}

async function api(method, path, body, { allowConflict = false } = {}) {
  const response = await fetch(`${base}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await response.text();
  if (allowConflict && response.status === 409) return { conflict: existingObject(JSON.parse(text)) };
  if (!response.ok) throw failure(method, path, response, text);
  return text ? JSON.parse(text) : null;
}

function existingObject(node) {
  if (!node || typeof node !== "object") return null;
  if (node.object && typeof node.object === "object") return node.object;
  for (const value of Object.values(node)) {
    const found = existingObject(value);
    if (found) return found;
  }
  return null;
}

const targetStatus = (current, wanted) => {
  if (current === wanted) return null;
  if (wanted === "open") return current === "closed" ? "re-opened" : null;
  return wanted;
};

async function inBatches(items, size, worker) {
  for (let i = 0; i < items.length; i += size) await Promise.all(items.slice(i, i + size).map(worker));
}

const exists = await fetch(`${base}/ws/${ws}`, { headers });
if (exists.status === 404) {
  await api("POST", "/ws", { name: FARADAY_WORKSPACE, description: "Meu Rastreio" });
  console.log(`Faraday: workspace ${FARADAY_WORKSPACE} criado.`);
} else if (!exists.ok) {
  throw failure("GET", `/ws/${FARADAY_WORKSPACE}`, exists, await exists.text());
}

const hostResult = await api("POST", `/ws/${ws}/hosts`, hostData, { allowConflict: true });
const hostId = (hostResult.conflict ?? hostResult)?.id ?? (hostResult.conflict ?? hostResult)?._id;
if (!hostId) throw new Error(`Faraday: não foi possível obter o asset ${host}`);

const counts = { created: 0, updated: 0, unchanged: 0 };
await inBatches(vulns, 5, async (vuln) => {
  const result = await api("POST", `/ws/${ws}/vulns`, { ...vuln, parent: hostId, parent_type: "Host" }, { allowConflict: true });
  if (!result.conflict) {
    counts.created++;
    return;
  }
  const existing = result.conflict;
  const patch = {};
  const status = targetStatus(existing.status, vuln.status);
  if (status) patch.status = status;
  if (vuln.resolution ? existing.resolution !== vuln.resolution : isDecisionResolution(existing.resolution)) {
    patch.resolution = vuln.resolution;
  }
  if (!Object.keys(patch).length) {
    counts.unchanged++;
    return;
  }
  await api("PATCH", `/ws/${ws}/vulns/${existing._id ?? existing.id}`, patch);
  counts.updated++;
});
console.log(
  `Faraday: ${vulns.length} achados de ${host}: ${counts.created} novos, ${counts.updated} com status atualizado, ${counts.unchanged} sem mudança.`,
);

const current = new Set(report.findings.map((f) => f.id));
const SCANNER_OF_TOOL = { "osv-scanner": "osv" };
const scannerRan = (tool) => report.scanners?.[SCANNER_OF_TOOL[tool] ?? tool]?.status === "ok";
const stale = [];
for (let offset = 0; ; offset += 500) {
  const q = {
    filters: [
      { name: "host_id", op: "eq", val: hostId },
      { name: "status", op: "in", val: ["open", "re-opened"] },
    ],
    limit: 500,
    offset,
  };
  const page = await api("GET", `/ws/${ws}/vulns/filter?q=${encodeURIComponent(JSON.stringify(q))}`);
  const rows = page?.vulnerabilities ?? [];
  for (const row of rows) {
    const v = row.value ?? row;
    const sameHost = v.target === host || v.parent === hostId;
    if (sameHost && scannerRan(v.tool) && v.external_id && !current.has(v.external_id)) stale.push(v._id ?? v.id ?? row.id);
  }
  if (rows.length < 500) break;
}
if (stale.length) {
  await api("PATCH", `/ws/${ws}/vulns`, { ids: stale, status: "closed" });
}
console.log(`Faraday: ${stale.length} achados que não aparecem mais foram fechados.`);
