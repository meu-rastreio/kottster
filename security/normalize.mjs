#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, i, all) => {
    if (value.startsWith("--")) pairs.push([value.slice(2), all[i + 1]]);
    return pairs;
  }, []),
);
const { root, raw, out, project, commit, branch } = args;
const dirty = args.dirty === "true";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const RAW_FILE_TOOL = {
  "semgrep.json": "semgrep",
  "hounddog.json": "hounddog",
  "osv.json": "osv",
  "socket-scan.json": "socket",
};

const unreadable = new Set();
const readJson = (file) => {
  const path = join(raw, file);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    unreadable.add(file);
    return null;
  }
};

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g,
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}/g,
  /\b(ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}/g,
  /\bsk-[A-Za-z0-9_-]{20,}/g,
  /\bxox[abpors]-[A-Za-z0-9-]{10,}/g,
  /\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]+@/g,
  /\b[A-Fa-f0-9]{32,}\b/g,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
];
const SECRET_KEY = String.raw`(?:pass(?:word)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_]*["']?\s*[:=]\s*`;
// Linha com atribuição a um nome de credencial: mascara tudo depois do ":"/"=" até o fim da linha.
// Não tenta interpretar aspas/escapes (cada linguagem tem regras diferentes); prefere mascarar a mais a vazar.
const SECRET_ASSIGNMENT = new RegExp(`(${SECRET_KEY})[^\\n]*`, "gi");

export function redact(text) {
  if (!text) return text;
  let result = String(text).replace(SECRET_ASSIGNMENT, (_, prefix) => `${prefix}[REDACTED]`);
  for (const pattern of SECRET_PATTERNS) result = result.replace(pattern, "[REDACTED]");
  return result;
}

const sourceCache = new Map();
function readLines(file, start, end) {
  if (!file || !start) return "";
  if (!sourceCache.has(file)) {
    const path = join(root, file);
    sourceCache.set(file, existsSync(path) ? readFileSync(path, "utf8").split("\n") : []);
  }
  const lines = sourceCache.get(file);
  return lines.slice(start - 1, Math.min(end || start, start + 7)).join("\n");
}

const stableId = (...parts) =>
  createHash("sha256")
    .update(parts.map((p) => String(p ?? "").replace(/\s+/g, " ").trim()).join("|"))
    .digest("hex")
    .slice(0, 16);

const packageKey = (ecosystem, name, version) =>
  [String(ecosystem ?? "").toLowerCase(), name ?? "", version ?? ""].join("|");

const findings = [];

function add(finding) {
  const secret = finding.category === "secret";
  findings.push({
    id: finding.id,
    tool: finding.tool,
    tool_version: finding.tool_version,
    rule: finding.rule,
    rule_license: finding.rule_license ?? null,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence ?? null,
    title: redact(finding.title),
    message: redact(finding.message),
    file: finding.file ?? null,
    line_start: finding.line_start ?? null,
    line_end: finding.line_end ?? null,
    snippet: secret ? null : redact(finding.snippet || "") || null,
    cwe: finding.cwe ?? [],
    owasp: finding.owasp ?? [],
    references: finding.references ?? [],
    package: finding.package ?? null,
    aliases: finding.aliases ?? [],
  });
}

const semgrep = readJson("semgrep.json");
for (const r of semgrep?.results ?? []) {
  const meta = r.extra?.metadata ?? {};
  const snippet = readLines(r.path, r.start?.line, r.end?.line);
  const isSecret = /secret|credential|password|token|api[-_]?key/i.test(r.check_id) || meta.category === "secrets";
  add({
    id: stableId("semgrep", r.check_id, r.path, snippet),
    tool: "semgrep",
    tool_version: semgrep.version,
    rule: r.check_id,
    rule_license: meta.license ?? (r.check_id.startsWith("security.") ? "interno (security/semgrep-rules.yml)" : null),
    category: isSecret ? "secret" : "code",
    severity: { ERROR: "high", WARNING: "medium", INFO: "low" }[r.extra?.severity] ?? "low",
    confidence: meta.confidence?.toLowerCase() ?? null,
    title: r.check_id.split(".").pop(),
    message: r.extra?.message,
    file: r.path,
    line_start: r.start?.line,
    line_end: r.end?.line,
    snippet,
    cwe: [].concat(meta.cwe ?? []),
    owasp: [].concat(meta.owasp ?? []),
    references: [].concat(meta.references ?? [], meta.source ?? []),
  });
}

const hounddog = readJson("hounddog.json");
const sinkInfo = new Map((hounddog?.data_sinks ?? []).map((s) => [s.id, s]));
for (const flow of hounddog?.dataflows ?? []) {
  const seg = flow.code_segment ?? {};
  const sink = sinkInfo.get(flow.data_sink_slug) ?? {};
  const elements = [...new Set((flow.data_elements ?? []).map((e) => e.data_element_slug))];
  add({
    id: stableId("hounddog", flow.data_sink_slug, seg.rel_file_path, elements.join(","), seg.content),
    tool: "hounddog",
    tool_version: hounddog.hounddog_version,
    rule: `${elements.join("+")} -> ${flow.data_sink_slug}`,
    rule_license: "HoundDog.ai Terms of Service (uso interno)",
    category: "privacy",
    severity: SEVERITY_ORDER.includes(flow.severity) ? flow.severity : "low",
    title: sink.vulnerability?.description ?? `Dado sensível enviado para ${sink.name ?? flow.data_sink_slug}`,
    message: `Dados (${elements.join(", ")}) fluem para ${sink.name ?? flow.data_sink_slug}. ${sink.vulnerability?.remediation ?? ""}`.trim(),
    file: seg.rel_file_path,
    line_start: seg.line_start,
    line_end: seg.line_end,
    snippet: seg.content,
    cwe: sink.vulnerability?.cwe ?? [],
    owasp: sink.vulnerability?.owasp ?? [],
  });
}

const cvssToSeverity = (score) => {
  const n = Number(score);
  if (Number.isNaN(n)) return null;
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  return n > 0 ? "low" : "info";
};
const osv = readJson("osv.json");
for (const result of osv?.results ?? []) {
  const manifest = result.source?.path?.replace(/^\/src\//, "");
  for (const pkg of result.packages ?? []) {
    const vulns = new Map((pkg.vulnerabilities ?? []).map((v) => [v.id, v]));
    for (const group of pkg.groups ?? []) {
      const vuln = vulns.get(group.ids[0]) ?? {};
      const label = vuln.database_specific?.severity?.toLowerCase();
      const name = `${pkg.package.name}@${pkg.package.version}`;
      add({
        id: stableId("osv", group.ids[0], manifest, name),
        tool: "osv-scanner",
        tool_version: null,
        rule: group.ids[0],
        rule_license: "OSV (CC-BY 4.0 / fonte do advisory)",
        category: "dependency",
        severity: cvssToSeverity(group.max_severity) ?? (label === "moderate" ? "medium" : label) ?? "medium",
        confidence: "high",
        title: vuln.summary ?? group.ids[0],
        message: `${name} (${pkg.package.ecosystem}) é afetado por ${group.aliases?.join(", ") || group.ids[0]}.`,
        file: manifest,
        package: { name: pkg.package.name, version: pkg.package.version, ecosystem: pkg.package.ecosystem },
        aliases: [...new Set([...(group.ids ?? []), ...(group.aliases ?? [])])],
        cwe: vuln.database_specific?.cwe_ids ?? [],
        references: (vuln.references ?? []).filter((ref) => ref.type === "ADVISORY").map((ref) => ref.url),
      });
    }
  }
}

const SOCKET_SEVERITY = { critical: "critical", high: "high", middle: "medium", medium: "medium" };
const SOCKET_RISK_TYPES = new Set([
  "malware",
  "gptMalware",
  "criticalCVE",
  "cve",
  "mediumCVE",
  "mildCVE",
  "didYouMean",
  "gptDidYouMean",
  "gptSecurity",
  "gptAnomaly",
  "potentialVulnerability",
  "obfuscatedFile",
  "obfuscatedRequire",
  "manifestConfusion",
  "protestware",
  "troll",
  "deprecated",
]);
const osvKeys = new Set(
  findings
    .filter((f) => f.tool === "osv-scanner")
    .flatMap((f) => f.aliases.map((alias) => `${alias}|${packageKey(f.package.ecosystem, f.package.name, f.package.version)}`)),
);
const socketPackageName = (artifact) => {
  if (!artifact.namespace) return artifact.name;
  return artifact.type === "maven" ? `${artifact.namespace}:${artifact.name}` : `${artifact.namespace}/${artifact.name}`;
};
const socketScan = readJson("socket-scan.json");
let socketAlerts = 0;
for (const artifact of Array.isArray(socketScan?.data) ? socketScan.data : []) {
  const name = socketPackageName(artifact);
  const manifests = (artifact.manifestFiles ?? []).map((m) => m.file).filter(Boolean);
  for (const alert of artifact.alerts ?? []) {
    socketAlerts++;
    const severity = SOCKET_SEVERITY[alert.severity];
    const props = alert.props ?? {};
    const advisory = [props.ghsaId, props.cveId].find((id) => typeof id === "string" && id.trim()) ?? null;
    const coveredByOsv = advisory && osvKeys.has(`${advisory}|${packageKey(artifact.type, name, artifact.version)}`);
    if (!severity || !SOCKET_RISK_TYPES.has(alert.type) || coveredByOsv) continue;
    const id = stableId("socket", advisory ?? alert.type, artifact.type, name, artifact.version);
    for (const file of alert.file ? [alert.file] : manifests.length ? manifests : [null]) {
      add({
        id,
        tool: "socket",
        tool_version: null,
        rule: advisory ? `${alert.type}:${advisory}` : alert.type,
        rule_license: "Socket (conferir contrato)",
        category: "dependency",
        severity,
        confidence: "high",
        title: props.title ?? `${alert.type} em ${name}`,
        message: `${name}@${artifact.version} (${artifact.type}): ${props.description ?? props.note ?? alert.type}`.slice(0, 500),
        file,
        package: { name, version: artifact.version ?? null, ecosystem: artifact.type },
        aliases: [props.ghsaId, props.cveId].filter((v) => typeof v === "string" && v.trim()),
        references: [props.url, advisory && `https://osv.dev/vulnerability/${advisory}`].filter(Boolean),
      });
    }
  }
}

const grouped = new Map();
for (const f of findings) {
  const location = { file: f.file, line_start: f.line_start, line_end: f.line_end };
  const existing = grouped.get(f.id);
  if (!existing) {
    grouped.set(f.id, { ...f, occurrences: [location] });
  } else if (!existing.occurrences.some((o) => o.file === location.file && o.line_start === location.line_start)) {
    existing.occurrences.push(location);
  }
}
const unique = [...grouped.values()];
const decisionsPath = join(root, "security", "decisions.json");
const decisions = existsSync(decisionsPath) ? JSON.parse(readFileSync(decisionsPath, "utf8")) : {};
for (const f of unique) {
  const decision = decisions[f.id];
  f.status = decision?.status ?? "novo";
  f.decision = decision ?? null;
}
unique.sort(
  (a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    String(a.file).localeCompare(String(b.file)) ||
    (a.line_start ?? 0) - (b.line_start ?? 0),
);

const scanners = readJson("status.json") ?? {};
for (const file of unreadable) {
  const tool = RAW_FILE_TOOL[file];
  if (tool) scanners[tool] = { status: "failed", detail: `saída inválida em raw/${file}` };
}
if (scanners.socket?.status === "ok") {
  const included = unique.filter((f) => f.tool === "socket").length;
  scanners.socket.detail = `${scanners.socket.detail} · ${socketAlerts} alertas no Socket, ${included} de risco (médio ou mais grave, fora do OSV)`;
}
const open = unique.filter((f) => !["falso-positivo", "risco-aceito", "corrigido"].includes(f.status));
const report = {
  project,
  commit,
  dirty,
  branch,
  generated_at: new Date().toISOString(),
  scanners,
  summary: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, open.filter((f) => f.severity === s).length])),
  findings: unique,
};
writeFileSync(join(out, "findings.json"), JSON.stringify(report, null, 2));

const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const location = (f) => {
  const extra = f.occurrences.length > 1 ? ` (+${f.occurrences.length - 1} locais)` : "";
  return `${cell(f.file)}${f.line_start ? `:${f.line_start}` : ""}${extra}`;
};
const overview = [
  "| Scanner | Status |",
  "| --- | --- |",
  ...Object.entries(scanners).map(([tool, s]) => `| ${tool} | ${s.status}${s.detail ? ` (${cell(s.detail)})` : ""} |`),
  "",
  `**Em aberto:** ${SEVERITY_ORDER.map((s) => `${s} ${report.summary[s]}`).join(" · ")} — total ${open.length} de ${unique.length}`,
  "",
];
const md = [
  `# Security scan — ${project}`,
  "",
  `Commit \`${commit.slice(0, 12)}\`${dirty ? " **com alterações não commitadas**" : ""} · branch \`${branch}\` · ${report.generated_at}`,
  "",
  ...overview,
  "| Severidade | Ferramenta | Regra | Local | Status | ID |",
  "| --- | --- | --- | --- | --- | --- |",
  ...unique.map(
    (f) =>
      `| ${f.severity} | ${f.tool} | ${cell(f.title)} | ${location(f)}${f.package ? ` (${cell(f.package.name)}@${cell(f.package.version)})` : ""} | ${f.status} | \`${f.id}\` |`,
  ),
  "",
];
writeFileSync(join(out, "findings.md"), md.join("\n"));

const COMMENT_ROWS = 50;
const runUrl = process.env.GITHUB_RUN_ID
  ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
  : null;
const shown = open.slice(0, COMMENT_ROWS);
const comment = [
  "<!-- security-scan -->",
  `### Security scan · \`${commit.slice(0, 7)}\``,
  "",
  ...overview,
  ...(shown.length
    ? [
        "| Severidade | Ferramenta | Regra | Local | ID |",
        "| --- | --- | --- | --- | --- |",
        ...shown.map(
          (f) =>
            `| ${f.severity} | ${f.tool} | ${cell(f.title)} | ${location(f)}${f.package ? ` (${cell(f.package.name)}@${cell(f.package.version)})` : ""} | \`${f.id}\` |`,
        ),
      ]
    : ["Nenhum achado em aberto. Isso não comprova ausência de falhas."]),
  "",
  ...(open.length > shown.length ? [`Mostrando ${shown.length} de ${open.length} achados em aberto.`] : []),
  ...(runUrl ? [`Relatório completo no [resumo da execução](${runUrl}) (artefato \`security-findings\`).`] : []),
  "",
];
writeFileSync(join(out, "comment.md"), comment.join("\n"));

console.log(`findings: ${unique.length} (em aberto: ${open.length}) -> ${join(out, "findings.json")}`);
