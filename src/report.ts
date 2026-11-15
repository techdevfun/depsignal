/** Human table + JSON rendering for audit reports. */
import type { AuditReport, PackageResult } from "./rules.js";

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

export function renderHuman(report: AuditReport, limit?: number): string {
  const lines: string[] = [];
  const pkgs = report.packages;
  const nameW = Math.max(7, ...pkgs.map((p) => p.name.length));
  const verW = Math.max(7, ...pkgs.map((p) => p.pinned.length));
  lines.push(
    `${pad("package", nameW)}  ${pad("version", verW)}  verdict  findings`,
  );
  lines.push(`${"-".repeat(nameW)}  ${"-".repeat(verW)}  -------  --------`);
  for (const p of pkgs) {
    const label =
      p.resolvedFrom === "pinned"
        ? ""
        : p.resolvedFrom === "latest"
          ? " (resolved to latest)"
          : " (resolved to latest satisfying)";
    lines.push(
      `${pad(p.name, nameW)}  ${pad(p.pinned, verW)}  ${pad(p.verdict, 7)}  ${p.findings.length} finding(s)${label}`,
    );
  }
  lines.push("");
  for (const p of pkgs) {
    lines.push(`${p.name}==${p.pinned} (${p.verdict})`);
    if (p.findings.length === 0) {
      lines.push("  no findings");
    }
    const shown = limit !== undefined ? p.findings.slice(0, limit) : p.findings;
    for (const f of shown) {
      const sev = f.severity.toUpperCase();
      lines.push(`  [${sev}] ${f.title}`);
      lines.push(`        ${f.evidence}`);
      lines.push(`        source: ${f.source}`);
    }
    if (shown.length < p.findings.length) {
      lines.push(
        `  ... and ${p.findings.length - shown.length} more finding(s) (run with --json for the full list)`,
      );
    }
  }
  if (report.skipped.length > 0) {
    lines.push("");
    for (const s of report.skipped) lines.push(`skipped: ${s}`);
  }
  if (report.notes.length > 0) {
    lines.push("");
    for (const n of report.notes) lines.push(`note: ${n}`);
  }
  const fails = pkgs.filter((p) => p.verdict === "FAIL").length;
  const warns = pkgs.filter((p) => p.verdict === "WARN").length;
  lines.push("");
  lines.push(
    `${pkgs.length} package(s): ${fails} FAIL, ${warns} WARN, ${pkgs.length - fails - warns} PASS`,
  );
  lines.push(
    fails > 0
      ? "verdict: FAIL - at least one dependency failed the gate (exit 1)"
      : "verdict: PASS - no dependency failed the gate (exit 0)",
  );
  return lines.join("\n");
}

export function renderJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

export function summaryLine(p: PackageResult): string {
  return `${p.name}==${p.pinned}: ${p.verdict}`;
}
