/**
 * Baseline files: JSON written by `audit --save-baseline`, read by
 * `check` and `diff`. A baseline is an AuditReport; `check` fails only
 * on NEW fail findings (same package + same finding key) and lists
 * fixed findings without failing.
 */
import { readFileSync, writeFileSync } from "node:fs";
import type { AuditReport, Finding, PackageResult } from "./rules.js";

export function loadBaseline(path: string): AuditReport {
  const raw = readFileSync(path, "utf8");
  const data = JSON.parse(raw) as AuditReport;
  if (!data || data.tool !== "depsignal" || !Array.isArray(data.packages)) {
    throw new Error(`not a depsignal baseline: ${path}`);
  }
  return data;
}

export function saveBaseline(path: string, report: AuditReport): void {
  writeFileSync(path, JSON.stringify(report, null, 2) + "\n", "utf8");
}

export interface DiffEntry {
  name: string;
  before: string;
  after: string;
  kind: "new" | "fixed" | "unchanged";
  rule: string;
  title: string;
}

/** Compare two reports package by package, finding by finding. */
export function diffReports(
  before: AuditReport,
  after: AuditReport,
): DiffEntry[] {
  const entries: DiffEntry[] = [];
  const beforeByName = new Map<string, PackageResult>();
  for (const p of before.packages) beforeByName.set(p.name, p);
  const afterByName = new Map<string, PackageResult>();
  for (const p of after.packages) afterByName.set(p.name, p);

  const names = new Set([...beforeByName.keys(), ...afterByName.keys()]);
  for (const name of [...names].sort()) {
    const b = beforeByName.get(name);
    const a = afterByName.get(name);
    const bFindings = new Map<string, Finding>();
    for (const f of b?.findings ?? []) bFindings.set(f.key, f);
    const aFindings = new Map<string, Finding>();
    for (const f of a?.findings ?? []) aFindings.set(f.key, f);

    for (const [key, f] of aFindings) {
      if (!bFindings.has(key)) {
        entries.push({
          name,
          before: b ? b.verdict : "-",
          after: a?.verdict ?? "-",
          kind: "new",
          rule: f.rule,
          title: f.title,
        });
      }
    }
    for (const [key, f] of bFindings) {
      if (!aFindings.has(key)) {
        entries.push({
          name,
          before: b?.verdict ?? "-",
          after: a ? a.verdict : "-",
          kind: "fixed",
          rule: f.rule,
          title: f.title,
        });
      }
    }
    for (const [key, f] of aFindings) {
      if (bFindings.has(key)) {
        entries.push({
          name,
          before: b?.verdict ?? "-",
          after: a?.verdict ?? "-",
          kind: "unchanged",
          rule: f.rule,
          title: f.title,
        });
      }
    }
  }
  return entries;
}

/** New FAIL findings in `current` that were not in `baseline`. */
export function newFailFindings(
  baseline: AuditReport,
  current: AuditReport,
): { name: string; finding: Finding }[] {
  const baseKeys = new Set<string>();
  for (const p of baseline.packages) {
    for (const f of p.findings) {
      if (f.severity === "fail") baseKeys.add(`${p.name}:${f.key}`);
    }
  }
  const out: { name: string; finding: Finding }[] = [];
  for (const p of current.packages) {
    for (const f of p.findings) {
      if (f.severity === "fail" && !baseKeys.has(`${p.name}:${f.key}`)) {
        out.push({ name: p.name, finding: f });
      }
    }
  }
  return out;
}

/** FAIL findings present in baseline but gone in current. */
export function fixedFailFindings(
  baseline: AuditReport,
  current: AuditReport,
): { name: string; finding: Finding }[] {
  const curKeys = new Set<string>();
  for (const p of current.packages) {
    for (const f of p.findings) {
      if (f.severity === "fail") curKeys.add(`${p.name}:${f.key}`);
    }
  }
  const out: { name: string; finding: Finding }[] = [];
  for (const p of baseline.packages) {
    for (const f of p.findings) {
      if (f.severity === "fail" && !curKeys.has(`${p.name}:${f.key}`)) {
        out.push({ name: p.name, finding: f });
      }
    }
  }
  return out;
}
