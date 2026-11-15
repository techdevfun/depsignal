#!/usr/bin/env node
/**
 * depsignal - audit Python dependencies against PyPI's own security signals.
 *
 * Usage:
 *   depsignal audit <requirements.txt | pyproject.toml> [--json]
 *             [--allow <pkg> ...] [--save-baseline <file>]
 *             [--pypi-base <url>]
 *   depsignal check --baseline <file> [--input <req>] [--pypi-base <url>]
 *   depsignal diff <baseline-a> <baseline-b>
 *   depsignal explain <pkg>[@<version>] [--pypi-base <url>]
 *   depsignal --help | --version
 *
 * Exit codes: 0 = no FAIL, 1 = >=1 FAIL (audit/check), 2 = usage/network error.
 * `--pypi-base` points the client at another registry-compatible server;
 * it exists so the LiteLLM 1.107.0 replay can run against a local fixture
 * server with recorded payloads (1.107.0 no longer exists on PyPI).
 */
import { readFileSync } from "node:fs";
import {
  diffReports,
  fixedFailFindings,
  loadBaseline,
  newFailFindings,
  saveBaseline,
} from "./baseline.js";
import { parsePyprojectText, parseRequirementsText } from "./pep508.js";
import { PypiClient, PypiError } from "./pypi.js";
import { auditPackage, auditRequirements } from "./rules.js";
import { renderHuman, renderJson } from "./report.js";
import { isStable, latestStable } from "./version.js";

const VERSION = "0.1.0";
const DEFAULT_BASE = "https://pypi.org";

function usage(): string {
  return [
    "depsignal 0.1.0 - audit Python dependencies against PyPI security signals",
    "",
    "Usage:",
    "  depsignal audit <requirements.txt | pyproject.toml> [--json]",
    "            [--allow <pkg> ...] [--save-baseline <file>]",
    "            [--pypi-base <url>] [--limit <n>]",
    "  depsignal check --baseline <file> [--input <req>] [--pypi-base <url>]",
    "  depsignal diff <baseline-a> <baseline-b>",
    "  depsignal explain <pkg>[@<version>] [--pypi-base <url>]",
    "  depsignal --help | --version",
    "",
    "Exit codes: 0 = no FAIL, 1 = >=1 FAIL, 2 = usage or network error.",
    "See https://github.com/techdevfun/depsignal for the verdict rules.",
  ].join("\n");
}

function failUsage(message: string): never {
  console.error(`error: ${message}`);
  console.error(usage());
  process.exit(2);
}

interface GlobalFlags {
  json: boolean;
  allow: string[];
  saveBaseline: string | null;
  pypiBase: string;
  input: string | null;
  baseline: string | null;
  limit: number | null;
  positional: string[];
}

function parseFlags(args: string[]): GlobalFlags {
  const flags: GlobalFlags = {
    json: false,
    allow: [],
    saveBaseline: null,
    pypiBase: process.env.DEPSIGNAL_PYPI_BASE ?? DEFAULT_BASE,
    input: null,
    baseline: null,
    limit: null,
    positional: [],
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") flags.json = true;
    else if (a === "--allow") {
      const v = args[++i];
      if (!v) failUsage("--allow needs a package name");
      flags.allow.push(v.toLowerCase().replace(/[-_.]+/g, "-"));
    } else if (a === "--save-baseline") {
      const v = args[++i];
      if (!v) failUsage("--save-baseline needs a file path");
      flags.saveBaseline = v;
    } else if (a === "--pypi-base") {
      const v = args[++i];
      if (!v) failUsage("--pypi-base needs a URL");
      flags.pypiBase = v.replace(/\/$/, "");
    } else if (a === "--input") {
      const v = args[++i];
      if (!v) failUsage("--input needs a file path");
      flags.input = v;
    } else if (a === "--baseline") {
      const v = args[++i];
      if (!v) failUsage("--baseline needs a file path");
      flags.baseline = v;
    } else if (a === "--limit") {
      const v = args[++i];
      const n = Number(v);
      if (!v || !Number.isInteger(n) || n < 1)
        failUsage("--limit needs a positive integer");
      flags.limit = n;
    } else if (a.startsWith("--")) {
      failUsage(`unknown flag: ${a}`);
    } else {
      flags.positional.push(a);
    }
  }
  return flags;
}

function readInput(path: string) {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    failUsage(`cannot read input file: ${path}`);
  }
  if (path.endsWith("pyproject.toml")) return parsePyprojectText(text!);
  return parseRequirementsText(text!);
}

async function cmdAudit(flags: GlobalFlags): Promise<number> {
  const input = flags.positional[0];
  if (!input) failUsage("audit needs an input file");
  const parsed = readInput(input);
  if (parsed.requirements.length === 0) {
    console.error("error: no requirements found in input file");
    return 2;
  }
  const client = new PypiClient({ baseUrl: flags.pypiBase });
  let report;
  try {
    report = await auditRequirements(
      parsed.requirements,
      client,
      {
        allow: new Set(flags.allow),
      },
      { skipped: parsed.skipped, notes: parsed.notes },
    );
  } catch (err) {
    return networkError(err);
  }
  if (flags.saveBaseline) {
    saveBaseline(flags.saveBaseline, report);
    console.error(`baseline saved to ${flags.saveBaseline}`);
  }
  if (flags.json) console.log(renderJson(report));
  else console.log(renderHuman(report, flags.limit ?? undefined));
  return report.packages.some((p) => p.verdict === "FAIL") ? 1 : 0;
}

async function cmdCheck(flags: GlobalFlags): Promise<number> {
  if (!flags.baseline) failUsage("check needs --baseline <file>");
  let baseline;
  try {
    baseline = loadBaseline(flags.baseline);
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : err}`);
    return 2;
  }
  const input = flags.input ?? flags.positional[0];
  if (!input)
    failUsage("check needs --input <file> or a positional input file");
  const parsed = readInput(input);
  if (parsed.requirements.length === 0) {
    console.error("error: no requirements found in input file");
    return 2;
  }
  const client = new PypiClient({ baseUrl: flags.pypiBase });
  let report;
  try {
    report = await auditRequirements(
      parsed.requirements,
      client,
      {
        allow: new Set(flags.allow),
      },
      { skipped: parsed.skipped, notes: parsed.notes },
    );
  } catch (err) {
    return networkError(err);
  }
  const fresh = newFailFindings(baseline, report);
  const fixed = fixedFailFindings(baseline, report);
  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          version: 1,
          tool: "depsignal",
          checkedAt: report.checkedAt,
          newFailFindings: fresh,
          fixedFailFindings: fixed,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(`checking ${input} against baseline ${flags.baseline} ...`);
    for (const { name, finding } of fixed) {
      console.log(`${name}: ${finding.title} (fixed)`);
    }
    if (fresh.length === 0) {
      console.log("no new FAIL findings vs baseline");
      console.log("verdict: PASS - no new failures (exit 0)");
    } else {
      for (const { name, finding } of fresh) {
        console.log(`[FAIL] ${name}: ${finding.title}`);
        console.log(`       ${finding.evidence}`);
        console.log(`       source: ${finding.source}`);
      }
      console.log(
        `verdict: FAIL - ${fresh.length} new FAIL finding(s) vs baseline (exit 1)`,
      );
    }
  }
  return fresh.length > 0 ? 1 : 0;
}

function cmdDiff(flags: GlobalFlags): number {
  const [a, b] = flags.positional;
  if (!a || !b) failUsage("diff needs two baseline files");
  let before;
  let after;
  try {
    before = loadBaseline(a);
    after = loadBaseline(b);
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : err}`);
    return 2;
  }
  const entries = diffReports(before, after);
  let fixed = 0;
  let added = 0;
  for (const e of entries) {
    if (e.kind === "fixed") {
      console.log(`${e.name}: ${e.before} -> ${e.after} (fixed)`);
      fixed++;
    } else if (e.kind === "new") {
      console.log(`${e.name}: ${e.before} -> ${e.after} (new: ${e.title})`);
      added++;
    } else {
      console.log(`${e.name}: ${e.before} -> ${e.after}`);
    }
  }
  console.log(
    `${fixed} fixed, ${added} new, ${entries.length - fixed - added} unchanged`,
  );
  return 0;
}

async function cmdExplain(flags: GlobalFlags): Promise<number> {
  const target = flags.positional[0];
  if (!target) failUsage("explain needs <pkg>[@<version>]");
  const at = target.lastIndexOf("@");
  const name = (at > 0 ? target.slice(0, at) : target)
    .toLowerCase()
    .replace(/[-_.]+/g, "-");
  const wantVersion = at > 0 ? target.slice(at + 1) : null;
  const client = new PypiClient({ baseUrl: flags.pypiBase });
  try {
    const simple = await client.simpleIndex(name);
    const version =
      wantVersion ?? latestStable(simple.versions.filter(isStable));
    if (!version) {
      console.error(`error: no stable release found for ${name}`);
      return 2;
    }
    const [versionJson, simpleFull] = await Promise.all([
      client.versionJson(name, version),
      client.simpleIndex(name),
    ]);
    void simpleFull;
    const req = {
      name,
      normalized: name,
      specs: [{ op: "==" as const, version }],
      extras: [],
      marker: null,
      raw: `${name}==${version}`,
    };
    const result = await auditPackage(req, client, { allow: new Set() });
    console.log(`${name}==${version}`);
    console.log(`project page: https://pypi.org/project/${name}/${version}/`);
    console.log(
      `security tab: https://pypi.org/project/${name}/${version}/#security`,
    );
    console.log(`JSON API: https://pypi.org/pypi/${name}/${version}/json`);
    console.log(`Simple API: https://pypi.org/simple/${name}/`);
    console.log(`latest stable: ${latestStable(simple.versions) ?? "unknown"}`);
    console.log(
      `license: ${versionJson.info.license_expression ?? versionJson.info.license ?? "none published"}`,
    );
    console.log(
      `yanked: ${versionJson.info.yanked === true ? "yes" : "no"}; vulnerabilities in JSON API: ${(versionJson.vulnerabilities ?? []).length}`,
    );
    console.log(`verdict: ${result.verdict}`);
    for (const f of result.findings) {
      console.log(`  [${f.severity.toUpperCase()}] ${f.title}`);
      console.log(`        ${f.evidence}`);
      console.log(`        source: ${f.source}`);
    }
    if (result.findings.length === 0) console.log("  no findings");
    return result.verdict === "FAIL" ? 1 : 0;
  } catch (err) {
    return networkError(err);
  }
}

function networkError(err: unknown): number {
  if (err instanceof PypiError && err.status === 404) {
    console.error(`error: ${err.message}`);
  } else if (err instanceof Error) {
    console.error(`error: ${err.message}`);
  } else {
    console.error(`error: ${String(err)}`);
  }
  return 2;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(usage());
    return 0;
  }
  if (args[0] === "--version" || args[0] === "-V") {
    console.log(`depsignal ${VERSION}`);
    return 0;
  }
  const [command, ...rest] = args;
  const flags = parseFlags(rest);
  switch (command) {
    case "audit":
      return cmdAudit(flags);
    case "check":
      return cmdCheck(flags);
    case "diff":
      return cmdDiff(flags);
    case "explain":
      return cmdExplain(flags);
    default:
      failUsage(`unknown command: ${command}`);
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`error: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  });
