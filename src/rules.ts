/**
 * Verdict rules S1-S6 (plus project status) over PyPI JSON + Simple API data.
 *
 * Severity: FAIL blocks CI, WARN is reported but does not fail, INFO is
 * context. One package verdict: FAIL if any FAIL finding, else WARN if
 * any WARN finding, else PASS.
 *
 * Vulnerability matching (S1): PyPI's `fixed_in` lists one fixed version
 * per affected release line (e.g. django: 3.2.19, 4.1.9, 4.2.1). A pinned
 * version is affected when it is below the fixed version of ITS OWN
 * release line (same major.minor). If its line has no fixed version, it
 * is affected only when it is below the lowest fixed version of the same
 * major line. A vuln with no `fixed_in` at all affects every version.
 * Withdrawn advisories are ignored.
 *
 * Provenance change (S2): the Simple API exposes attestation PRESENCE
 * (a provenance URL per file, or null) and no publisher identity, so a
 * change is a change in attestation coverage state (full / partial /
 * none) between the pinned release and the previous stable release.
 * Any change is a FAIL, in either direction: an attestation that appears
 * from a new publisher is exactly the LiteLLM 1.107.0 signal, and an
 * attestation that disappears is a loss. This also flags a project
 * adopting attestations for the first time; use --allow for that case.
 * The finding says which direction it is.
 */
import {
  dedupeVulnerabilities,
  fileVersion,
  provenanceSummary,
  type PypiClient,
  type SimpleFile,
  type Vulnerability,
} from "./pypi.js";
import {
  compareVersions,
  isStable,
  latestSatisfying,
  latestStable,
} from "./version.js";
import type { Requirement } from "./pep508.js";

export type Severity = "fail" | "warn" | "info";
export type Verdict = "PASS" | "WARN" | "FAIL";

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  evidence: string;
  source: string;
  /** Stable key for baseline comparison (package + rule + id). */
  key: string;
}

export interface PackageResult {
  name: string;
  pinned: string;
  resolvedFrom: "pinned" | "latest" | "range";
  verdict: Verdict;
  findings: Finding[];
  signals: {
    vulnerabilities: number;
    provenance: string;
    provenancePrevious: string | null;
    yanked: boolean;
    latestYanked: boolean;
    lateFiles: number;
    latestReleaseAgeDays: number | null;
    license: string | null;
    projectStatus: string | null;
  };
}

export interface AuditOptions {
  allow: Set<string>;
  now?: Date;
}

const LATE_FILE_DAYS = 14;
const LATE_FILE_CUTOFF = "2026-07-01"; // PyPI rejects late files after this date
const STALE_YEARS = 2;

function daysBetween(a: Date, b: Date): number {
  return Math.floor((b.getTime() - a.getTime()) / 86400000);
}

function parseUploadTime(s: string | undefined): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Is `pinned` affected by this vulnerability, per the fixed_in rule above? */
export function vulnAffects(vuln: Vulnerability, pinned: string): boolean {
  if (vuln.withdrawn) return false;
  const fixed = vuln.fixed_in ?? [];
  if (fixed.length === 0) return true;
  const pinnedParts = pinned.split(".");
  const major = Number(pinnedParts[0]);
  const minor = Number(pinnedParts[1] ?? 0);
  const sameLine = fixed.filter((f) => {
    const p = f.split(".");
    return Number(p[0]) === major && Number(p[1] ?? 0) === minor;
  });
  if (sameLine.length > 0) {
    return sameLine.some((f) => (compareVersions(pinned, f) ?? 0) < 0);
  }
  const sameMajor = fixed.filter((f) => Number(f.split(".")[0]) === major);
  if (sameMajor.length > 0) {
    const lowest = sameMajor.reduce((a, b) =>
      (compareVersions(a, b) ?? 0) <= 0 ? a : b,
    );
    return (compareVersions(pinned, lowest) ?? 0) < 0;
  }
  return false;
}

function pickFixedForLine(vuln: Vulnerability, pinned: string): string | null {
  const fixed = vuln.fixed_in ?? [];
  if (fixed.length === 0) return null;
  const pinnedParts = pinned.split(".");
  const major = Number(pinnedParts[0]);
  const minor = Number(pinnedParts[1] ?? 0);
  const sameLine = fixed.filter((f) => {
    const p = f.split(".");
    return Number(p[0]) === major && Number(p[1] ?? 0) === minor;
  });
  const pool = sameLine.length > 0 ? sameLine : fixed;
  return pool.reduce((a, b) => ((compareVersions(a, b) ?? 0) <= 0 ? a : b));
}

export function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "fail")) return "FAIL";
  if (findings.some((f) => f.severity === "warn")) return "WARN";
  return "PASS";
}

function filesForVersion(
  files: SimpleFile[],
  normalizedName: string,
  version: string,
  versions: string[],
): SimpleFile[] {
  return files.filter(
    (f) => fileVersion(f.filename, normalizedName, versions) === version,
  );
}

function earliestUpload(
  files: { upload_time?: string; "upload-time"?: string }[],
): Date | null {
  let best: Date | null = null;
  for (const f of files) {
    const d = parseUploadTime(f.upload_time ?? f["upload-time"]);
    if (d && (!best || d < best)) best = d;
  }
  return best;
}

export async function auditPackage(
  req: Requirement,
  client: PypiClient,
  opts: AuditOptions,
): Promise<PackageResult> {
  const now = opts.now ?? new Date();
  const name = req.normalized;
  const jsonBase = `https://pypi.org/pypi/${name}`;
  const simpleBase = `https://pypi.org/simple/${name}/`;

  // Resolve the version to audit.
  let pinned: string;
  let resolvedFrom: PackageResult["resolvedFrom"];
  const exact = req.specs.find(
    (s) => s.op === "==" && !s.version.endsWith(".*"),
  );
  if (exact) {
    pinned = exact.version;
    resolvedFrom = "pinned";
  } else {
    // Need the version list first.
    const simple = await client.simpleIndex(name);
    const versions = simple.versions;
    if (req.specs.length === 0) {
      const latest = latestStable(versions);
      if (!latest) throw new Error(`no stable release found for ${name}`);
      pinned = latest;
      resolvedFrom = "latest";
    } else {
      const latest = latestSatisfying(versions, req.specs);
      if (!latest) {
        throw new Error(
          `no release of ${name} satisfies ${req.specs.map((s) => s.op + s.version).join(",")}`,
        );
      }
      pinned = latest;
      resolvedFrom = "range";
    }
  }

  const [versionJson, simple] = await Promise.all([
    client.versionJson(name, pinned),
    client.simpleIndex(name),
  ]);

  const findings: Finding[] = [];
  const add = (
    rule: string,
    severity: Severity,
    title: string,
    evidence: string,
    source: string,
    key: string,
  ) => {
    findings.push({ rule, severity, title, evidence, source, key });
  };

  const isAllowed = opts.allow.has(name);

  // ---- S1: vulnerabilities ----
  const vulns = dedupeVulnerabilities(versionJson.vulnerabilities ?? []);
  let vulnCount = 0;
  for (const v of vulns) {
    if (!vulnAffects(v, pinned)) continue;
    vulnCount++;
    const fixed = pickFixedForLine(v, pinned);
    const aliases = (v.aliases ?? []).filter((a) => a !== v.id);
    const evidence = fixed
      ? `${v.id} affects ${pinned} (fixed in ${fixed})`
      : `${v.id} affects ${pinned} (no fixed version published)`;
    add(
      "vulnerability",
      "fail",
      `Known vulnerability ${v.id}`,
      aliases.length > 0
        ? `${evidence}; also known as ${aliases.join(", ")}`
        : evidence,
      v.link || `https://osv.dev/vulnerability/${v.id}`,
      `vulnerability:${v.id}`,
    );
  }

  // ---- S2: provenance ----
  const pinnedFiles = filesForVersion(
    simple.files,
    name,
    pinned,
    simple.versions,
  );
  const prov = provenanceSummary(pinnedFiles);
  const stableVersions = simple.versions
    .filter(isStable)
    .sort((a, b) => compareVersions(a, b) ?? 0);
  // Previous stable release WITH files in this index (the index may be
  // a trimmed recorded fixture; a release with no files cannot be compared).
  let prevStable: string | null = null;
  let prevFiles: SimpleFile[] = [];
  for (const v of [...stableVersions]
    .reverse()
    .filter((v) => (compareVersions(v, pinned) ?? 0) < 0)) {
    const files = filesForVersion(simple.files, name, v, simple.versions);
    if (files.length > 0) {
      prevStable = v;
      prevFiles = files;
      break;
    }
  }
  let prevState: string | null = null;
  if (prevStable) {
    prevState = provenanceSummary(prevFiles).state;
    if (prevState !== prov.state) {
      const direction =
        prov.state === "none"
          ? "attestations lost"
          : prevState === "none"
            ? "attestations appeared from a previously unattested release"
            : `coverage changed (${prevState} -> ${prov.state})`;
      add(
        "provenance-change",
        "fail",
        "Change of provenance vs previous release",
        `Provenance state changed ${prevState} -> ${prov.state} between ${prevStable} and ${pinned}: ${direction}. Provenance alone cannot prove the new publisher is the same as the old one.`,
        simpleBase,
        "provenance-change",
      );
    }
  }
  if (prov.state === "none") {
    add(
      "provenance-none",
      "warn",
      "No build provenance published",
      `None of ${prov.total} file(s) of ${pinned} carry a provenance attestation, so the build origin is unverifiable. This is not a malware flag on its own.`,
      simpleBase,
      "provenance-none",
    );
  } else if (prov.state === "partial") {
    add(
      "provenance-partial",
      "warn",
      "Incomplete provenance",
      `Only ${prov.attested} of ${prov.total} file(s) of ${pinned} carry a provenance attestation.`,
      simpleBase,
      "provenance-partial",
    );
  }

  // ---- S3: yanked ----
  const yankedInfo = versionJson.info.yanked;
  const yankedFiles = (versionJson.urls ?? []).some(
    (u) => u.yanked === true || u.yanked === "true",
  );
  const yanked = yankedInfo === true || yankedInfo === "true" || yankedFiles;
  if (yanked) {
    add(
      "yanked",
      "fail",
      "Pinned version is yanked",
      `${name} ${pinned} is yanked on PyPI and should not be installed.`,
      `${jsonBase}/${pinned}/json`,
      "yanked",
    );
  }
  const latest = latestStable(simple.versions);
  let latestYanked = false;
  if (latest && latest !== pinned) {
    const latestFiles = filesForVersion(
      simple.files,
      name,
      latest,
      simple.versions,
    );
    latestYanked = latestFiles.some(
      (u) => u.yanked === true || u.yanked === "true",
    );
    if (latestYanked) {
      add(
        "latest-yanked",
        "warn",
        "Latest release is yanked",
        `The latest stable release ${latest} is yanked; the pinned version ${pinned} is not, but the project may be in trouble.`,
        `${jsonBase}/${latest}/json`,
        "latest-yanked",
      );
    }
  }

  // ---- S4: late files ----
  let lateFiles = 0;
  if (pinnedFiles.length > 0) {
    const first = earliestUpload(pinnedFiles);
    if (first && first.toISOString().slice(0, 10) < LATE_FILE_CUTOFF) {
      for (const f of pinnedFiles) {
        const up = parseUploadTime(f["upload-time"]);
        if (up && daysBetween(first, up) > LATE_FILE_DAYS) lateFiles++;
      }
      if (lateFiles > 0) {
        add(
          "late-file",
          "warn",
          "Late file upload",
          `${lateFiles} file(s) of ${pinned} were uploaded more than ${LATE_FILE_DAYS} days after the release's first file. Files added long after release day are a PyPI Security-tab warning.`,
          simpleBase,
          "late-file",
        );
      }
    }
  }

  // ---- S5: staleness ----
  let latestAgeDays: number | null = null;
  if (latest) {
    const latestFiles = filesForVersion(
      simple.files,
      name,
      latest,
      simple.versions,
    );
    const first = earliestUpload(latestFiles);
    if (first) {
      latestAgeDays = daysBetween(first, now);
      if (latestAgeDays > STALE_YEARS * 365) {
        add(
          "stale",
          "warn",
          "Latest release is old",
          `Latest stable release ${latest} was published ${Math.floor(latestAgeDays / 365)} year(s) ago (${first.toISOString().slice(0, 10)}). Stability is not abandonment, but check the project is still maintained.`,
          `${jsonBase}/${latest}/json`,
          "stale",
        );
      }
    }
  }

  // ---- S6: license ----
  const license =
    versionJson.info.license_expression || versionJson.info.license || null;
  if (
    !license ||
    license.trim() === "" ||
    license.trim().toUpperCase() === "UNKNOWN"
  ) {
    add(
      "license",
      "warn",
      "No license metadata",
      `${name} ${pinned} publishes no license metadata on PyPI.`,
      `${jsonBase}/${pinned}/json`,
      "license",
    );
  }

  // ---- S7: project status (observed, not claimed) ----
  const projectStatus = simple.projectStatus;
  if (projectStatus && projectStatus !== "active") {
    add(
      "project-status",
      "warn",
      `Project status is "${projectStatus}"`,
      `PyPI reports project status "${projectStatus}" for ${name}. Check the Security tab on the project page for archived or quarantined state.`,
      simpleBase,
      "project-status",
    );
  }

  // --allow suppresses FAIL findings for this package (reported, not hidden).
  let finalFindings = findings;
  if (isAllowed) {
    finalFindings = findings.map((f) =>
      f.severity === "fail"
        ? { ...f, severity: "warn" as Severity, title: `${f.title} (allowed)` }
        : f,
    );
  }

  return {
    name,
    pinned,
    resolvedFrom,
    verdict: verdictOf(finalFindings),
    findings: finalFindings,
    signals: {
      vulnerabilities: vulnCount,
      provenance: prov.state,
      provenancePrevious: prevState,
      yanked,
      latestYanked,
      lateFiles,
      latestReleaseAgeDays: latestAgeDays,
      license: license && license.trim() !== "" ? license : null,
      projectStatus,
    },
  };
}

export interface AuditReport {
  version: 1;
  tool: "depsignal";
  checkedAt: string;
  packages: PackageResult[];
  skipped: string[];
  notes: string[];
}

export async function auditRequirements(
  reqs: Requirement[],
  client: PypiClient,
  opts: AuditOptions,
  meta: { skipped: string[]; notes: string[] },
): Promise<AuditReport> {
  const packages: PackageResult[] = [];
  for (const req of reqs) {
    packages.push(await auditPackage(req, client, opts));
  }
  return {
    version: 1,
    tool: "depsignal",
    checkedAt: (opts.now ?? new Date()).toISOString(),
    packages,
    skipped: meta.skipped,
    notes: meta.notes,
  };
}

// Re-exported for the CLI's explain command.
export type { Requirement };
