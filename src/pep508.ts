/**
 * PEP 508 requirement parsing for requirements.txt and pyproject.toml.
 * Environment markers are honoured for the common cases (python_version,
 * sys_platform, os_name, implementation_name, extra): entries whose
 * marker does not match this runtime are skipped and reported, never
 * silently audited.
 */
import { parseSpecifiers, type Specifier } from "./version.js";

export interface Requirement {
  name: string;
  normalized: string;
  specs: Specifier[];
  extras: string[];
  marker: string | null;
  /** True when the requirement was skipped because its marker did not match. */
  skippedByMarker?: boolean;
  raw: string;
}

export function normalizeName(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

const NAME_RE = /^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$/;

/** Parse one requirement line (no comments, no options). Returns null on failure. */
export function parseRequirement(line: string): Requirement | null {
  const raw = line.trim();
  if (!raw) return null;
  // Split off the environment marker.
  let main = raw;
  let marker: string | null = null;
  const semi = raw.indexOf(";");
  if (semi !== -1) {
    main = raw.slice(0, semi).trim();
    marker = raw.slice(semi + 1).trim();
  }
  // Extras: name[extra1,extra2]
  let extras: string[] = [];
  let rest = main;
  const bracket = main.indexOf("[");
  if (bracket !== -1) {
    const close = main.indexOf("]", bracket);
    if (close === -1) return null;
    extras = main
      .slice(bracket + 1, close)
      .split(",")
      .map((e) => e.trim())
      .filter(Boolean);
    rest = main.slice(0, bracket).trim() + main.slice(close + 1).trim();
  }
  // Name is the leading run; the remainder is the specifier set.
  const m = rest.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$/);
  if (!m || !NAME_RE.test(m[1])) return null;
  const specs = m[2] ? parseSpecifiers(m[2]) : [];
  if (specs === null) return null;
  return {
    name: m[1],
    normalized: normalizeName(m[1]),
    specs,
    extras,
    marker,
    raw,
  };
}

export interface MarkerEnv {
  python_version: string;
  sys_platform: string;
  os_name: string;
  implementation_name: string;
  extra: string;
}

export function currentMarkerEnv(): MarkerEnv {
  const v = process.version.replace(/^v/, "").split(".");
  return {
    python_version: `${v[0]}.${v[1] ?? "0"}`,
    sys_platform: process.platform === "win32" ? "win32" : process.platform,
    os_name: process.platform === "win32" ? "nt" : "posix",
    implementation_name: "cpython",
    extra: "",
  };
}

function evalMarkerAtom(atom: string, env: MarkerEnv): boolean | null {
  // name op "value"  (or 'value')
  const m = atom.match(
    /^([a-z_]+)\s*(==|!=|>=|<=|>|<|~=|in|not in)\s*['"]([^'"]*)['"]$/,
  );
  if (!m) return null;
  const key = m[1] as keyof MarkerEnv;
  const value = env[key];
  if (value === undefined) return null;
  const op = m[2];
  const rhs = m[3];
  if (op === "in") return value.includes(rhs);
  if (op === "not in") return !value.includes(rhs);
  // python_version compares numerically segment by segment.
  if (key === "python_version") {
    const cmp = compareDotted(value, rhs);
    switch (op) {
      case "==":
        return cmp === 0;
      case "!=":
        return cmp !== 0;
      case ">=":
        return cmp >= 0;
      case "<=":
        return cmp <= 0;
      case ">":
        return cmp > 0;
      case "<":
        return cmp < 0;
      default:
        return null;
    }
  }
  switch (op) {
    case "==":
      return value === rhs;
    case "!=":
      return value !== rhs;
    case ">=":
      return value >= rhs;
    case "<=":
      return value <= rhs;
    case ">":
      return value > rhs;
    case "<":
      return value < rhs;
    default:
      return null;
  }
}

function compareDotted(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Evaluate a PEP 508 marker. Returns true/false, or null when the marker
 * uses syntax we do not understand (caller treats null as "cannot decide"
 * and audits the requirement rather than skipping it silently).
 */
export function evalMarker(
  marker: string,
  env: MarkerEnv = currentMarkerEnv(),
): boolean | null {
  // Split on top-level "and"/"or" (parentheses are not supported; an
  // unsupported marker returns null).
  if (marker.includes("(") || marker.includes(")")) return null;
  const orParts = marker.split(/\s+or\s+/);
  let sawAtom = false;
  for (const orPart of orParts) {
    const andParts = orPart.split(/\s+and\s+/);
    let andResult: boolean | null = true;
    for (const atom of andParts) {
      const r = evalMarkerAtom(atom.trim(), env);
      if (r === null) return null;
      sawAtom = true;
      andResult = (andResult as boolean) && r;
    }
    if (andResult === true) return true;
  }
  return sawAtom ? false : null;
}

export interface ParseInputResult {
  requirements: Requirement[];
  skipped: string[];
  notes: string[];
}

/** Parse a requirements.txt document. */
export function parseRequirementsText(text: string): ParseInputResult {
  const requirements: Requirement[] = [];
  const skipped: string[] = [];
  const notes: string[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("-")) {
      notes.push(`skipped option line (not followed in v0.1.0): ${line}`);
      continue;
    }
    const commentCut = line.indexOf(" #");
    const clean = (commentCut === -1 ? line : line.slice(0, commentCut)).trim();
    const req = parseRequirement(clean);
    if (!req) {
      notes.push(`unparseable line skipped: ${line}`);
      continue;
    }
    if (req.marker) {
      const ok = evalMarker(req.marker);
      if (ok === false) {
        skipped.push(`${req.name} (marker did not match: ${req.marker})`);
        continue;
      }
      if (ok === null) {
        notes.push(
          `marker not understood, audited anyway: ${req.name} (${req.marker})`,
        );
      }
    }
    requirements.push(req);
  }
  return { requirements, skipped, notes };
}

/**
 * Minimal TOML reader for pyproject.toml [project] dependencies:
 * finds `dependencies = [...]` and returns the quoted strings.
 * Full TOML is out of scope for a zero-dependency CLI; anything we
 * cannot parse is reported as an error by the caller.
 */
export function parsePyprojectText(text: string): ParseInputResult {
  const requirements: Requirement[] = [];
  const skipped: string[] = [];
  const notes: string[] = [];
  const lines = text.split("\n");
  let inProject = false;
  let depBlock: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const section = line.match(/^\[([^\]]+)\]$/);
    if (section) {
      inProject = section[1].trim() === "project";
      continue;
    }
    if (!inProject) continue;
    const depMatch = line.match(/^dependencies\s*=\s*(.*)$/);
    if (depMatch) {
      depBlock = depMatch[1];
      if (!depBlock.includes("]")) {
        // Multi-line array: keep consuming lines until the closing bracket.
        while (i + 1 < lines.length && !depBlock.includes("]")) {
          i++;
          depBlock += "\n" + lines[i];
        }
      }
    }
  }
  if (depBlock === null) {
    notes.push("no [project] dependencies found in pyproject.toml");
    return { requirements, skipped, notes };
  }
  const strings = [...depBlock.matchAll(/"([^"]*)"|'([^']*)'/g)].map(
    (m) => m[1] ?? m[2],
  );
  if (strings.length === 0) {
    notes.push("dependencies array parsed but contained no strings");
    return { requirements, skipped, notes };
  }
  for (const s of strings) {
    const req = parseRequirement(s);
    if (!req) {
      notes.push(`unparseable dependency skipped: ${s}`);
      continue;
    }
    if (req.marker) {
      const ok = evalMarker(req.marker);
      if (ok === false) {
        skipped.push(`${req.name} (marker did not match: ${req.marker})`);
        continue;
      }
      if (ok === null) {
        notes.push(
          `marker not understood, audited anyway: ${req.name} (${req.marker})`,
        );
      }
    }
    requirements.push(req);
  }
  return { requirements, skipped, notes };
}
