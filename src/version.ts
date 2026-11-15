/**
 * Minimal PEP 440-ish version parsing and comparison.
 *
 * Covers the version shapes seen on PyPI: epochs (1!2.0), release
 * segments, pre-releases (a/b/rc/alpha/beta/pre/preview), post
 * releases (.post1) and dev releases (.dev1). Ordering follows PEP 440:
 * dev < pre < final < post; within pre-releases a < b < rc.
 * This is a comparator for security gating, not a full PEP 440
 * implementation: local versions (+local) compare equal on the public
 * part and sort after it, which is enough for fixed_in matching.
 */

export interface ParsedVersion {
  epoch: number;
  release: number[];
  pre: { kind: "a" | "b" | "rc"; n: number } | null;
  post: number | null;
  dev: number | null;
  local: string | null;
  raw: string;
}

const PRE_ALIASES: Record<string, "a" | "b" | "rc"> = {
  a: "a",
  alpha: "a",
  b: "b",
  beta: "b",
  c: "rc",
  rc: "rc",
  pre: "rc",
  preview: "rc",
};

export function parseVersion(raw: string): ParsedVersion | null {
  const input = raw.trim();
  if (!input) return null;
  // PEP 440 normalisation: separators . _ - are equivalent; case-insensitive.
  let s = input.toLowerCase();
  // PEP 440: a trailing "-N" / "_N" is a post-release ("1.0-1" -> "1.0.post1").
  s = s.replace(/[-_](\d+)$/, ".post$1");
  s = s.replace(/[-_]/g, ".");
  let epoch = 0;
  const bang = s.indexOf("!");
  if (bang !== -1) {
    const e = Number(s.slice(0, bang));
    if (!Number.isInteger(e) || e < 0) return null;
    epoch = e;
    s = s.slice(bang + 1);
  }
  let local: string | null = null;
  const plus = s.indexOf("+");
  if (plus !== -1) {
    local = s.slice(plus + 1);
    s = s.slice(0, plus);
    if (!local) return null;
  }
  let dev: number | null = null;
  const devMatch = s.match(/\.dev(\d*)$/);
  if (devMatch) {
    dev = devMatch[1] === "" ? 0 : Number(devMatch[1]);
    s = s.slice(0, devMatch.index);
  }
  let post: number | null = null;
  const postMatch = s.match(/\.post(\d*)$/);
  if (postMatch) {
    post = postMatch[1] === "" ? 0 : Number(postMatch[1]);
    s = s.slice(0, postMatch.index);
  }
  let pre: ParsedVersion["pre"] = null;
  const preMatch = s.match(/\.(a|alpha|b|beta|c|rc|pre|preview)(\d*)$/);
  if (preMatch) {
    pre = {
      kind: PRE_ALIASES[preMatch[1]],
      n: preMatch[2] === "" ? 0 : Number(preMatch[2]),
    };
    s = s.slice(0, preMatch.index);
  }
  // Also accept "1.0a1" without a dot separator (normalised above only
  // for - and _; "1.0a1" stays "1.0a1").
  if (!pre) {
    const glued = s.match(
      /^(\d+(?:\.\d+)*)(a|alpha|b|beta|c|rc|pre|preview)(\d*)$/,
    );
    if (glued) {
      pre = {
        kind: PRE_ALIASES[glued[2]],
        n: glued[3] === "" ? 0 : Number(glued[3]),
      };
      s = glued[1];
    }
  }
  const parts = s.split(".");
  if (parts.some((p) => p === "" || !/^\d+$/.test(p))) return null;
  return {
    epoch,
    release: parts.map(Number),
    pre,
    post,
    dev,
    local,
    raw: input,
  };
}

/** Compare two parsed versions: -1, 0 or 1. */
export function compareParsed(a: ParsedVersion, b: ParsedVersion): number {
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    const x = a.release[i] ?? 0;
    const y = b.release[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  // dev releases sort before their base version (even before pre-releases).
  if (a.dev !== null || b.dev !== null) {
    if (a.dev === null) return 1;
    if (b.dev === null) return -1;
    if (a.dev !== b.dev) return a.dev < b.dev ? -1 : 1;
  }
  // pre < final < post
  const rank = (v: ParsedVersion): number =>
    v.pre ? 0 : v.post !== null ? 2 : 1;
  if (rank(a) !== rank(b)) return rank(a) < rank(b) ? -1 : 1;
  if (a.pre && b.pre) {
    const order = { a: 0, b: 1, rc: 2 } as const;
    if (a.pre.kind !== b.pre.kind)
      return order[a.pre.kind] < order[b.pre.kind] ? -1 : 1;
    if (a.pre.n !== b.pre.n) return a.pre.n < b.pre.n ? -1 : 1;
  }
  if (a.post !== null && b.post !== null && a.post !== b.post)
    return a.post < b.post ? -1 : 1;
  if (a.post !== null && b.post === null) return 1;
  if (a.post === null && b.post !== null) return -1;
  // Local versions sort after the public version.
  if (a.local === null && b.local !== null) return -1;
  if (a.local !== null && b.local === null) return 1;
  return 0;
}

/** Compare two version strings. Returns -1, 0, 1, or null if unparseable. */
export function compareVersions(a: string, b: string): number | null {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return null;
  return compareParsed(pa, pb);
}

export function isStable(v: string): boolean {
  const p = parseVersion(v);
  if (!p) return false;
  return p.pre === null && p.dev === null;
}

export interface Specifier {
  op: "==" | "!=" | ">=" | "<=" | ">" | "<" | "~=" | "===";
  version: string;
}

/** Parse a comma-separated PEP 508 specifier set. */
export function parseSpecifiers(text: string): Specifier[] | null {
  const out: Specifier[] = [];
  for (const part of text.split(",")) {
    const t = part.trim();
    if (!t) continue;
    const m = t.match(/^(===|==|~=|!=|>=|<=|>|<)\s*(.+)$/);
    if (!m) return null;
    out.push({ op: m[1] as Specifier["op"], version: m[2].trim() });
  }
  return out;
}

/** Does `version` satisfy every specifier in `specs`? */
export function satisfies(version: string, specs: Specifier[]): boolean {
  for (const s of specs) {
    if (s.op === "===") {
      if (version !== s.version) return false;
      continue;
    }
    if (s.op === "==") {
      // "==" with a trailing .* prefix match, e.g. ==4.2.*
      if (s.version.endsWith(".*")) {
        const prefix = s.version.slice(0, -2);
        const pv = parseVersion(version);
        const pp = parseVersion(prefix);
        if (!pv || !pp) return false;
        for (let i = 0; i < pp.release.length; i++) {
          if ((pv.release[i] ?? 0) !== pp.release[i]) return false;
        }
        if (pv.pre !== null || pv.dev !== null) return false;
        continue;
      }
      const c = compareVersions(version, s.version);
      if (c === null || c !== 0) return false;
      continue;
    }
    const c = compareVersions(version, s.version);
    if (c === null) return false;
    switch (s.op) {
      case "!=":
        if (c === 0) return false;
        break;
      case ">=":
        if (c < 0) return false;
        break;
      case "<=":
        if (c > 0) return false;
        break;
      case ">":
        if (c <= 0) return false;
        break;
      case "<":
        if (c >= 0) return false;
        break;
      case "~=": {
        // Compatible release: >= V, == V.* (all but last segment).
        if (c < 0) return false;
        const pv = parseVersion(version);
        const pp = parseVersion(s.version);
        if (!pv || !pp) return false;
        const prefix = pp.release.slice(0, -1);
        for (let i = 0; i < prefix.length; i++) {
          if ((pv.release[i] ?? 0) !== prefix[i]) return false;
        }
        break;
      }
    }
  }
  return true;
}

/** Latest stable version from a list that satisfies `specs` (null = none). */
export function latestSatisfying(
  versions: string[],
  specs: Specifier[],
): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (!isStable(v)) continue;
    if (!satisfies(v, specs)) continue;
    if (best === null || (compareVersions(v, best) ?? 0) > 0) best = v;
  }
  return best;
}

/** Latest stable version overall (null = none). */
export function latestStable(versions: string[]): string | null {
  return latestSatisfying(versions, []);
}
