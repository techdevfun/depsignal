/**
 * PyPI client: JSON API + Simple API v1.4, public data only, no auth.
 *
 * Observed facts (verified 15 November 2026 against live PyPI):
 * - JSON API `https://pypi.org/pypi/<name>/<version>/json` carries
 *   top-level `vulnerabilities` (OSV entries: id, aliases, fixed_in,
 *   link, withdrawn), `info.yanked`, `info.license`,
 *   `info.license_expression`, and `releases` with per-file `yanked`
 *   and `upload_time`.
 * - Simple API v1.4 (`Accept: application/vnd.pypi.simple.v1+json`)
 *   file entries carry `provenance` (a URL string, or null), `upload-time`,
 *   `yanked` and `hashes`. Files carry NO version field: the version is
 *   recovered by matching the filename against the `versions` list.
 * - `provenance` is a URL like
 *   https://pypi.org/integrity/<name>/<version>/<file>/provenance
 *   pointing at Sigstore attestation bundles. The Simple API exposes
 *   NO repository identity: the publisher identity lives inside the
 *   Sigstore certificate, which this CLI does not decode. So provenance
 *   change detection compares attestation PRESENCE between releases
 *   (attested vs unattested), and says so in the finding.
 * - Simple API top level also carries `project-status` (e.g. "active").
 */
export interface JsonFile {
  filename: string;
  url: string;
  yanked: boolean | string;
  upload_time?: string;
  upload_time_iso_8601?: string;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  fixed_in: string[];
  link: string;
  withdrawn: string | null;
  details?: string;
}

export interface VersionJson {
  info: {
    name: string;
    version: string;
    yanked: boolean | string;
    license: string | null;
    license_expression: string | null;
    summary?: string;
    home_page?: string;
    project_urls?: Record<string, string>;
  };
  vulnerabilities: Vulnerability[];
  urls: JsonFile[];
  /** Present on project JSON only; version JSON omits it. */
  releases?: Record<string, JsonFile[]>;
  last_serial?: number;
}

export interface SimpleFile {
  filename: string;
  url: string;
  hashes: Record<string, string>;
  provenance: string | null;
  "upload-time": string;
  yanked: boolean | string;
  "requires-python": string | null;
}

export interface SimpleIndex {
  name: string;
  versions: string[];
  files: SimpleFile[];
  projectStatus: string | null;
}

export interface PypiClientOptions {
  baseUrl: string; // default https://pypi.org
  timeoutMs?: number;
  retries?: number;
}

export class PypiError extends Error {
  status: number | null;
  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "PypiError";
    this.status = status;
  }
}

const JSON_HEADERS = { Accept: "application/json" };
const SIMPLE_HEADERS = {
  Accept: "application/vnd.pypi.simple.v1+json",
};

async function fetchJson(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
  retries: number,
): Promise<unknown> {
  let lastError: Error | null = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { headers, signal: controller.signal });
      if (res.status === 404) {
        throw new PypiError(`not found on PyPI: ${url}`, 404);
      }
      if (res.status === 429) {
        // Back off once; PyPI rate limits are transient. Never hammer.
        if (attempt < retries) {
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        throw new PypiError(`PyPI rate-limited (429) for ${url}`, 429);
      }
      if (!res.ok) {
        throw new PypiError(
          `PyPI returned ${res.status} for ${url}`,
          res.status,
        );
      }
      return (await res.json()) as unknown;
    } catch (err) {
      if (err instanceof PypiError) throw err;
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000));
      }
    } finally {
      clearTimeout(timer);
    }
  }
  throw new PypiError(
    `network error fetching ${url}: ${lastError?.message ?? "unknown"}`,
    null,
  );
}

export class PypiClient {
  private baseUrl: string;
  private timeoutMs: number;
  private retries: number;

  constructor(opts: PypiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.timeoutMs = opts.timeoutMs ?? 10000;
    this.retries = opts.retries ?? 1;
  }

  async versionJson(name: string, version: string): Promise<VersionJson> {
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
    const data = (await fetchJson(
      url,
      JSON_HEADERS,
      this.timeoutMs,
      this.retries,
    )) as VersionJson;
    return data;
  }

  async projectJson(name: string): Promise<VersionJson> {
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(name)}/json`;
    const data = (await fetchJson(
      url,
      JSON_HEADERS,
      this.timeoutMs,
      this.retries,
    )) as VersionJson;
    return data;
  }

  async simpleIndex(name: string): Promise<SimpleIndex> {
    const url = `${this.baseUrl}/simple/${encodeURIComponent(name)}/`;
    const data = (await fetchJson(
      url,
      SIMPLE_HEADERS,
      this.timeoutMs,
      this.retries,
    )) as {
      name: string;
      versions: string[];
      files: SimpleFile[];
      "project-status"?: { status?: string };
    };
    return {
      name: data.name,
      versions: data.versions ?? [],
      files: data.files ?? [],
      projectStatus: data["project-status"]?.status ?? null,
    };
  }
}

/** Recover the version of a Simple API file from its filename. */
export function fileVersion(
  filename: string,
  normalizedName: string,
  versions: string[],
): string | null {
  // Distribution filenames preserve the project's original capitalisation
  // ("Django-4.2.tar.gz"); compare case-insensitively.
  const lower = filename.toLowerCase();
  const prefix = `${normalizedName}-`;
  if (!lower.startsWith(prefix)) return null;
  const rest = lower.slice(prefix.length);
  // Longest version first so "1.10.0" wins over "1.1".
  const sorted = [...versions].sort((a, b) => b.length - a.length);
  for (const v of sorted) {
    if (rest === v || rest.startsWith(`${v}-`) || rest.startsWith(`${v}.`)) {
      return v;
    }
  }
  return null;
}

export type ProvenanceState = "full" | "partial" | "none";

export interface ProvenanceSummary {
  state: ProvenanceState;
  total: number;
  attested: number;
}

/** Classify attestation coverage of one release's files. */
export function provenanceSummary(files: SimpleFile[]): ProvenanceSummary {
  const total = files.length;
  const attested = files.filter(
    (f) => f.provenance !== null && f.provenance !== "",
  ).length;
  const state: ProvenanceState =
    total === 0
      ? "none"
      : attested === 0
        ? "none"
        : attested === total
          ? "full"
          : "partial";
  return { state, total, attested };
}

/**
 * Deduplicate the JSON API vulnerability list. PyPI returns the same
 * advisory twice under different ids (e.g. GHSA-... and PYSEC-...)
 * with each id listed in the other's aliases. Group entries that
 * share an id/alias and keep the first.
 */
export function dedupeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  const out: Vulnerability[] = [];
  const seen = new Set<string>();
  for (const v of vulns) {
    const keys = [v.id, ...(v.aliases ?? [])].map((s) => s.toUpperCase());
    if (keys.some((k) => seen.has(k))) continue;
    for (const k of keys) seen.add(k);
    out.push(v);
  }
  return out;
}
