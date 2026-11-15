/**
 * Live smoke test: real PyPI, soft-skip on any network failure.
 * Never hard-fails CI because PyPI is down or slow.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url)) + "/..";
const CLI = join(ROOT, "dist", "cli.js");

function liveAudit(t, content) {
  const dir = mkdtempSync(join(tmpdir(), "depsignal-live-"));
  const path = join(dir, "requirements.txt");
  writeFileSync(path, content);
  const r = spawnSync(process.execPath, [CLI, "audit", path], {
    encoding: "utf8",
    timeout: 60000,
  });
  if (
    r.status === 2 ||
    r.error ||
    /network error|rate-limited|timed out/i.test(r.stderr + r.stdout)
  ) {
    t.skip(`live PyPI unavailable (${(r.stderr || "").trim().slice(0, 120)})`);
    return null;
  }
  return r;
}

test("live: django==4.2 shows the GHSA-r3xc-prgr-mg9p vuln", (t) => {
  const r = liveAudit(t, "django==4.2\n");
  if (!r) return;
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /GHSA-r3xc-prgr-mg9p/);
  assert.match(r.stdout, /fixed in 4\.2\.1/);
});

test("live: pillow latest has no vulnerability and full provenance", (t) => {
  const r = liveAudit(t, "pillow\n");
  if (!r) return;
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /pillow\s+\S+\s+PASS/);
});
