/** E2E tests: real CLI against the local fixture server (recorded payloads). */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startFixtureServer } from "./fixture-server.js";

const ROOT = dirname(fileURLToPath(import.meta.url)) + "/..";
const CLI = join(ROOT, "dist", "cli.js");

let baseUrl;
let server;

test.before(async () => {
  ({ server, baseUrl } = await startFixtureServer());
});

test.after(() => {
  server.closeAllConnections();
  server.close();
});

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// NOTE: async spawn (not spawnSync) - the fixture server lives in this
// process, so a synchronous wait would deadlock the event loop.
async function run(args, cwd) {
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      [CLI, ...args, "--pypi-base", baseUrl],
      { cwd: cwd ?? ROOT, encoding: "utf8", timeout: 60000 },
    );
    return { status: 0, stdout, stderr };
  } catch (err) {
    return {
      status: typeof err.code === "number" ? err.code : 2,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

function tmpReq(content, name = "requirements.txt") {
  const dir = mkdtempSync(join(tmpdir(), "depsignal-e2e-"));
  const path = join(dir, name);
  writeFileSync(path, content);
  return { dir, path };
}

test("audit django==4.2 (recorded): FAIL, GHSA-r3xc-prgr-mg9p fixed in 4.2.1", async () => {
  const { path } = tmpReq("django==4.2\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /GHSA-r3xc-prgr-mg9p/);
  assert.match(r.stdout, /fixed in 4\.2\.1/);
  assert.match(r.stdout, /CVE-2023-31047/);
  assert.match(r.stdout, /verdict: FAIL/);
});

test("audit requests==2.34.2 and pillow==13.0.0 (recorded): PASS", async () => {
  const { path } = tmpReq("requests==2.34.2\npillow==13.0.0\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /requests\s+2\.34\.2\s+PASS/);
  assert.match(r.stdout, /pillow\s+13\.0\.0\s+PASS/);
});

test("audit litellm==1.107.0 (recorded fixture): FAIL, Change of Provenance", async () => {
  const { path } = tmpReq("litellm==1.107.0\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /Change of provenance/i);
  assert.match(r.stdout, /none -> full/);
  assert.match(r.stdout, /verdict: FAIL/);
});

test("audit litellm==1.106.2 (recorded): WARN, no provenance, no FAIL", async () => {
  const { path } = tmpReq("litellm==1.106.2\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /litellm\s+1\.106\.2\s+WARN/);
  assert.match(r.stdout, /No build provenance/i);
});

test("audit acme-widget==1.0.0 (synthetic): WARN - partial, late file, stale, license", async () => {
  const { path } = tmpReq("acme-widget==1.0.0\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /acme-widget\s+1\.0\.0\s+WARN/);
  assert.match(r.stdout, /Incomplete provenance/);
  assert.match(r.stdout, /Late file upload/);
  assert.match(r.stdout, /Latest release is old/);
  assert.match(r.stdout, /No license metadata/);
});

test("audit acme-widget==1.1.0 (synthetic): FAIL, yanked", async () => {
  const { path } = tmpReq("acme-widget==1.1.0\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /Pinned version is yanked/);
});

test("audit --json shape", async () => {
  const { path } = tmpReq("django==4.2\n");
  const r = await run(["audit", path, "--json"]);
  assert.equal(r.status, 1);
  const data = JSON.parse(r.stdout);
  assert.equal(data.tool, "depsignal");
  assert.equal(data.version, 1);
  assert.equal(data.packages.length, 1);
  const pkg = data.packages[0];
  assert.equal(pkg.name, "django");
  assert.equal(pkg.pinned, "4.2");
  assert.equal(pkg.verdict, "FAIL");
  assert.ok(pkg.findings.some((f) => f.rule === "vulnerability"));
  assert.ok(pkg.signals.provenance);
});

test("audit --allow suppresses the FAIL (downgraded to WARN)", async () => {
  const { path } = tmpReq("litellm==1.107.0\n");
  const r = await run(["audit", path, "--allow", "litellm"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /allowed/);
});

test("audit unpinned resolves to latest and labels it", async () => {
  const { path } = tmpReq("requests\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /requests\s+2\.34\.2\s+PASS/);
  assert.match(r.stdout, /resolved to latest/);
});

test("audit --limit truncates human output but keeps the verdict", async () => {
  const { path } = tmpReq("django==4.2\n");
  const full = await run(["audit", path, "--json"]);
  const total = JSON.parse(full.stdout).packages[0].findings.length;
  assert.ok(total > 2, `expected several findings, got ${total}`);
  const r = await run(["audit", path, "--limit", "2"]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, new RegExp(`${total} finding\\(s\\)`));
  assert.match(r.stdout, new RegExp(`and ${total - 2} more finding\\(s\\)`));
});

test("audit unknown package: exit 2", async () => {
  const { path } = tmpReq("nosuchpkg-xyz==1.0\n");
  const r = await run(["audit", path]);
  assert.equal(r.status, 2);
  assert.match(r.stderr + r.stdout, /not found/i);
});

test("check/diff flows on baselines", async () => {
  const { dir, path: reqDjango } = tmpReq("django==4.2\n");
  const baselineA = join(dir, "a.json");
  const baselineB = join(dir, "b.json");
  const reqFixed = join(dir, "fixed.txt");
  writeFileSync(reqFixed, "requests==2.34.2\n");

  const save = await run([
    "audit",
    reqDjango,
    "--save-baseline",
    baselineA,
    "--json",
  ]);
  assert.equal(save.status, 1);
  const saved = JSON.parse(readFileSync(baselineA, "utf8"));
  assert.equal(saved.packages[0].verdict, "FAIL");

  // check: same input, no new FAILs -> exit 0
  const checkSame = await run([
    "check",
    "--baseline",
    baselineA,
    "--input",
    reqDjango,
  ]);
  assert.equal(checkSame.status, 0, checkSame.stdout + checkSame.stderr);
  assert.match(checkSame.stdout, /no new FAIL findings/);

  // check: worse input (litellm replay) vs django baseline -> exit 1, new FAIL
  const reqBad = join(dir, "bad.txt");
  writeFileSync(reqBad, "litellm==1.107.0\n");
  const checkBad = await run([
    "check",
    "--baseline",
    baselineA,
    "--input",
    reqBad,
  ]);
  assert.equal(checkBad.status, 1, checkBad.stdout + checkBad.stderr);
  assert.match(checkBad.stdout, /new FAIL finding/);

  // diff: django baseline vs fixed baseline -> every django FAIL finding
  // is fixed (django 4.2 carries several distinct affecting vulns), 0 new
  const saveB = await run([
    "audit",
    reqFixed,
    "--save-baseline",
    baselineB,
    "--json",
  ]);
  assert.equal(saveB.status, 0);
  const diff = await run(["diff", baselineA, baselineB]);
  assert.equal(diff.status, 0, diff.stdout + diff.stderr);
  assert.match(diff.stdout, /django: FAIL -> - \(fixed\)/);
  assert.match(diff.stdout, /fixed, 0 new/);
});

test("pyproject.toml input", async () => {
  const { dir } = tmpReq("", "pyproject.toml");
  const path = join(dir, "pyproject.toml");
  writeFileSync(
    path,
    '[project]\nname = "demo"\ndependencies = [\n  "django==4.2",\n  "requests==2.34.2",\n]\n',
  );
  const r = await run(["audit", path]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /django\s+4\.2\s+FAIL/);
  assert.match(r.stdout, /requests\s+2\.34\.2\s+PASS/);
});

test("explain drills down with source URLs", async () => {
  const r = await run(["explain", "django@4.2"]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /django==4\.2/);
  assert.match(
    r.stdout,
    /security tab: https:\/\/pypi\.org\/project\/django\/4\.2\/#security/,
  );
  assert.match(r.stdout, /GHSA-r3xc-prgr-mg9p/);
});
