/** Unit tests: pure functions only, no network. */
import test from "node:test";
import assert from "node:assert/strict";
import {
  compareVersions,
  isStable,
  latestSatisfying,
  latestStable,
  parseSpecifiers,
  parseVersion,
  satisfies,
} from "../dist/version.js";
import {
  evalMarker,
  parsePyprojectText,
  parseRequirement,
  parseRequirementsText,
} from "../dist/pep508.js";
import {
  dedupeVulnerabilities,
  fileVersion,
  provenanceSummary,
} from "../dist/pypi.js";
import { vulnAffects, verdictOf } from "../dist/rules.js";
import { diffReports, newFailFindings } from "../dist/baseline.js";

test("version compare: release segments", () => {
  assert.equal(compareVersions("4.2", "4.2.1"), -1);
  assert.equal(compareVersions("4.2.1", "4.2"), 1);
  assert.equal(compareVersions("4.2", "4.2.0"), 0);
  assert.equal(compareVersions("1.10.0", "1.9.9"), 1);
  assert.equal(compareVersions("2!1.0", "1!9.9"), 1);
  assert.equal(compareVersions("1.0", "1.0"), 0);
});

test("version compare: pre/post/dev ordering (PEP 440)", () => {
  assert.equal(compareVersions("1.0a1", "1.0"), -1);
  assert.equal(compareVersions("1.0a1", "1.0b1"), -1);
  assert.equal(compareVersions("1.0b2", "1.0rc1"), -1);
  assert.equal(compareVersions("1.0rc1", "1.0"), -1);
  assert.equal(compareVersions("1.0", "1.0.post1"), -1);
  assert.equal(compareVersions("1.0.post1", "1.0.post2"), -1);
  assert.equal(compareVersions("1.0.dev1", "1.0"), -1);
  assert.equal(compareVersions("1.0.dev1", "1.0a1"), -1);
  assert.equal(compareVersions("1.0alpha1", "1.0a2"), -1);
  assert.equal(compareVersions("1.0-1", "1.0"), 1); // "1.0-1" normalises to 1.0.post1
  assert.equal(compareVersions("1.0-1", "1.0.1"), -1); // post sorts after the .1 release
});

test("version parse: bad input returns null", () => {
  assert.equal(parseVersion(""), null);
  assert.equal(parseVersion("abc"), null);
  assert.equal(parseVersion("1..2"), null);
  assert.equal(compareVersions("abc", "1.0"), null);
});

test("isStable and latestStable", () => {
  assert.equal(isStable("1.0"), true);
  assert.equal(isStable("1.0rc1"), false);
  assert.equal(isStable("1.0.dev1"), false);
  assert.equal(latestStable(["1.0", "2.0rc1", "1.5"]), "1.5");
  assert.equal(latestStable(["1.0rc1"]), null);
});

test("specifiers: ==, ranges, ~= and ==", () => {
  const specs = parseSpecifiers(">=1.0,<2.0");
  assert.ok(specs && satisfies("1.5", specs));
  assert.ok(specs && !satisfies("2.0", specs));
  assert.ok(specs && !satisfies("0.9", specs));
  assert.ok(satisfies("4.2.1", parseSpecifiers("==4.2.*")));
  assert.ok(!satisfies("4.3", parseSpecifiers("==4.2.*")));
  assert.ok(satisfies("1.4.2", parseSpecifiers("~=1.4.2")));
  assert.ok(!satisfies("1.5.0", parseSpecifiers("~=1.4.2")));
  assert.ok(satisfies("1.4.9", parseSpecifiers("~=1.4.2")));
  assert.ok(!satisfies("1.0", parseSpecifiers("!=1.0")));
  assert.equal(
    latestSatisfying(["1.0", "1.5", "2.0"], parseSpecifiers(">=1.0,<2.0")),
    "1.5",
  );
  assert.equal(parseSpecifiers("bogus"), null);
});

test("PEP 508: name, extras, specifiers, markers", () => {
  const r = parseRequirement("requests[security]==2.34.2");
  assert.equal(r.name, "requests");
  assert.deepEqual(r.extras, ["security"]);
  assert.deepEqual(r.specs, [{ op: "==", version: "2.34.2" }]);
  assert.equal(parseRequirement("Django==4.2").normalized, "django");
  assert.equal(parseRequirement("bad name!"), null);
  const m = parseRequirement('foo==1.0; python_version < "3.0"');
  assert.equal(m.marker, 'python_version < "3.0"');
});

test("markers: match and skip", () => {
  assert.equal(
    evalMarker('python_version >= "3.8"', {
      python_version: "20.24",
      sys_platform: "linux",
      os_name: "posix",
      implementation_name: "cpython",
      extra: "",
    }),
    true,
  );
  assert.equal(evalMarker('sys_platform == "win32"'), false);
  assert.equal(
    evalMarker('python_version >= "3.8" and sys_platform == "linux"'),
    true,
  );
  assert.equal(
    evalMarker('python_version >= "3.8" or sys_platform == "win32"'),
    true,
  );
  assert.equal(evalMarker('os_name == "nt" or sys_platform == "win32"'), false);
  assert.equal(evalMarker('(python_version >= "3.8")'), null); // parens unsupported -> null
});

test("requirements.txt parsing: comments, options, markers", () => {
  const { requirements, skipped, notes } = parseRequirementsText(
    '# comment\ndjango==4.2\nrequests\n-r other.txt\nfoo==1.0; sys_platform == "win32"\nbad line here!\n',
  );
  assert.deepEqual(
    requirements.map((r) => r.name),
    ["django", "requests"],
  );
  assert.equal(skipped.length, 1);
  assert.ok(notes.some((n) => n.includes("-r other.txt")));
  assert.ok(notes.some((n) => n.includes("unparseable")));
});

test("pyproject.toml parsing", () => {
  const { requirements, notes } = parsePyprojectText(
    '[build-system]\nrequires = ["setuptools"]\n\n[project]\nname = "demo"\ndependencies = [\n  "django==4.2",\n  "requests>=2.0",\n]\n',
  );
  assert.deepEqual(
    requirements.map((r) => r.name),
    ["django", "requests"],
  );
  assert.equal(notes.length, 0);
  const empty = parsePyprojectText('[project]\nname = "x"\n');
  assert.equal(empty.requirements.length, 0);
  assert.ok(empty.notes.length > 0);
});

test("vuln matching: django 4.2 case (GHSA-r3xc-prgr-mg9p)", () => {
  const vuln = {
    id: "GHSA-r3xc-prgr-mg9p",
    aliases: ["CVE-2023-31047", "PYSEC-2023-61"],
    fixed_in: ["3.2.19", "4.1.9", "4.2.1"],
    link: "https://osv.dev/vulnerability/GHSA-r3xc-prgr-mg9p",
    withdrawn: null,
  };
  assert.equal(vulnAffects(vuln, "4.2"), true);
  assert.equal(vulnAffects(vuln, "4.2.1"), false);
  assert.equal(vulnAffects(vuln, "4.2.2"), false);
  assert.equal(vulnAffects(vuln, "4.1.8"), true);
  assert.equal(vulnAffects(vuln, "4.1.9"), false);
  assert.equal(vulnAffects(vuln, "3.2.18"), true);
  assert.equal(vulnAffects(vuln, "3.2.19"), false);
  assert.equal(vulnAffects(vuln, "5.0"), false); // different major line
  assert.equal(vulnAffects({ ...vuln, withdrawn: "2023-06-01" }, "4.2"), false);
  assert.equal(vulnAffects({ ...vuln, fixed_in: [] }, "4.2"), true); // unfixed
  assert.equal(vulnAffects({ ...vuln, fixed_in: ["3.2.19"] }, "3.1.0"), true);
  assert.equal(vulnAffects({ ...vuln, fixed_in: ["3.2.19"] }, "4.2"), false);
});

test("vuln dedupe: GHSA/PYSEC twins collapse", () => {
  const a = {
    id: "GHSA-r3xc-prgr-mg9p",
    aliases: ["CVE-2023-31047", "PYSEC-2023-61"],
    fixed_in: ["4.2.1"],
    link: "",
    withdrawn: null,
  };
  const b = {
    id: "PYSEC-2023-61",
    aliases: ["CVE-2023-31047", "GHSA-r3xc-prgr-mg9p"],
    fixed_in: ["4.2.1"],
    link: "",
    withdrawn: null,
  };
  assert.equal(dedupeVulnerabilities([a, b]).length, 1);
  const other = {
    id: "GHSA-xxxx-yyyy-zzzz",
    aliases: ["CVE-2024-00001"],
    fixed_in: ["2.0"],
    link: "",
    withdrawn: null,
  };
  assert.equal(dedupeVulnerabilities([a, other]).length, 2);
});

test("provenance classification", () => {
  const attested = (n) => ({
    filename: n,
    provenance: "https://example.invalid/p",
  });
  const bare = (n) => ({ filename: n, provenance: null });
  assert.deepEqual(provenanceSummary([attested("a"), attested("b")]), {
    state: "full",
    total: 2,
    attested: 2,
  });
  assert.deepEqual(provenanceSummary([bare("a"), bare("b")]), {
    state: "none",
    total: 2,
    attested: 0,
  });
  assert.deepEqual(provenanceSummary([attested("a"), bare("b")]), {
    state: "partial",
    total: 2,
    attested: 1,
  });
  assert.deepEqual(provenanceSummary([]), {
    state: "none",
    total: 0,
    attested: 0,
  });
});

test("fileVersion recovers versions from filenames", () => {
  const versions = ["1.106.2", "1.107.0", "1.10.0"];
  assert.equal(
    fileVersion("litellm-1.107.0.tar.gz", "litellm", versions),
    "1.107.0",
  );
  assert.equal(
    fileVersion(
      "litellm-1.106.2-cp310-abi3-manylinux_2_28_x86_64.whl",
      "litellm",
      versions,
    ),
    "1.106.2",
  );
  assert.equal(fileVersion("other-1.0.tar.gz", "litellm", versions), null);
  assert.equal(
    fileVersion("pillow-1.10.0-cp311-cp311-win_amd64.whl", "pillow", versions),
    "1.10.0",
  );
  // Distribution filenames keep the project's capitalisation.
  assert.equal(
    fileVersion("Django-4.2.tar.gz", "django", ["4.2", "4.2.1"]),
    "4.2",
  );
});

test("verdictOf", () => {
  const f = (sev) => ({
    rule: "x",
    severity: sev,
    title: "",
    evidence: "",
    source: "",
    key: "x",
  });
  assert.equal(verdictOf([]), "PASS");
  assert.equal(verdictOf([f("warn")]), "WARN");
  assert.equal(verdictOf([f("warn"), f("fail")]), "FAIL");
});

test("baseline diff: new / fixed / unchanged", () => {
  const pkg = (name, verdict, keys) => ({
    name,
    pinned: "1.0",
    resolvedFrom: "pinned",
    verdict,
    findings: keys.map((k) => ({
      rule: k,
      severity: "fail",
      title: k,
      evidence: "",
      source: "",
      key: k,
    })),
    signals: {},
  });
  const before = {
    version: 1,
    tool: "depsignal",
    checkedAt: "2026-11-15T00:00:00.000Z",
    packages: [pkg("a", "FAIL", ["vulnerability:X"]), pkg("b", "PASS", [])],
    skipped: [],
    notes: [],
  };
  const after = {
    version: 1,
    tool: "depsignal",
    checkedAt: "2026-11-15T00:00:00.000Z",
    packages: [pkg("a", "PASS", []), pkg("b", "FAIL", ["yanked"])],
    skipped: [],
    notes: [],
  };
  const diff = diffReports(before, after);
  assert.equal(
    diff.find((d) => d.kind === "fixed" && d.name === "a").rule,
    "vulnerability:X",
  );
  assert.equal(
    diff.find((d) => d.kind === "new" && d.name === "b").rule,
    "yanked",
  );
  assert.equal(newFailFindings(before, after).length, 1);
  assert.equal(newFailFindings(before, after)[0].name, "b");
});
