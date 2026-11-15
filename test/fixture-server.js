/**
 * Fixture server: serves recorded PyPI payloads from test/fixtures
 * under the same paths as pypi.org, so e2e tests and the demo replay
 * run offline. For litellm, the recorded 1.106.2 Simple payload is
 * merged with the reconstructed 1.107.0 payload (labelled in the file).
 */
import { createServer } from "node:http";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures");

function loadJson(name) {
  const data = JSON.parse(readFileSync(join(FIX, name), "utf8"));
  delete data._fixture;
  return data;
}

function simpleFor(name) {
  if (name === "litellm") {
    const base = loadJson("litellm.simple.json");
    const extra = loadJson("litellm-1.107.0.simple.json");
    const versions = [...new Set([...base.versions, ...extra.versions])];
    return { ...base, versions, files: [...base.files, ...extra.files] };
  }
  return loadJson(`${name}.simple.json`);
}

function versionJsonFor(name, version) {
  // Exact version file, else fall back to the newest recorded version file.
  try {
    return loadJson(`${name}-${version}.json`);
  } catch {
    const files = readdirSync(FIX).filter(
      (f) =>
        f.startsWith(`${name}-`) &&
        f.endsWith(".json") &&
        !f.includes("simple"),
    );
    if (files.length === 0) throw new Error("no fixture");
    files.sort();
    return loadJson(files[files.length - 1]);
  }
}

export function startFixtureServer() {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      try {
        const url = new URL(req.url, "http://127.0.0.1");
        const simple = url.pathname.match(/^\/simple\/([^/]+)\/$/);
        const versionJson = url.pathname.match(
          /^\/pypi\/([^/]+)\/([^/]+)\/json$/,
        );
        const projectJson = url.pathname.match(/^\/pypi\/([^/]+)\/json$/);
        let payload = null;
        if (simple) {
          payload = simpleFor(decodeURIComponent(simple[1]));
        } else if (versionJson) {
          payload = versionJsonFor(
            decodeURIComponent(versionJson[1]),
            decodeURIComponent(versionJson[2]),
          );
        } else if (projectJson) {
          const name = decodeURIComponent(projectJson[1]);
          const simpleData = simpleFor(name);
          const latest = simpleData.versions[simpleData.versions.length - 1];
          payload = versionJsonFor(name, latest);
        }
        if (!payload) {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "not found in fixtures" }));
          return;
        }
        res.writeHead(200, {
          "content-type": "application/json",
          connection: "close",
        });
        res.end(JSON.stringify(payload));
      } catch (err) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ message: String(err) }));
      }
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
    server.on("error", reject);
  });
}
