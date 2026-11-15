#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Part 1 is a LIVE audit against PyPI (no auth). Part 2 replays
# litellm==1.107.0 against the local fixture server with RECORDED
# payloads - 1.107.0 no longer exists on PyPI, so a live probe cannot
# reproduce it. The replay is labelled as a recorded fixture in the
# transcript.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/depsignal-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/depsignal"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/work"
mkdir -p "$WORK"
cp "$ROOT/examples/demo-requirements.txt" "$WORK/requirements.txt"
cp "$ROOT/examples/litellm-replay-requirements.txt" "$WORK/litellm.txt"
cd "$WORK"

OUT="$ROOT/demo/transcript.txt"
{
  echo "# depsignal demo - real CLI output"
  echo "# part 1: LIVE audit against PyPI (no auth)"
  echo ""
  echo "\$ depsignal audit requirements.txt --limit 3"
  depsignal audit requirements.txt --limit 3 || echo "exit: $?"
  echo ""
  echo "# part 2: RECORDED FIXTURE replay - litellm==1.107.0"
  echo "# (1.107.0 was removed from PyPI on 21 Oct 2026; this replay"
  echo "#  runs against a local fixture server with payloads recorded"
  echo "#  2026-11-15, labelled in test/fixtures/litellm-1.107.0.*)"
  echo ""
} > "$OUT" 2>&1

# Start the fixture server for part 2 (separate process so it can serve
# while the CLI runs).
node --input-type=module -e "
import { startFixtureServer } from '$ROOT/test/fixture-server.js';
import { writeFileSync } from 'node:fs';
const { server, baseUrl } = await startFixtureServer();
writeFileSync('$SCRATCH/base-url.txt', baseUrl);
await new Promise(() => {}); // run until killed
" > "$SCRATCH/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  if [ -f "$SCRATCH/base-url.txt" ]; then break; fi
  sleep 0.2
done
BASE_URL="$(cat "$SCRATCH/base-url.txt")"
echo "fixture server on $BASE_URL"

{
  echo "\$ depsignal audit litellm.txt --pypi-base $BASE_URL"
  depsignal audit litellm.txt --pypi-base "$BASE_URL" || echo "exit: $?"
} >> "$OUT" 2>&1

# Replace the concrete port with PORT in the transcript so the GIF is stable.
sed -i "s|$BASE_URL|http://127.0.0.1:PORT|g" "$OUT"
sed -i "s|--pypi-base http://127.0.0.1:PORT|--pypi-base http://127.0.0.1:PORT|" "$OUT"
echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
