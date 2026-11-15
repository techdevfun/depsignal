# Contributing

## Development

```sh
npm install
npm run build
npm test        # unit + e2e (fixture server, recorded payloads)
npm run test:live  # live PyPI smoke; soft-skips on network failure
npm run lint    # eslint + prettier
node scripts/preflight.js  # ASCII-only + no-internal-names scan
```

## Rules

- Zero runtime dependencies. TypeScript strict, Node 20+.
- Every figure cited in the README must come from a live source fetched
  during the build or a recorded fixture labelled as such. No invented
  numbers.
- All public content is English only (ASCII). The preflight script blocks
  anything else, including text inside the demo transcript.
- Fixture payloads in `test/fixtures/` are either verbatim recordings
  from live PyPI (with source URL + record date) or reconstructions
  clearly labelled as such (litellm 1.107.0, which no longer exists on
  PyPI). Never present a reconstruction as a verbatim recording.
