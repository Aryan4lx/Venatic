# venatic - roadmap

Status: Phase 1 shipped (DNS hostname diffing). Phase 2 in progress (network flow hunts from Zeek logs).

## Phase 1 - DNS baseline diffing (shipped)

- `venatic import <csv> -t <tenant>` - hostname baselines (auto-detects columns)
- `venatic diff` - NEW / REMOVED / CHANGED hostnames, `--json` / `--csv` exports
- Multi-tenant SQLite storage, streaming imports, atomic `--replace`

## Phase 2 - network hunts (in progress)

Normalized `events` schema (one wide table; every source feeds every hunt):

- [x] Zeek TSV parser: `conn`, `dns`, `http` (raw or .gz, file or directory)
- [x] `hunt beaconing` - regular-interval connections to one destination
      (interval CV, payload-size regularity, conn-count ramp -> score 0-100)
- [x] `hunt long-conns` - duration outliers (default >= 1h, tunable)
- [x] `hunt volume` - bytes per host vs median (`--by src|dst`)
- [x] `hunt dnstunnel` - unique subdomains, NXDOMAIN ratio, label length/entropy,
      TXT share per base domain -> score 0-100
- [x] SIEM wrapper-CSV parser (`import-siem`): `Raw Event Log` column carrying
      FortiOS KV lines (traffic, utm/dns) or IIS W3C lines; auto-detect per row,
      malformed-quote tolerant, timestamp built from date/time/timezone
- [x] `.arpa` reverse-lookup zones excluded from `hunt dnstunnel` (PTR floods
      the unique-name counter but can't carry tunnel data)
- [ ] web anomalies hunt (404 bursts, non-browser UAs, traversal/cmd= patterns) -
      parser exists (IIS), hunt design pending review of the imported data
- [ ] `venatic diff` for event datasets: first-seen destinations vs baseline (extend
      hosts-diff to `SELECT DISTINCT dst_host` on events)

Hunt conventions: every hunt is a pure function `(db, datasetId, opts) -> findings[]`
plus a renderer; `--json` on every hunt for SIEM piping; allow-listing per tenant
comes before Phase 3.

## Phase 3 - GUI (after CLI hunts settle)

- `venatic serve` - Fastify + React/Vite, localhost-only by default
- tenant switcher, dataset browser, diff drill-down, hunt dashboard (Chart.js)
- same engine as the CLI; no separate logic

## Phase 4 - scale & workflow

- allow-listing UI, per-hunt severity thresholds
- scheduled runs + "hunting book" (saved queries, annotated findings)
- intel feeds (known-bad domains/IPs) cross-check
- DuckDB escape hatch only if volumes demand it; SQLite aggregate-first until then
