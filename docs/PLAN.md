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

## Phase 3 - GUI (shipped)

- [x] `venatic serve` - plain node:http dashboard on 127.0.0.1 (no framework,
      no build chain; single-file vanilla JS frontend + Chart.js served
      locally so it works on air-gapped networks)
- [x] tenant switcher, dataset browser, DNS diff view, all four hunts with
      score bars and a top-talkers chart
- [x] JSON API (`/api/tenants`, `/api/datasets`, `/api/diff`, `/api/hunt`)
      usable without the UI
- [ ] drill-down: click a candidate to see the raw events behind it
- [ ] per-hunt severity thresholds / allow-list editing in the UI

## Phase 4 - scale & workflow

- allow-listing UI, per-hunt severity thresholds
- scheduled runs + "hunting book" (saved queries, annotated findings)
- intel feeds (known-bad domains/IPs) cross-check
- DuckDB escape hatch only if volumes demand it; SQLite aggregate-first until then

## Phase 5 - ML & ensemble hunts (shipped)

Techniques follow David Hoelzer's public threat-hunting material; synthesis
and sources in `docs/ML-RESEARCH.md`.

- [x] `hunt fft-beacons` - per-host/pair FFT over time-binned connection
      counts; dominant non-DC frequency = beacon period; catches jittered
      check-ins the interval-CV hunt misses (zero dependencies)
- [x] `hunt dns-clusters` - DBSCAN over engineered qname features (length,
      label entropy, digit ratio, bigram rarity) with PCA scatter in the
      dashboard; groups "the weird" instead of listing outliers
- [x] `ml-train` / `hunt ml-anomaly` - TensorFlow.js autoencoder on per-host
      behavioral profiles (10 dims); flags worst-reconstruction hosts with
      per-feature deviations; per-tenant model files; no native deps
- [x] `hunt ensemble` - merge every detector into one ranked triage queue;
      hosts flagged by multiple independent detectors rise to the top
- [x] dashboard: scatter for clusters, spectrum/feature bars for ML, merged
      ensemble queue first in "run all"
- [ ] protocol classifier (Hoelzer's first-16-bytes model) - blocked on
      payload capture: needs a Zeek sensor script exporting stream prefixes
- [ ] log-line autoencoder (BPE + Conv1D on raw log lines) - needs raw-line
      retention for SIEM imports
- [ ] analyst feedback loop: allow-list suppressions feeding back into scores
