# venatic

Threat hunting for SOC teams. Import DNS query logs your analysts export as
CSV, then diff each new export against a stored baseline to instantly see
NEW, REMOVED, and CHANGED hostnames per customer. Import Zeek TSV logs
(conn/dns/http) and run network hunts: beaconing, long connections, volume
outliers, and DNS tunneling/DGA detection.

Multi-tenant by design: every dataset is tagged with a tenant (customer) name
and tenants never mix. Storage is SQLite (built into Node, no external
database) and logs are streamed, so the same code paths handle 10 rows or 10
million.

## Setup

```sh
npm install
npm run build
npm link        # optional: installs `venatic` (alias `th`) globally
```

Requires Node >= 22.5 (uses the built-in `node:sqlite` module). Data lives in
`~/.threathunt/threathunt.db` by default; override with `--db <path>` or the
`THREATHUNT_DB` env var. Run commands via `venatic ...` / `th ...` (after
npm link) or `npm run th -- ...` / `node dist/index.js ...`.

## Usage

```sh
# 1. import a baseline for a customer
th import week24.csv -t acme

# 2. daily/weekly: diff a fresh export against it (nothing is stored)
th diff --file week25.csv -t acme --against week24
th diff --file today.csv -t acme --latest     # baseline = most recent import

# 3. or diff two datasets you already imported
th import week25.csv -t acme
th diff -t acme --from week24 --to week25

# 4. exports for evidence / other tools
th diff --file week25.csv -t acme --against week24 --json
th diff --file week25.csv -t acme --against week24 --csv findings.csv

# 5. inventory
th list -t acme
th tenants
```

Terminal output truncates each section (default 50 rows, `--limit N` to
raise). `--json` / `--csv` always contain the complete diff.

## Zeek logs & hunts

Import Zeek TSV logs (raw or .gz, a single file or a whole directory,
recursively). Currently supported log types: `conn`, `dns`, `http` (others
are skipped with a note).

```sh
# import a directory of zeek logs as an events dataset
th import-zeek C:\zeek\logs -t acme -l zeek-jan1

# run hunts over the most recent events dataset (or pick one with -l <label>)
th hunt beaconing -t acme          # regular-interval check-ins to one host
th hunt long-conns -t acme         # connections open for hours (default >= 1h)
th hunt volume -t acme             # hosts moving the most bytes, vs median
th hunt dnstunnel -t acme          # tunneling / DGA per base domain

# every hunt supports --json and --limit, plus per-hunt tuning:
th hunt beaconing -t acme --min-conns 10 --max-cv 0.1 --min-interval 30s
th hunt long-conns -t acme --min-duration 2h
th hunt volume -t acme --by dst
th hunt dnstunnel -t acme --min-conns 50
```

Scores are 0-100 and are triage aids, not verdicts: beaconing blends interval
regularity (CV of gaps between connections), payload-size regularity, and
connection count; DNS tunneling blends unique-subdomain count, label entropy,
NXDOMAIN ratio, and TXT share (reverse-lookup `.arpa` zones are excluded).
Always verify a candidate before escalating.

## SIEM CSV exports (`import-siem`)

Many SIEMs export raw events as a wrapper CSV where one column (`Raw Event
Log`) contains the original log line. Venatic parses those rows directly:

- **FortiOS** KV lines: `type=traffic` (src/dst IP+port, proto, duration,
  bytes) and `type=utm subtype=dns` (qname, qtype, rcode). The KV tokenizer
  survives malformed quotes seen in real exports; timestamps use the export's
  `date`/`time`/`tz` fields.
- **IIS / W3C** lines (detected by the `IISWebLog` marker): method, URI,
  status, user agent, cs-host, bytes, time-taken.

```sh
th import-siem export.csv -t acme -l fortigate-week42
```

Rows that are empty or carry an unsupported log type are counted and
reported, never fatal. Note: SIEM exports are often capped (e.g. 10,000
rows) - check the export footer before drawing conclusions.

## CSV format

Headered CSV with a hostname column and an optional query-count column.
Columns are auto-detected from common names:

- hostname: `hostname`, `host`, `domain`, `query`, `dns_query`, `dnsquery`, `name`, `fqdn`
- count: `count`, `counts`, `queries`, `query_count`, `querycount`, `hits`, `requests`, `request_count`, `total`, `total_queries`

Overrides for odd exports: `--host-col <name>`, `--count-col <name>`,
`--no-header` (treats column 1 as host, column 2 as count). Hostnames are
normalized before diffing (lowercase, trim, trailing dot stripped), so
`Example.COM.` and `example.com` are the same host. Duplicate rows within one
file have their counts summed. `--limit <n>` on `diff` controls terminal
truncation only.

## Diff output

- **NEW**: hostnames in the incoming set that were never in the baseline (the
  main hunting signal: C2, DGA, lookalike, exfil domains)
- **REMOVED**: baseline hostnames gone from the incoming set (torn-down infra,
  or a data collection problem)
- **CHANGED**: present in both but query count moved (beaconing spikes)

CSV export columns: `type,hostname,count_baseline,count_incoming`.

## Dashboard (`venatic serve`)

A local web UI over the same engine - nothing leaves your machine (binds to
127.0.0.1 only):

```sh
th serve          # opens http://127.0.0.1:8422 in your browser
th serve --port 9000 --no-open
```

- pick a tenant, browse datasets, run DNS diffs with NEW/REMOVED/CHANGED
  sections and top-host tables
- run all four hunts over any events dataset; beaconing and DNS-tunnel
  candidates get score bars, volume gets a chart of the top talkers
- every screen is backed by the same JSON API the CLI uses (`/api/tenants`,
  `/api/datasets`, `/api/diff`, `/api/hunt`) - pipe it into your own tooling
  if you want

Large diffs are capped at 5,000 rows per section in the UI (the CLI's
`--csv` export has no cap).

## Tests

```sh
npm test
```
