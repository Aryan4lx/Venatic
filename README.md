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
NXDOMAIN ratio, and TXT share. Always verify a candidate before escalating.

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

## Tests

```sh
npm test
```
