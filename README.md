# venatic

Threat hunting for SOC teams. Import the DNS query logs your analysts export
as CSV, then diff each new export against a stored baseline to instantly see
NEW, REMOVED, and CHANGED hostnames per customer. DNS baseline diffing is the
first module - the tenant/dataset core is built to carry more log types and
hunting modules later.

Built for an MSSP: every dataset is tagged with a tenant (customer) name and
diffs never mix customers. Storage is SQLite (built into Node, no external
database) and CSVs are streamed, so the same code paths handle 10 rows or 10
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
