#!/usr/bin/env node
import { Command, Argument } from 'commander';
import { basename } from 'node:path';
import { createWriteStream } from 'node:fs';
import { resolveDbPath } from './config.js';
import { readHosts, type CsvParseOptions } from './csv.js';
import {
  openDb,
  getDataset,
  latestDataset,
  createDataset,
  deleteDataset,
  listDatasets,
  listTenants,
  refreshRowCount,
  HostWriter,
  diffCounts,
  iterAdded,
  iterRemoved,
  iterChanged,
  type Dataset,
  type DiffCounts,
} from './store.js';
import { renderDiffTerminal } from './report.js';
import { readZeek } from './zeek.js';
import { readSiem } from './siem.js';
import { startServe } from './web/server.js';
import { EventWriter, type Row } from './store.js';
import {
  huntBeaconing,
  renderBeaconing,
  huntLongConns,
  renderLongConns,
  huntVolume,
  renderVolume,
  huntDnsTunnel,
  renderDnsTunnel,
  huntHeader,
} from './hunts.js';

interface CommonOpts {
  db?: string;
  tenant?: string;
  header?: boolean;
  hostCol?: string;
  countCol?: string;
}

interface ImportOpts extends CommonOpts {
  label?: string;
  replace?: boolean;
}

interface DiffOpts extends CommonOpts {
  file?: string;
  against?: string;
  latest?: boolean;
  from?: string;
  to?: string;
  json?: boolean;
  csv?: string;
  limit?: string;
}

function csvOpts(o: CommonOpts): CsvParseOptions {
  // commander turns --no-header into opts.header === false
  return { noHeader: o.header === false, hostCol: o.hostCol, countCol: o.countCol };
}

function need<T>(v: T | undefined, msg: string): T {
  if (v === undefined) throw new Error(msg);
  return v;
}

async function importCsv(file: string, o: ImportOpts): Promise<void> {
  const tenant = need(o.tenant, '--tenant <name> is required');
  const db = openDb(resolveDbPath(o.db));
  let dataset: Dataset | undefined;
  try {
    const label = o.label ?? basename(file).replace(/\.csv$/i, '');
    const existing = getDataset(db, tenant, label);
    if (existing && !o.replace) {
      throw new Error(`dataset '${label}' already exists for tenant '${tenant}' (imported ${existing.imported_at}). Use --replace to overwrite.`);
    }
    // import under a temp label first, swap only on success - a bad file must
    // never destroy the previous baseline via --replace
    dataset = createDataset(db, tenant, `__import_tmp_${process.pid}_${Date.now()}`);
    const writer = new HostWriter(db, dataset.id);
    const meta = await readHosts(file, csvOpts(o), (row) => writer.add(row.hostname, row.count));
    writer.flush();
    dataset.row_count = refreshRowCount(db, dataset.id);
    db.exec('BEGIN');
    try {
      if (existing) deleteDataset(db, existing.id);
      db.prepare('UPDATE datasets SET label = ? WHERE id = ?').run(label, dataset.id);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
    dataset.label = label;

    const hostCol = typeof meta.hostKey === 'number' ? `column 1` : `'${meta.hostKey}'`;
    const countCol = meta.countKey === null ? 'no count column' : typeof meta.countKey === 'number' ? `column 2` : `'${meta.countKey}'`;
    console.log(`imported ${dataset.row_count} unique hostnames (${writer.rowsSeen} rows) from ${file}`);
    console.log(`tenant '${tenant}', dataset '${label}' | host column: ${hostCol}, count column: ${countCol}`);
  } catch (err) {
    if (dataset) deleteDataset(db, dataset.id);
    throw err;
  } finally {
    db.close();
  }
}

async function cmdDiff(o: DiffOpts): Promise<void> {
  const tenant = need(o.tenant, '--tenant <name> is required');
  const db = openDb(resolveDbPath(o.db));
  let temp: Dataset | undefined;
  try {
    let baseline: Dataset;
    let incoming: Dataset;

    if (o.file) {
      if (!!o.against === !!o.latest) {
        throw new Error('with --file, pass exactly one of --against <label> or --latest');
      }
      baseline = o.against
        ? need(getDataset(db, tenant, o.against), `no dataset '${o.against}' for tenant '${tenant}' (see: th list -t ${tenant})`)
        : need(latestDataset(db, tenant), `tenant '${tenant}' has no datasets yet - import a baseline with 'th import' first`);
      incoming = createDataset(db, tenant, `__diff_tmp_${process.pid}_${Date.now()}`);
      temp = incoming;
      const writer = new HostWriter(db, incoming.id);
      await readHosts(o.file, csvOpts(o), (row) => writer.add(row.hostname, row.count));
      writer.flush();
      incoming.row_count = refreshRowCount(db, incoming.id);
      incoming.label = basename(o.file); // display only, temp dataset is dropped below
    } else if (o.from && o.to) {
      baseline = need(getDataset(db, tenant, o.from), `no dataset '${o.from}' for tenant '${tenant}' (see: th list -t ${tenant})`);
      incoming = need(getDataset(db, tenant, o.to), `no dataset '${o.to}' for tenant '${tenant}' (see: th list -t ${tenant})`);
    } else {
      throw new Error('diff needs --file <csv> (plus --against <label> or --latest), or --from <label> --to <label>');
    }

    if (baseline.id === incoming.id) throw new Error('baseline and incoming are the same dataset');
    const counts = diffCounts(db, baseline.id, incoming.id);

    if (o.csv) await writeCsvExport(o.csv, db, baseline.id, incoming.id);
    if (o.json) printJson(db, tenant, baseline, incoming, counts);
    else if (!o.csv) renderDiffTerminal(db, baseline, incoming, counts, o.limit ? parseInt(o.limit, 10) : 50);
    if (o.csv) console.log(`diff written to ${o.csv}`);
  } finally {
    if (temp) deleteDataset(db, temp.id);
    db.close();
  }
}

function printJson(db: import('node:sqlite').DatabaseSync, tenant: string, baseline: Dataset, incoming: Dataset, counts: DiffCounts): void {
  console.log(
    JSON.stringify(
      {
        tenant,
        baseline: { label: baseline.label, imported_at: baseline.imported_at, hostnames: baseline.row_count },
        incoming: { label: incoming.label, hostnames: incoming.row_count },
        summary: counts,
        added: [...iterAdded(db, baseline.id, incoming.id)],
        removed: [...iterRemoved(db, baseline.id, incoming.id)],
        changed: [...iterChanged(db, baseline.id, incoming.id)],
      },
      null,
      2,
    ),
  );
}

function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function writeCsvExport(path: string, db: import('node:sqlite').DatabaseSync, baselineId: number, incomingId: number): Promise<void> {
  const out = createWriteStream(path);
  let n = 1; // header row
  // Writeable backpressure guard
  const writeAsync = async (line: string): Promise<void> => {
    if (!out.write(line + '\n')) await new Promise<void>((res) => out.once('drain', res));
    n++;
  };

  await writeAsync('type,hostname,count_baseline,count_incoming');
  for (const r of iterAdded(db, baselineId, incomingId)) await writeAsync(`new,${csvCell(r.hostname)},,${r.count ?? ''}`);
  for (const r of iterRemoved(db, baselineId, incomingId)) await writeAsync(`removed,${csvCell(r.hostname)},${r.count ?? ''},`);
  for (const r of iterChanged(db, baselineId, incomingId)) await writeAsync(`changed,${csvCell(r.hostname)},${r.oldCount},${r.newCount}`);
  await new Promise<void>((res) => out.end(res));
  console.log(`wrote ${n} rows (header + ${n - 1} diff entries) to ${path}`);
}

function parseDuration(s: string): number {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/.exec(s.trim());
  if (!m) throw new Error(`invalid duration '${s}' (examples: 90m, 2h, 600s)`);
  const mult = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2] ?? 'ms']!;
  return Math.round(parseFloat(m[1]) * mult);
}

/** Shared atomic events import: temp dataset -> reader -> row_count -> label swap. */
async function importEvents(target: string, o: ImportOpts, defaultLabel: string, read: (writer: EventWriter) => Promise<string>): Promise<void> {
  const tenant = need(o.tenant, '--tenant <name> is required');
  const db = openDb(resolveDbPath(o.db));
  let dataset: Dataset | undefined;
  try {
    const label = o.label ?? defaultLabel;
    const existing = getDataset(db, tenant, label);
    if (existing && !o.replace) {
      throw new Error(`dataset '${label}' already exists for tenant '${tenant}' (imported ${existing.imported_at}). Use --replace to overwrite.`);
    }
    dataset = createDataset(db, tenant, `__import_tmp_${process.pid}_${Date.now()}`, 'events');
    const writer = new EventWriter(db, dataset.id);
    const summary = await read(writer);
    writer.flush(); // otherwise the final buffered batch never reaches the table
    const total = db.prepare('SELECT COUNT(*) AS n FROM events WHERE dataset_id = ?').get(dataset.id) as { n: number | bigint };
    dataset.row_count = Number(total.n);
    if (dataset.row_count === 0) throw new Error(`no usable events found in ${target}`);
    db.prepare('UPDATE datasets SET row_count = ? WHERE id = ?').run(dataset.row_count, dataset.id);
    db.exec('BEGIN');
    try {
      if (existing) deleteDataset(db, existing.id);
      db.prepare('UPDATE datasets SET label = ? WHERE id = ?').run(label, dataset.id);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
    dataset.label = label;

    console.log(`imported ${dataset.row_count} events from ${target}`);
    console.log(`tenant '${tenant}', dataset '${label}' | ${summary}`);
  } catch (err) {
    if (dataset) deleteDataset(db, dataset.id);
    throw err;
  } finally {
    db.close();
  }
}

async function importZeek(target: string, o: ImportOpts): Promise<void> {
  const label = o.label ?? basename(target).replace(/\.(log|csv)(\.gz)?$/i, '');
  await importEvents(target, o, label, async (writer) => {
    const results = await readZeek(target, (e) => writer.add(e));
    if (results.length === 0) throw new Error(`no Zeek log files (*.log, *.log.gz) found in ${target}`);
    const byKind = new Map<string, number>();
    for (const r of results) byKind.set(r.kind, (byKind.get(r.kind) ?? 0) + r.rows);
    const parts = [...byKind.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}: ${v}`).join(', ');
    const unsupported = [...new Set(results.filter((r) => !['conn', 'dns', 'http'].includes(r.kind)).map((r) => r.kind))];
    if (unsupported.length) console.log(`skipped unsupported log types: ${unsupported.join(', ')}`);
    return `events by log type - ${parts || 'none'}`;
  });
}

async function importSiem(file: string, o: ImportOpts): Promise<void> {
  const label = o.label ?? basename(file).replace(/\.csv$/i, '');
  await importEvents(file, o, label, async (writer) => {
    const res = await readSiem(file, (e) => writer.add(e));
    if (res.skipped > 0) console.log(`skipped ${res.skipped} rows (empty or unsupported raw log types)`);
    return `fortinet: ${res.fortinet}, iis: ${res.iis}`;
  });
}

interface HuntOpts {
  tenant?: string;
  label?: string;
  json?: boolean;
  limit?: string;
  db?: string;
  minConns?: string;
  maxCv?: string;
  minInterval?: string;
  minDuration?: string;
  by?: string;
}

async function cmdHunt(name: string, o: HuntOpts): Promise<void> {
  const tenant = need(o.tenant, '--tenant <name> is required');
  const db = openDb(resolveDbPath(o.db));
  try {
    const ds = o.label
      ? need(getDataset(db, tenant, o.label), `no dataset '${o.label}' for tenant '${tenant}' (see: th list -t ${tenant})`)
      : need(latestDataset(db, tenant, 'events'), `tenant '${tenant}' has no event datasets - import Zeek logs with 'th import-zeek' first`);
    if (ds.kind !== 'events') throw new Error(`dataset '${ds.label}' is a DNS baseline (kind=dns) - hunts run on event data imported with 'th import-zeek'`);
    const limit = o.limit ? parseInt(o.limit, 10) : 25;
    const opts = { limit, json: o.json === true };
    huntHeader(db, tenant, ds.id, `hunt: ${name}`);
    switch (name) {
      case 'beaconing': {
        const findings = huntBeaconing(db, ds.id, {
          minConns: o.minConns ? parseInt(o.minConns, 10) : undefined,
          maxCv: o.maxCv ? parseFloat(o.maxCv) : undefined,
          minIntervalMs: o.minInterval ? parseDuration(o.minInterval) : undefined,
          limit,
        });
        renderBeaconing(findings, opts);
        break;
      }
      case 'long-conns': {
        const findings = huntLongConns(db, ds.id, {
          minDurationMs: o.minDuration ? parseDuration(o.minDuration) : undefined,
          limit,
        });
        renderLongConns(findings, opts);
        break;
      }
      case 'volume': {
        const by = o.by ?? 'src';
        if (by !== 'src' && by !== 'dst') throw new Error("--by must be 'src' or 'dst'");
        renderVolume(huntVolume(db, ds.id, { by, limit }), opts);
        break;
      }
      case 'dnstunnel':
        renderDnsTunnel(huntDnsTunnel(db, ds.id, { minConns: o.minConns ? parseInt(o.minConns, 10) : undefined, limit }), opts);
        break;
      default:
        throw new Error(`unknown hunt '${name}'`);
    }
  } finally {
    db.close();
  }
}

function cmdList(o: { tenant?: string; db?: string }): void {
  const db = openDb(resolveDbPath(o.db));
  try {
    const datasets = listDatasets(db, o.tenant);
    if (datasets.length === 0) {
      console.log(o.tenant ? `no datasets for tenant '${o.tenant}'` : 'no datasets yet - import one with: th import <file.csv> -t <tenant>');
      return;
    }
    let currentTenant = '';
    for (const d of datasets) {
      if (d.tenant !== currentTenant) {
        currentTenant = d.tenant;
        console.log(`${d.tenant}:`);
      }
      console.log(`  ${d.label.padEnd(30)} ${d.row_count.toLocaleString().padStart(9)} ${d.kind === 'events' ? 'events    ' : 'hostnames '} imported ${d.imported_at}`);
    }
  } finally {
    db.close();
  }
}

function cmdTenants(o: { db?: string }): void {
  const db = openDb(resolveDbPath(o.db));
  try {
    const tenants = listTenants(db);
    if (tenants.length === 0) {
      console.log('no tenants yet - import one with: th import <file.csv> -t <tenant>');
      return;
    }
    for (const t of tenants) console.log(`${t.tenant.padEnd(30)} ${t.datasets} datasets, ${t.hosts.toLocaleString()} hostnames total`);
  } finally {
    db.close();
  }
}

const program = new Command();
program.name('venatic').description('venatic - threat hunting for SOC teams; DNS hostname baseline diffing').version('0.1.0');

program
  .command('import')
  .description('import a DNS hostname CSV as a dataset for a tenant')
  .argument('<file>', 'CSV file to import')
  .requiredOption('-t, --tenant <name>', 'tenant (customer) name')
  .option('-l, --label <name>', 'dataset label (default: file name without extension)')
  .option('--replace', 'overwrite an existing dataset with the same label', false)
  .option('--host-col <name>', 'CSV column with the hostname (default: auto-detect)')
  .option('--count-col <name>', 'CSV column with the query count (default: auto-detect)')
  .option('--no-header', 'CSV has no header row (column 1 = host, column 2 = count)')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((file: string, o: ImportOpts) => importCsv(file, o));

program
  .command('diff')
  .description('diff a new CSV or dataset against a baseline; shows NEW / REMOVED / CHANGED hostnames')
  .requiredOption('-t, --tenant <name>', 'tenant (customer) name')
  .option('--file <csv>', 'new CSV to compare (results are not stored)')
  .option('--against <label>', 'stored dataset to use as baseline (with --file)')
  .option('--latest', 'use the most recently imported dataset as baseline (with --file)')
  .option('--from <label>', 'baseline dataset for a stored-vs-stored diff')
  .option('--to <label>', 'newer dataset for a stored-vs-stored diff')
  .option('--host-col <name>', 'CSV column with the hostname (default: auto-detect)')
  .option('--count-col <name>', 'CSV column with the query count (default: auto-detect)')
  .option('--no-header', 'CSV has no header row (column 1 = host, column 2 = count)')
  .option('--json', 'print the full diff as JSON to stdout', false)
  .option('--csv <path>', 'write the full diff to a CSV file (type,hostname,count_baseline,count_incoming)')
  .option('--limit <n>', 'rows shown per section in terminal output', '50')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((o: DiffOpts) => cmdDiff(o));

program
  .command('import-zeek')
  .description('import Zeek TSV logs (conn/dns/http, raw or .gz; file or directory) as an events dataset')
  .argument('<target>', 'Zeek .log/.log.gz file or a directory containing them')
  .requiredOption('-t, --tenant <name>', 'tenant (customer) name')
  .option('-l, --label <name>', 'dataset label (default: file/dir name without extension)')
  .option('--replace', 'overwrite an existing dataset with the same label', false)
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((target: string, o: ImportOpts) => importZeek(target, o));

program
  .command('hunt')
  .description('run a detection hunt over an events dataset (beaconing, long-conns, volume, dnstunnel)')
  .addArgument(new Argument('<name>', 'which hunt to run').choices(['beaconing', 'long-conns', 'volume', 'dnstunnel']))
  .requiredOption('-t, --tenant <name>', 'tenant (customer) name')
  .option('-l, --label <name>', 'events dataset label (default: most recent events dataset)')
  .option('--json', 'print findings as JSON to stdout', false)
  .option('--limit <n>', 'max findings to show', '25')
  .option('--min-conns <n>', 'min connections per pair/domain (beaconing, dnstunnel)')
  .option('--max-cv <x>', 'beaconing: max interval coefficient of variation (default 0.2; lower = stricter)')
  .option('--min-interval <dur>', 'beaconing: ignore pairs with mean interval below this (e.g. 500ms, 5s; default 1s)')
  .option('--min-duration <dur>', 'long-conns: minimum duration (e.g. 90m, 2h; default 1h)')
  .option('--by <side>', 'volume: rank by src or dst hosts (default src)')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((name: string, o: HuntOpts) => cmdHunt(name, o));

program
  .command('import-siem')
  .description('import a SIEM CSV export whose "Raw Event Log" column carries FortiOS (traffic, utm/dns) or IIS W3C lines')
  .argument('<file>', 'SIEM CSV export with a Raw Event Log column')
  .requiredOption('-t, --tenant <name>', 'tenant (customer) name')
  .option('-l, --label <name>', 'dataset label (default: file name without extension)')
  .option('--replace', 'overwrite an existing dataset with the same label', false)
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((file: string, o: ImportOpts) => importSiem(file, o));

program
  .command('list')
  .description('list imported datasets, optionally for one tenant')
  .option('-t, --tenant <name>', 'filter by tenant')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((o: { tenant?: string; db?: string }) => cmdList(o));

program
  .command('tenants')
  .description('list tenants and their dataset totals')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .action((o: { db?: string }) => cmdTenants(o));

program
  .command('serve')
  .description('start the local web dashboard (http://127.0.0.1:<port>)')
  .option('-p, --port <n>', 'port to listen on', '8422')
  .option('--db <path>', 'database file (default: ~/.threathunt/threathunt.db)')
  .option('--no-open', "don't open the browser automatically")
  .action(async (o: { port: string; db?: string }) => {
    const port = Number(o.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid port '${o.port}'`);
    const { url } = await startServe({ db: o.db, port });
    console.log(`venatic dashboard running at ${url} (Ctrl+C to stop)`);
  });

program.parseAsync().catch((err: unknown) => {
  console.error(String(err instanceof Error ? err.message : err));
  process.exitCode = 1;
});
