#!/usr/bin/env node
import { Command } from 'commander';
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
      console.log(`  ${d.label.padEnd(30)} ${d.row_count.toLocaleString().padStart(9)} hostnames  imported ${d.imported_at}`);
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

program.parseAsync().catch((err: unknown) => {
  console.error(String(err instanceof Error ? err.message : err));
  process.exitCode = 1;
});
