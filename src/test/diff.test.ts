import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeHost, resolveColumns, readHosts, type CsvParseOptions } from '../csv.js';
import { openDb, createDataset, deleteDataset, getDataset, HostWriter, diffCounts, iterAdded, iterRemoved, iterChanged } from '../store.js';

const NO_OPTS: CsvParseOptions = {};

test('normalizeHost lowercases, trims, and strips trailing dots', () => {
  assert.equal(normalizeHost('Example.COM.'), 'example.com');
  assert.equal(normalizeHost('  Mail.Google.com '), 'mail.google.com');
  assert.equal(normalizeHost('EVIL-UPDATE.NET'), 'evil-update.net');
  assert.equal(normalizeHost('host.name..'), 'host.name');
});

test('resolveColumns auto-detects host and count columns', () => {
  const meta = resolveColumns({ dns_query: 'x', hits: 3, ts: '...' }, NO_OPTS);
  assert.equal(meta.hostKey, 'dns_query');
  assert.equal(meta.countKey, 'hits');
});

test('resolveColumns honors explicit overrides and single-column fallback', () => {
  const meta = resolveColumns({ ServerName: 'x', blah: 1 }, { hostCol: 'ServerName' });
  assert.equal(meta.hostKey, 'ServerName');
  assert.equal(meta.countKey, null);
  const single = resolveColumns({ value: 'x' }, NO_OPTS);
  assert.equal(single.hostKey, 'value');
  assert.throws(() => resolveColumns({ a: 'x', b: 'y' }, NO_OPTS));
});

test('readHosts parses a normal headered CSV and a headerless one', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'th-csv-'));
  try {
    const plain = join(dir, 'plain.csv');
    writeFileSync(plain, 'hostname,count\nA.com.,5\nB.com,notanumber\n\n', 'utf8');
    const rows: { hostname: string; count: number | null }[] = [];
    const meta = await readHosts(plain, NO_OPTS, (r) => rows.push(r));
    assert.deepEqual(rows, [
      { hostname: 'a.com', count: 5 },
      { hostname: 'b.com', count: null },
    ]);
    assert.equal(meta.hostKey, 'hostname');

    const bare = join(dir, 'bare.csv');
    writeFileSync(bare, 'x.com,7\ny.com,2\n', 'utf8');
    const bareRows: string[] = [];
    await readHosts(bare, { noHeader: true }, (r) => bareRows.push(`${r.hostname}=${r.count}`));
    assert.deepEqual(bareRows, ['x.com=7', 'y.com=2']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('diff engine finds NEW, REMOVED, CHANGED, UNCHANGED correctly', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'th-store-'));
  let db: ReturnType<typeof openDb> | undefined;
  try {
    db = openDb(join(dir, 'test.db'));
    const base = createDataset(db, 'acme', 'week1');
    const inc = createDataset(db, 'acme', 'week2');
    const w1 = new HostWriter(db, base.id);
    const w2 = new HostWriter(db, inc.id);
    // baseline mirrors fixtures/week1.csv
    for (const [h, n] of [['update.microsoft.com', 412], ['cdn.office.com', 1180], ['mail.google.com', 942], ['internal-svn.corp.local', 88], ['printer.hr.local', 12], ['intranet.corp.local', 655], ['vault.corp.local', 44], ['wiki.corp.local', 201]] as const) {
      w1.add(h, n);
    }
    // incoming mirrors fixtures/week2.csv, with a duplicate to test count merging
    for (const [h, n] of [['update.microsoft.com', 390], ['cdn.office.com', 1180], ['mail.google.com', 1005], ['internal-svn.corp.local', 88], ['printer.hr.local', 12], ['intranet.corp.local', 720], ['wiki.corp.local', 201], ['evil-update.net', 11], ['evil-update.net', 6], ['cdn-poll.evil-update.net', 6]] as const) {
      w2.add(h, n);
    }
    w1.flush();
    w2.flush();

    const counts = diffCounts(db, base.id, inc.id);
    assert.deepEqual(counts, { added: 2, removed: 1, changed: 3, unchanged: 4 });

    // node:sqlite rows have null prototypes - project to plain objects for comparison
    const plain = <T>(rows: T[]): T[] => rows.map((r) => ({ ...r }));

    assert.deepEqual(plain([...iterAdded(db, base.id, inc.id)].sort((a, b) => a.hostname.localeCompare(b.hostname))), [
      { hostname: 'cdn-poll.evil-update.net', count: 6 },
      { hostname: 'evil-update.net', count: 17 }, // duplicate merged by summing
    ]);
    assert.deepEqual(plain([...iterRemoved(db, base.id, inc.id)]), [{ hostname: 'vault.corp.local', count: 44 }]);
    assert.deepEqual(plain([...iterChanged(db, base.id, inc.id)].sort((a, b) => a.hostname.localeCompare(b.hostname))), [
      { hostname: 'intranet.corp.local', oldCount: 655, newCount: 720 },
      { hostname: 'mail.google.com', oldCount: 942, newCount: 1005 },
      { hostname: 'update.microsoft.com', oldCount: 412, newCount: 390 },
    ]);

    // tenant isolation: same labels under another tenant stay invisible
    const other = createDataset(db, 'otherco', 'week1');
    assert.equal(getDataset(db, 'acme', 'week1')!.id, base.id);
    assert.equal(getDataset(db, 'acme', 'nope'), undefined);
    deleteDataset(db, other.id);
  } finally {
    try { db?.close(); } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
