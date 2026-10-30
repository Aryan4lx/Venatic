import { DatabaseSync, type StatementSync } from 'node:sqlite';

export interface Dataset {
  id: number;
  tenant: string;
  label: string;
  imported_at: string;
  row_count: number;
}

export interface HostCounts {
  hostname: string;
  count: number | null;
}

export interface CountChange {
  hostname: string;
  oldCount: number;
  newCount: number;
}

export interface DiffCounts {
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
}

export function openDb(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS datasets (
      id INTEGER PRIMARY KEY,
      tenant TEXT NOT NULL,
      label TEXT NOT NULL,
      imported_at TEXT NOT NULL,
      row_count INTEGER NOT NULL DEFAULT 0,
      UNIQUE(tenant, label)
    );
    CREATE TABLE IF NOT EXISTS hosts (
      dataset_id INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
      hostname TEXT NOT NULL,
      count INTEGER,
      PRIMARY KEY (dataset_id, hostname)
    ) WITHOUT ROWID;
  `);
  return db;
}

type Row = Record<string, unknown>;

function toDataset(row: Row | undefined): Dataset | undefined {
  if (!row) return undefined;
  return {
    id: Number(row.id),
    tenant: String(row.tenant),
    label: String(row.label),
    imported_at: String(row.imported_at),
    row_count: Number(row.row_count),
  };
}

function num(row: Row | undefined, key: string): number {
  return Number((row ?? {})[key] ?? 0);
}

export function getDataset(db: DatabaseSync, tenant: string, label: string): Dataset | undefined {
  const row = db.prepare('SELECT id, tenant, label, imported_at, row_count FROM datasets WHERE tenant = ? AND label = ?').get(tenant, label) as Row | undefined;
  return toDataset(row);
}

export function latestDataset(db: DatabaseSync, tenant: string): Dataset | undefined {
  const row = db.prepare('SELECT id, tenant, label, imported_at, row_count FROM datasets WHERE tenant = ? ORDER BY imported_at DESC, id DESC LIMIT 1').get(tenant) as Row | undefined;
  return toDataset(row);
}

export function createDataset(db: DatabaseSync, tenant: string, label: string): Dataset {
  const at = new Date().toISOString();
  const res = db.prepare('INSERT INTO datasets (tenant, label, imported_at, row_count) VALUES (?, ?, ?, 0)').run(tenant, label, at);
  return { id: Number(res.lastInsertRowid), tenant, label, imported_at: at, row_count: 0 };
}

export function deleteDataset(db: DatabaseSync, id: number): void {
  db.prepare('DELETE FROM hosts WHERE dataset_id = ?').run(id);
  db.prepare('DELETE FROM datasets WHERE id = ?').run(id);
}

export function refreshRowCount(db: DatabaseSync, id: number): number {
  const row = db.prepare('SELECT COUNT(*) AS n FROM hosts WHERE dataset_id = ?').get(id) as Row | undefined;
  const n = num(row, 'n');
  db.prepare('UPDATE datasets SET row_count = ? WHERE id = ?').run(n, id);
  return n;
}

export function listDatasets(db: DatabaseSync, tenant?: string): Dataset[] {
  const sql = 'SELECT id, tenant, label, imported_at, row_count FROM datasets' + (tenant ? ' WHERE tenant = ?' : '') + ' ORDER BY tenant, imported_at DESC, id DESC';
  const rows = (tenant ? db.prepare(sql).all(tenant) : db.prepare(sql).all()) as Row[];
  return rows.map((r) => toDataset(r)!);
}

export function listTenants(db: DatabaseSync): { tenant: string; datasets: number; hosts: number }[] {
  const rows = db.prepare('SELECT tenant, COUNT(*) AS datasets, SUM(row_count) AS hosts FROM datasets GROUP BY tenant ORDER BY tenant').all() as Row[];
  return rows.map((r) => ({ tenant: String(r.tenant), datasets: num(r, 'datasets'), hosts: num(r, 'hosts') }));
}

/**
 * Buffered writer for one dataset. Batches inserts into transactions so even
 * multi-million row imports stay fast, and merges duplicate hostnames by
 * summing their counts.
 */
export class HostWriter {
  private stmt: StatementSync;
  private batch: [string, number | null][] = [];
  private seen = 0;

  constructor(private db: DatabaseSync, private datasetId: number) {
    this.stmt = db.prepare(
      'INSERT INTO hosts (dataset_id, hostname, count) VALUES (?, ?, ?) ' +
        'ON CONFLICT(dataset_id, hostname) DO UPDATE SET count = count + excluded.count',
    );
  }

  add(hostname: string, count: number | null): void {
    this.batch.push([hostname, count]);
    this.seen++;
    if (this.batch.length >= 5000) this.flush();
  }

  flush(): void {
    if (this.batch.length === 0) return;
    const rows = this.batch;
    this.batch = [];
    this.db.exec('BEGIN');
    try {
      for (const [hostname, count] of rows) this.stmt.run(this.datasetId, hostname, count);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  get rowsSeen(): number {
    return this.seen;
  }
}

const NOT_IN_OTHER = 'SELECT hostname, count FROM hosts a WHERE a.dataset_id = ? AND NOT EXISTS (SELECT 1 FROM hosts b WHERE b.dataset_id = ? AND b.hostname = a.hostname)';

const COUNT_QUERIES = {
  added: 'SELECT COUNT(*) AS n FROM hosts a WHERE a.dataset_id = ? AND NOT EXISTS (SELECT 1 FROM hosts b WHERE b.dataset_id = ? AND b.hostname = a.hostname)',
  changed:
    'SELECT COUNT(*) AS n FROM hosts a JOIN hosts b ON b.dataset_id = ? AND b.hostname = a.hostname ' +
    'WHERE a.dataset_id = ? AND a.count IS NOT NULL AND b.count IS NOT NULL AND a.count <> b.count',
} as const;

export function diffCounts(db: DatabaseSync, baselineId: number, incomingId: number): DiffCounts {
  const added = num(db.prepare(COUNT_QUERIES.added).get(incomingId, baselineId) as Row | undefined, 'n');
  const removed = num(db.prepare(COUNT_QUERIES.added).get(baselineId, incomingId) as Row | undefined, 'n');
  const changed = num(db.prepare(COUNT_QUERIES.changed).get(baselineId, incomingId) as Row | undefined, 'n');
  const incomingTotal = num(db.prepare('SELECT COUNT(*) AS n FROM hosts WHERE dataset_id = ?').get(incomingId) as Row | undefined, 'n');
  return { added, removed, changed, unchanged: incomingTotal - added - changed };
}

/** Hostnames in the incoming set but not in the baseline. */
export function iterAdded(db: DatabaseSync, baselineId: number, incomingId: number): IterableIterator<HostCounts> {
  return db.prepare(NOT_IN_OTHER).iterate(incomingId, baselineId) as IterableIterator<HostCounts>;
}

/** Hostnames in the baseline but not in the incoming set. */
export function iterRemoved(db: DatabaseSync, baselineId: number, incomingId: number): IterableIterator<HostCounts> {
  return db.prepare(NOT_IN_OTHER).iterate(baselineId, incomingId) as IterableIterator<HostCounts>;
}

/** Hostnames present in both sets whose counts differ. */
export function iterChanged(db: DatabaseSync, baselineId: number, incomingId: number): IterableIterator<CountChange> {
  return db
    .prepare(
      'SELECT a.hostname AS hostname, b.count AS oldCount, a.count AS newCount ' +
        'FROM hosts a JOIN hosts b ON b.dataset_id = ? AND b.hostname = a.hostname ' +
        'WHERE a.dataset_id = ? AND a.count IS NOT NULL AND b.count IS NOT NULL AND a.count <> b.count',
    )
    .iterate(baselineId, incomingId) as IterableIterator<CountChange>;
}
